/** RF Hunter v2 — wardrive + filters + dashboard cakes + bulk vulns */
(() => {
  const $ = (sel) => document.querySelector(sel);
  const selected = new Set();
  const triageSelected = new Set(); // device keys for vuln triage
  let catalog = { categories: [], device_types: [] };
  let devices = [];
  let devicesByKey = {};
  let focusedKey = null;
  let ws = null;
  let activeCategory = "all";
  let scanRunning = false;
  let vulnRunning = false;
  let pollTimer = null;
  let monitoring = false;
  let lastSample = null;
  let stats = { by_type: [], by_radio: [], by_severity: [], total: 0 };

  const filters = { text: "", type: "", radio: "", sev: "", wow: "", quality: "hide_noise", evidence: "" };
  let sortBy = "wow";
  let layoutMode = "cards";
  let wowTypeIds = [];
  let wowBleTypeIds = [];
  let demoModeActive = false;
  let demoVulnTriggered = false;
  let txArmed = false;
  let gpsFix = null;
  let gpsTrail = [];
  let lastScanTypeIds = null; // Set of device_type_id from last Start (scopes LIVE list)
  let scopeToLastScan = true;
  let wifiAps = [];
  let wifiStatus = null;
  /** When false, ignore Wi‑Fi AP pushes (WS + health poll) until user/start resumes. */
  let wifiLiveEnabled = true;
  let map = null;
  let mapReady = false;
  let mapBasemapLayer = null;
  let mapFollow = true;
  let hunterMarker = null;
  let trailLine = null;
  const deviceMarkers = {}; // key -> marker
  const wifiMarkers = {}; // bssid -> marker
  let mapLayerGroup = null;
  let wifiLayerGroup = null;
  let trafficMapTick = null;

  const MAP_FILTER_DEFAULTS = {
    rf: true,
    ble: true,
    wifi: true,
    adsb: true,
    ais: true,
    hunter: true,
    trail: true,
    critical_only: false,
    hide_noise: true,
    decode_only: false,
  };
  let mapFilters = { ...MAP_FILTER_DEFAULTS };
  try {
    const raw = localStorage.getItem("rfhunter.mapFilters");
    if (raw) mapFilters = { ...MAP_FILTER_DEFAULTS, ...JSON.parse(raw) };
  } catch (_) {}
  let mapFilterPreset = "";

  const PIE_COLORS = [
    "#3b9eff", "#a371f7", "#3dd68c", "#f0b429", "#f25c54",
    "#22d3ee", "#fb7185", "#84cc16", "#e879f9", "#94a3b8",
  ];
  const SEV_COLORS = {
    critical: "#f25c54",
    high: "#fb7185",
    medium: "#f0b429",
    low: "#3dd68c",
    unknown: "#7d8da6",
  };

  const els = {
    grid: $("#device-grid"),
    tabs: $("#category-tabs"),
    results: $("#results-list"),
    log: $("#log"),
    progress: $("#progress"),
    progressLabel: $("#progress-label"),
    sweepLive: $("#sweep-live"),
    vulnProgress: $("#vuln-progress"),
    vulnProgressLabel: $("#vuln-progress-label"),
    vulnCounts: $("#vuln-counts"),
    count: $("#detection-count"),
    trackCount: $("#track-count"),
    selectedCount: $("#selected-count"),
    btnSelectAll: $("#btn-select-all"),
    btnSelectWow: $("#btn-select-wow"),
    btnSelectLabTvs: $("#btn-select-lab-tvs"),
    btnDemoMode: $("#btn-demo-mode"),
    filterWow: $("#filter-wow"),
    filterQuality: $("#filter-quality"),
    filterEvidence: $("#filter-evidence"),
    btnReplay: $("#btn-replay"),
    focusWowHint: $("#focus-wow-hint"),
    hackrf: $("#hackrf-status"),
    gpsStatus: $("#gps-status"),
    wifiStatus: $("#wifi-status"),
    focusIdentity: $("#focus-identity"),
    focusLeak: $("#focus-leak"),
    focusGattSnap: $("#focus-gatt-snap"),
    focusWifi: $("#focus-wifi"),
    focusDecode: $("#focus-decode"),
    focusAdv: $("#focus-adv"),
    dashFindings: $("#dash-findings"),
    mapFixLabel: $("#map-fix-label"),
    mapPinCount: $("#map-pin-count"),
    btnMapFit: $("#btn-map-fit"),
    btnMapFollow: $("#btn-map-follow"),
    btnMapTrailClear: $("#btn-map-trail-clear"),
    scanStatus: $("#scan-status"),
    vulnStatus: $("#vuln-status"),
    btnScan: $("#btn-scan"),
    btnStop: $("#btn-stop"),
    btnCleanup: $("#btn-cleanup"),
    confirmModal: $("#confirm-modal"),
    confirmTitle: $("#confirm-title"),
    confirmSubtitle: $("#confirm-subtitle"),
    confirmBody: $("#confirm-body"),
    btnConfirmOk: $("#btn-confirm-ok"),
    btnConfirmAlt: $("#btn-confirm-alt"),
    replayModal: $("#replay-modal"),
    replayTitle: $("#replay-title"),
    replaySubtitle: $("#replay-subtitle"),
    replayBody: $("#replay-body"),
    btnReplayListen: $("#btn-replay-listen"),
    btnReplayTx: $("#btn-replay-tx"),
    btnRfClone: $("#btn-rf-clone"),
    cloneModal: $("#clone-modal"),
    clonePresets: $("#clone-presets"),
    cloneFreq: $("#clone-freq"),
    cloneSpectrum: $("#clone-spectrum"),
    clonePeak: $("#clone-peak"),
    cloneStatus: $("#clone-status"),
    cloneTxProgress: $("#clone-tx-progress"),
    cloneTxLabel: $("#clone-tx-label"),
    cloneTxFill: $("#clone-tx-fill"),
    cloneTxPct: $("#clone-tx-pct"),
    txLiveOverlay: $("#tx-live-overlay"),
    txLiveLabel: $("#tx-live-label"),
    txLiveFill: $("#tx-live-fill"),
    txLivePct: $("#tx-live-pct"),
    btnCloneLive: $("#btn-clone-live"),
    btnCloneHunt: $("#btn-clone-hunt"),
    btnCloneCompare: $("#btn-clone-compare"),
    btnCloneRecord: $("#btn-clone-record"),
    btnCloneTx: $("#btn-clone-tx"),
    cloneRecordDur: $("#clone-record-dur"),
    cloneTxSource: $("#clone-tx-source"),
    cloneTxRepeats: $("#clone-tx-repeats"),
    btnVulnQuick: $("#btn-vuln-quick"),
    btnVulnFull: $("#btn-vuln-full"),
    btnTpmsDecode: $("#btn-tpms-decode"),
    tpmsStatsHint: $("#tpms-stats-hint"),
    triageSelHint: $("#triage-sel-hint"),
    triageSelCount: $("#triage-sel-count"),
    chkTriageVisible: $("#chk-triage-visible"),
    btnTriageClear: $("#btn-triage-clear"),
    vulnHint: $("#vuln-hint"),
    btnTxArm: $("#btn-tx-arm"),
    txArmHint: $("#tx-arm-hint"),
    btnExportCsv: $("#btn-export-csv"),
    btnExportJson: $("#btn-export-json"),
    btnCaptures: $("#btn-captures"),
    focusEmpty: $("#focus-empty"),
    focusPanel: $("#focus-panel"),
    focusTitle: $("#focus-title"),
    focusBar: $("#focus-bar"),
    focusDb: $("#focus-db"),
    focusHint: $("#focus-hint"),
    focusSpark: $("#focus-spark"),
    focusMeta: $("#focus-meta"),
    focusTraffic: $("#focus-traffic"),
    focusRisk: $("#focus-risk"),
    btnMonitor: $("#btn-monitor"),
    btnDive: $("#btn-dive"),
    btnFpvDecode: $("#btn-fpv-decode"),
    btnSeeMap: $("#btn-see-map"),
    btnJson: $("#btn-json"),
    filterText: $("#filter-text"),
    filterType: $("#filter-type"),
    filterRadio: $("#filter-radio"),
    filterSev: $("#filter-sev"),
    sortBy: $("#sort-by"),
    layoutMode: $("#layout-switch"),
    layoutBtns: null, // filled in init
    btnClearFilters: $("#btn-clear-filters"),
    modal: $("#modal"),
    modalTitle: $("#modal-title"),
    modalSubtitle: $("#modal-subtitle"),
    modalBody: $("#modal-body"),
    modalToggleRaw: $("#modal-toggle-raw"),
  };

  let modalRawPayload = null;
  let modalShowingRaw = false;

  const ICONS = {
    rf: `<svg viewBox="0 0 24 24"><path d="M12 20v-4"/><path d="M8.5 12a5 5 0 0 1 7 0"/><path d="M5.5 9a9 9 0 0 1 13 0"/><path d="M2.5 6a13 13 0 0 1 19 0"/><circle cx="12" cy="16" r="1.2" fill="currentColor" stroke="none"/></svg>`,
    ble: `<svg viewBox="0 0 24 24"><path d="M7 7l10 10-5 4V3l5 4L7 17"/></svg>`,
    signal: `<svg viewBox="0 0 24 24"><path d="M4 18h2V10H4zm5 0h2V6H9zm5 0h2v-7h-2zm5 0h2V4h-2z"/></svg>`,
    shield: `<svg viewBox="0 0 24 24"><path d="M12 3l8 3v6c0 5-3.5 8.5-8 10-4.5-1.5-8-5-8-10V6l8-3z"/></svg>`,
    wave: `<svg viewBox="0 0 24 24"><path d="M3 12c2-4 4-4 6 0s4 4 6 0 4-4 6 0"/></svg>`,
    clock: `<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></svg>`,
    chip: `<svg viewBox="0 0 24 24"><rect x="7" y="7" width="10" height="10" rx="1"/><path d="M9 3v4M12 3v4M15 3v4M9 17v4M12 17v4M15 17v4M3 9h4M3 12h4M3 15h4M17 9h4M17 12h4M17 15h4"/></svg>`,
    alert: `<svg viewBox="0 0 24 24"><path d="M12 3l10 18H2L12 3z"/><path d="M12 10v5M12 17.5v.5"/></svg>`,
  };

  // Monochrome line icons (currentColor) — unique per type, dark-theme friendly
  const ICON_SVG = {
    tire: `<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="8"/><circle cx="12" cy="12" r="3"/><path d="M12 4v2M12 18v2M4 12h2M18 12h2"/></svg>`,
    tire_us: `<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="8"/><circle cx="12" cy="12" r="3"/><path d="M8 8l8 8M16 8l-8 8"/></svg>`,
    gate: `<svg viewBox="0 0 24 24"><path d="M4 20V8l8-4 8 4v12"/><path d="M4 10h16M9 10v10M15 10v10"/></svg>`,
    fob: `<svg viewBox="0 0 24 24"><rect x="8" y="3" width="8" height="14" rx="2"/><circle cx="12" cy="8" r="1.5"/><path d="M10 20h4M12 17v3"/></svg>`,
    alarm: `<svg viewBox="0 0 24 24"><path d="M6 10a6 6 0 0 1 12 0c0 4 2 5 2 5H4s2-1 2-5"/><path d="M10 19a2 2 0 0 0 4 0M9 4L7 2M15 4l2-2"/></svg>`,
    lora: `<svg viewBox="0 0 24 24"><path d="M12 20v-6"/><circle cx="12" cy="11" r="2"/><path d="M8 8a6 6 0 0 1 8 0M5.5 5.5a10 10 0 0 1 13 0"/></svg>`,
    plug: `<svg viewBox="0 0 24 24"><path d="M9 7V3M15 7V3M8 7h8v5a4 4 0 0 1-8 0V7zM12 16v5"/></svg>`,
    sensor: `<svg viewBox="0 0 24 24"><path d="M12 3v11a3 3 0 1 0 0 0"/><path d="M9 6h6"/></svg>`,
    factory: `<svg viewBox="0 0 24 24"><path d="M3 21V10l6 4V10l6 4V7l6 3v11z"/><path d="M7 21v-3M12 21v-3M17 21v-3"/></svg>`,
    home: `<svg viewBox="0 0 24 24"><path d="M3 11l9-7 9 7v9a1 1 0 0 1-1 1h-5v-6H9v6H4a1 1 0 0 1-1-1z"/></svg>`,
    walkie: `<svg viewBox="0 0 24 24"><rect x="7" y="6" width="10" height="15" rx="2"/><path d="M12 3v3M10 10h4M10 13h4"/></svg>`,
    phone: `<svg viewBox="0 0 24 24"><rect x="7" y="2" width="10" height="20" rx="2"/><path d="M10 18h4M11 5h2"/></svg>`,
    video: `<svg viewBox="0 0 24 24"><rect x="3" y="7" width="13" height="10" rx="1"/><path d="M16 10l5-3v10l-5-3z"/></svg>`,
    wifi: `<svg viewBox="0 0 24 24"><path d="M5 12.5a9 9 0 0 1 14 0M8 15.5a5 5 0 0 1 8 0"/><circle cx="12" cy="19" r="1.2" fill="currentColor" stroke="none"/></svg>`,
    spectrum: `<svg viewBox="0 0 24 24"><path d="M4 18V10M8 18V6M12 18v-8M16 18V4M20 18v-6"/></svg>`,
    tv: `<svg viewBox="0 0 24 24"><rect x="3" y="6" width="18" height="12" rx="1"/><path d="M8 21h8M12 18v3"/></svg>`,
    antenna: `<svg viewBox="0 0 24 24"><path d="M12 21V10M8 14l4-4 4 4"/><circle cx="12" cy="7" r="2"/><path d="M5 10a8 8 0 0 1 14 0"/></svg>`,
    plane: `<svg viewBox="0 0 24 24"><path d="M21 16v-2l-8-5V3.5a1.5 1.5 0 1 0-3 0V9l-8 5v2l8-2.5V19l-2 1.5V22l3.5-1 3.5 1v-1.5L13 19v-5.5l8 2.5z"/></svg>`,
    plane_side: `<svg viewBox="0 0 24 24"><path d="M3 13.5l8.5-2.2L21 8.5l-1.2 2.6-5.3 1.2 3.8 5.2-2.2.7-3.2-4.4-3.1.8L8.2 17H6.5l1.2-2.8L3 13.5z"/></svg>`,
    ship: `<svg viewBox="0 0 24 24"><path d="M3 17l2 3h14l2-3"/><path d="M5 17V11h14v6M12 11V5h4"/><path d="M9 8h3"/></svg>`,
    drone: `<svg viewBox="0 0 24 24"><rect x="9" y="10" width="6" height="4" rx="1"/><path d="M4 8l5 3M20 8l-5 3M4 16l5-3M20 16l-5-3"/><circle cx="4" cy="8" r="2"/><circle cx="20" cy="8" r="2"/><circle cx="4" cy="16" r="2"/><circle cx="20" cy="16" r="2"/></svg>`,
    pin: `<svg viewBox="0 0 24 24"><path d="M12 21s7-5.5 7-11a7 7 0 1 0-14 0c0 5.5 7 11 7 11z"/><circle cx="12" cy="10" r="2.5"/></svg>`,
    pager: `<svg viewBox="0 0 24 24"><rect x="3" y="7" width="18" height="11" rx="2"/><path d="M7 11h6M7 14h10"/></svg>`,
    plane_msg: `<svg viewBox="0 0 24 24"><path d="M3 12l18-8-4 16-5-4-3 4v-5z"/><path d="M11 15l8-11"/></svg>`,
    beacon: `<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="3"/><path d="M12 5v2M12 17v2M5 12h2M17 12h2M7 7l1.5 1.5M15.5 15.5L17 17M17 7l-1.5 1.5M7 17l1.5-1.5"/></svg>`,
    weather: `<svg viewBox="0 0 24 24"><path d="M8 18h9a4 4 0 0 0 0-8 5.5 5.5 0 0 0-10.4-1.5A3.5 3.5 0 0 0 8 18z"/></svg>`,
    car: `<svg viewBox="0 0 24 24"><path d="M4 14l2-5h12l2 5"/><path d="M3 14h18v4H3z"/><circle cx="7" cy="18" r="1.5"/><circle cx="17" cy="18" r="1.5"/></svg>`,
    lock: `<svg viewBox="0 0 24 24"><rect x="6" y="11" width="12" height="10" rx="1"/><path d="M8 11V8a4 4 0 0 1 8 0v3"/></svg>`,
    radio: `<svg viewBox="0 0 24 24"><rect x="3" y="8" width="18" height="12" rx="2"/><path d="M7 4l10 4M8 14h2M13 14h4"/></svg>`,
    chip_cat: `<svg viewBox="0 0 24 24"><rect x="7" y="7" width="10" height="10" rx="1"/><path d="M9 3v4M12 3v4M15 3v4M9 17v4M12 17v4M15 17v4M3 9h4M3 12h4M3 15h4M17 9h4M17 12h4M17 15h4"/></svg>`,
    rf: `<svg viewBox="0 0 24 24"><path d="M12 20v-4"/><path d="M8.5 12a5 5 0 0 1 7 0"/><path d="M5.5 9a9 9 0 0 1 13 0"/><circle cx="12" cy="16" r="1.2" fill="currentColor" stroke="none"/></svg>`,
  };

  // Unique icon key per device type (no repeats)
  const TYPE_ICON = {
    tpms_eu: "tire",
    tpms_us: "tire_us",
    garage_433: "gate",
    garage_315: "fob",
    alarm_869: "alarm",
    lora_eu868: "lora",
    tuya_ble: "plug",
    ble_sensors: "sensor",
    industrial_360: "factory",
    ism_868_domotica: "home",
    pmr446: "walkie",
    dect: "phone",
    lband_av: "video",
    wifi_24: "wifi",
    full_spectrum: "spectrum",
    smart_tv_bt: "tv",
    telemetry_1690: "antenna",
    wifi_ap: "wifi",
    adsb_1090: "plane",
    ais_marine: "ship",
    fpv_58: "drone",
    aprs_vhf: "pin",
    pocsag_pager: "pager",
    acars_vhf: "radio",
    epirb_406: "beacon",
    weather_433: "weather",
  };

  const CAT_ICON = {
    automotive: "car",
    access: "lock",
    iot: "chip_cat",
    industrial: "factory",
    comms: "radio",
    aviation: "plane",
    maritime: "ship",
  };

  // Catalog YAML icon names → SVG keys
  const NAMED_ICON = {
    plane: "plane",
    ship: "ship",
    drone: "drone",
    tire: "tire",
    key: "fob",
    alarm: "alarm",
    lora: "lora",
    plug: "plug",
    sensor: "sensor",
    factory: "factory",
    home: "home",
    walkie: "walkie",
    phone: "phone",
    fpv: "video",
    wifi: "wifi",
    spectrum: "spectrum",
    tv: "tv",
    antenna: "antenna",
    aprs: "pin",
    pager: "pager",
    beacon: "beacon",
    weather: "weather",
    car: "car",
    chip: "chip_cat",
    radio: "radio",
  };

  const PORTAPACK_TYPE_IDS = [
    "adsb_1090",
    "ais_marine",
    "fpv_58",
    "lband_av",
    "aprs_vhf",
    "pocsag_pager",
    "acars_vhf",
    "epirb_406",
    "weather_433",
    "pmr446",
    "dect",
    "industrial_360",
    "ble_sensors",
    "tuya_ble",
    "smart_tv_bt",
    "garage_433",
    "alarm_869",
    "tpms_eu",
    "lora_eu868",
    "ism_868_domotica",
    "wifi_24",
  ];

  function resolveIconKey(idOrObj) {
    if (!idOrObj) return "rf";
    if (typeof idOrObj === "string") {
      return TYPE_ICON[idOrObj] || CAT_ICON[idOrObj] || NAMED_ICON[idOrObj] || "rf";
    }
    const id = idOrObj.device_type_id || idOrObj.id;
    if (id && TYPE_ICON[id]) return TYPE_ICON[id];
    if (idOrObj.icon && NAMED_ICON[idOrObj.icon]) return NAMED_ICON[idOrObj.icon];
    if (idOrObj.icon && TYPE_ICON[idOrObj.icon]) return TYPE_ICON[idOrObj.icon];
    const cat = idOrObj.category;
    if (cat && CAT_ICON[cat]) return CAT_ICON[cat];
    const radio = (idOrObj.radio || "").toLowerCase();
    if (radio === "ble") return "plug";
    if (radio === "wifi") return "wifi";
    if (radio === "adsb") return "plane";
    if (radio === "ais") return "ship";
    return "rf";
  }

  function typeGlyph(idOrObj) {
    const key = resolveIconKey(idOrObj);
    return ICON_SVG[key] || ICON_SVG.rf;
  }

  function typeIconHtml(idOrObj, cls = "type-glyph") {
    return `<span class="${cls} mono-ico" aria-hidden="true">${typeGlyph(idOrObj)}</span>`;
  }

  function log(msg) {
    els.log.textContent += msg + "\n";
    els.log.scrollTop = els.log.scrollHeight;
  }

  function showModal(title, data, opts = {}) {
    els.modalTitle.textContent = title;
    els.modalSubtitle.textContent = opts.subtitle || "";
    modalRawPayload = opts.raw != null ? opts.raw : (typeof data === "object" ? data : null);
    modalShowingRaw = false;
    els.modalBody.classList.toggle("raw", false);
    if (opts.html) {
      els.modalBody.innerHTML = data;
      els.modalToggleRaw.classList.toggle("hidden", !modalRawPayload);
      els.modalToggleRaw.textContent = "Raw JSON";
    } else {
      els.modalBody.textContent = typeof data === "string" ? data : JSON.stringify(data, null, 2);
      els.modalBody.classList.add("raw");
      els.modalToggleRaw.classList.add("hidden");
    }
    els.modal.classList.remove("hidden");
  }

  function showDiveLoading(device) {
    const isTpms =
      device &&
      (device.device_type_id === "tpms_us" ||
        device.device_type_id === "tpms_eu" ||
        (device.metadata || {}).attack_profile === "tpms_315" ||
        (device.metadata || {}).attack_profile === "tpms_433");
    const isFpv = isFpvDevice(device);
    showModal(
      isFpv ? "FPV decode" : isTpms ? "TPMS deep dive" : "Deep dive",
      `<div class="dive-loading"><div class="spinner"></div>
        <p>${
          isFpv
            ? "Capturing wideband IQ + FM video demod…"
            : isTpms
              ? "Capturing IQ + decoding TPMS frames…"
              : "Capturing & analysing signal…"
        }</p>
        <p class="hint">${
          isFpv
            ? "~0.6s @ 10 Msps — needs an active analog VTX (NTSC/PAL)"
            : isTpms
              ? "Move/spin the tire or wait for sensor TX (~20s listen)"
              : "IQ / GATT probe in progress"
        }</p></div>`,
      { html: true, subtitle: isFpv && device?.freq_mhz != null ? `${Number(device.freq_mhz).toFixed(3)} MHz` : "Please wait" }
    );
    els.modalToggleRaw.classList.add("hidden");
  }

  function isFpvDevice(d) {
    if (!d) return false;
    const radio = (d.radio || "").toLowerCase();
    if (radio === "adsb" || radio === "ais" || radio === "ble") return false;
    const tid = String(d.device_type_id || "").toLowerCase();
    const meta = d.metadata || {};
    const profile = String(meta.attack_profile || "").toLowerCase();
    const hint = String((meta.catalog_hint || {}).device_type_id || "").toLowerCase();
    const blocked = new Set([
      "adsb_1090",
      "ais_marine",
      "acars_vhf",
      "aprs_vhf",
      "pocsag_pager",
      "epirb_406",
    ]);
    if (blocked.has(tid) || blocked.has(profile) || blocked.has(hint)) return false;
    if (tid === "fpv_58" || tid === "lband_av") return true;
    if (profile === "fpv_58" || profile === "lband_video") return true;
    if (hint === "fpv_58" || hint === "lband_av") return true;
    const f = d.freq_mhz;
    if (f == null) return false;
    const freq = Number(f);
    // 5.8 GHz VTX only — L-band via catalog type (avoids ADS-B @ 1090)
    return freq >= 5640 && freq <= 5955;
  }

  async function runFpvOrDive(d) {
    if (!d) return;
    const fpv = isFpvDevice(d);
    log((fpv ? "FPV decode " : "Deep dive ") + (d.key || d.freq_mhz || "") + "…");
    showDiveLoading(d);
    try {
      const res = await api("/api/deep-dive", {
        method: "POST",
        body: JSON.stringify({ device: d }),
      });
      showDiveReport(res);
      const risk = res.risk || {};
      const frames = (res.analysis?.fpv?.frames || []).length;
      if (fpv) {
        log(
          res.analysis?.fpv?.ok
            ? `FPV decode ok — ${frames} frame(s)`
            : `FPV decode — ${res.analysis?.fpv?.message || "no video"}`
        );
      } else {
        log(`Dive done — ${risk.severity || risk.status || "?"} ${risk.exploitability || ""}`);
      }
      const snap = await api("/api/tracker");
      setDevices(snap.devices || []);
      if (focusedKey && devicesByKey[focusedKey]) renderFocus(devicesByKey[focusedKey]);
    } catch (e) {
      showModal(fpv ? "FPV decode error" : "Deep dive error", String(e));
      log((fpv ? "FPV" : "Dive") + " ERROR: " + e);
    }
  }

  function fmtNum(v, digits = 1, suffix = "") {
    if (v == null || Number.isNaN(Number(v))) return "—";
    return `${Number(v).toFixed(digits)}${suffix}`;
  }

  function fmtHz(hz) {
    if (hz == null) return "—";
    const a = Math.abs(hz);
    if (a >= 1e6) return `${(hz / 1e6).toFixed(3)} MHz`;
    if (a >= 1e3) return `${(hz / 1e3).toFixed(1)} kHz`;
    return `${Math.round(hz)} Hz`;
  }

  function sevClass(sev) {
    const s = (sev || "unknown").toLowerCase();
    if (s === "vulnerable") return "critical";
    return s;
  }

  function svgSpectrumChart(points, opts = {}) {
    if (!points || points.length < 2) {
      return `<div class="chart-empty">No spectrum samples available</div>`;
    }
    const W = 860;
    const H = 180;
    const pad = { t: 16, r: 16, b: 28, l: 48 };
    const xs = points.map((p) => p.khz != null ? p.khz : p.hz / 1000);
    const ys = points.map((p) => p.db);
    const xmin = Math.min(...xs);
    const xmax = Math.max(...xs);
    const ymin = Math.min(...ys);
    const ymax = Math.max(...ys);
    const yPad = Math.max(2, (ymax - ymin) * 0.08);
    const y0 = ymin - yPad;
    const y1 = ymax + yPad;
    const xSpan = Math.max(xmax - xmin, 1e-6);
    const ySpan = Math.max(y1 - y0, 1e-6);
    const sx = (x) => pad.l + ((x - xmin) / xSpan) * (W - pad.l - pad.r);
    const sy = (y) => pad.t + (1 - (y - y0) / ySpan) * (H - pad.t - pad.b);

    const line = points
      .map((p, i) => {
        const x = sx(xs[i]);
        const y = sy(ys[i]);
        return `${i === 0 ? "M" : "L"}${x.toFixed(1)},${y.toFixed(1)}`;
      })
      .join(" ");
    const area =
      line +
      ` L${sx(xs[xs.length - 1]).toFixed(1)},${(H - pad.b).toFixed(1)}` +
      ` L${sx(xs[0]).toFixed(1)},${(H - pad.b).toFixed(1)} Z`;

    const peakI = ys.indexOf(Math.max(...ys));
    const peakX = sx(xs[peakI]);
    const peakY = sy(ys[peakI]);

    const yTicks = 4;
    let grid = "";
    for (let i = 0; i <= yTicks; i++) {
      const v = y0 + (ySpan * i) / yTicks;
      const y = sy(v);
      grid += `<line x1="${pad.l}" y1="${y}" x2="${W - pad.r}" y2="${y}" stroke="#243044" stroke-width="1"/>`;
      grid += `<text x="${pad.l - 6}" y="${y + 3}" fill="#7d8da6" font-size="10" text-anchor="end" font-family="JetBrains Mono,monospace">${v.toFixed(0)}</text>`;
    }
    grid += `<text x="${pad.l}" y="${H - 8}" fill="#7d8da6" font-size="10" font-family="JetBrains Mono,monospace">${xmin.toFixed(0)} kHz</text>`;
    grid += `<text x="${W - pad.r}" y="${H - 8}" fill="#7d8da6" font-size="10" text-anchor="end" font-family="JetBrains Mono,monospace">${xmax.toFixed(0)} kHz</text>`;

    return `
      <div class="chart-wrap">
        <svg viewBox="0 0 ${W} ${H}" preserveAspectRatio="none" role="img" aria-label="Spectrum">
          ${grid}
          <path d="${area}" fill="rgba(59,158,255,0.18)" />
          <path d="${line}" fill="none" stroke="#3b9eff" stroke-width="2" />
          <circle cx="${peakX}" cy="${peakY}" r="4" fill="#f0b429" stroke="#0a0e14" stroke-width="1.5"/>
        </svg>
      </div>
      <div class="chart-legend">
        <span><i style="background:#3b9eff"></i>PSD (dBFS)</span>
        <span><i style="background:#f0b429"></i>Peak ${ys[peakI].toFixed(1)} dB @ ${xs[peakI].toFixed(1)} kHz</span>
        ${opts.extra || ""}
      </div>`;
  }

  function svgHistoryChart(hist) {
    if (!hist || hist.length < 2) return "";
    const points = hist.map((db, i) => ({ khz: i, db }));
    return `
      <div class="dive-section">
        <h4>${ICONS.wave} Signal history (wardrive)</h4>
        ${svgSpectrumChart(points, { extra: "<span>Sample index → power</span>" })}
      </div>`;
  }

  function enrichRiskFromBle(risk, ble) {
    if (!risk || !ble?.services?.length) return risk;
    const writable = [];
    const readable = [];
    const hid = [];
    for (const svc of ble.services) {
      const su = svc.uuid || "";
      if (String(su).toLowerCase().includes("1812")) {
        hid.push(su);
      }
      for (const c of svc.characteristics || []) {
        const props = c.properties || [];
        const line = [c.description || "char", c.uuid, props.join(","), `svc ${su}`]
          .filter(Boolean)
          .join(" · ");
        if (props.includes("write") || props.includes("write-without-response")) {
          writable.push(line);
        }
        if (props.includes("read") && c.value_hex) {
          readable.push(line);
        }
        if (String(su).toLowerCase().includes("1812")) {
          hid.push(line);
        }
      }
    }
    const findings = (risk.findings || []).map((f) => {
      if (f.evidence?.length) return f;
      const title = f.finding || "";
      if (/writable GATT/i.test(title) && writable.length) {
        return { ...f, evidence: writable };
      }
      if (/unauthenticated GATT read/i.test(title) && readable.length) {
        return { ...f, evidence: readable };
      }
      if (/HID service/i.test(title) && hid.length) {
        return { ...f, evidence: hid };
      }
      return f;
    });
    return { ...risk, findings };
  }

  function evidenceList(items) {
    if (!items) return "";
    const arr = Array.isArray(items)
      ? items
      : typeof items === "string"
        ? [items]
        : [];
    if (!arr.length) return "";
    return `<ul class="finding-evidence">${arr
      .map((e) => {
        if (e == null) return "";
        if (typeof e === "string" || typeof e === "number") {
          return `<li><code>${escapeHtml(String(e))}</code></li>`;
        }
        const line = [
          e.uuid || e.name || "",
          e.description || "",
          Array.isArray(e.properties) ? e.properties.join(",") : e.props || "",
          e.service || e.service_uuid || "",
        ]
          .filter(Boolean)
          .join(" · ");
        return `<li><code>${escapeHtml(line || JSON.stringify(e))}</code></li>`;
      })
      .join("")}</ul>`;
  }

  function macHexForms(mac) {
    const raw = String(mac || "").replace(/[^0-9a-fA-F]/g, "").toLowerCase();
    if (raw.length !== 12) return [];
    const forms = [raw];
    let rev = "";
    for (let i = 10; i >= 0; i -= 2) rev += raw.slice(i, i + 2);
    if (rev !== raw) forms.push(rev);
    return forms;
  }

  function detectMacInMfg(device) {
    const forms = macHexForms(device?.mac);
    if (!forms.length) return null;
    const mfg = (device.metadata || {}).manufacturer_data || {};
    for (const [cid, hex] of Object.entries(mfg)) {
      const blob = String(hex || "").replace(/[^0-9a-fA-F]/g, "").toLowerCase();
      for (const form of forms) {
        const idx = blob.indexOf(form);
        if (idx >= 0) {
          return {
            company_id: cid,
            offset: Math.floor(idx / 2),
            match_hex: form,
            byte_reversed: form !== forms[0],
            blob,
            idx,
          };
        }
      }
    }
    return null;
  }

  function highlightMacInHex(hex, matchHex) {
    const blob = String(hex || "");
    const clean = blob.replace(/[^0-9a-fA-F]/gi, "");
    const form = String(matchHex || "").toLowerCase();
    const lower = clean.toLowerCase();
    const idx = form ? lower.indexOf(form) : -1;
    if (idx < 0) return escapeHtml(blob.slice(0, 96)) + (blob.length > 96 ? "…" : "");
    const before = clean.slice(0, idx);
    const mid = clean.slice(idx, idx + form.length);
    const after = clean.slice(idx + form.length);
    return `${escapeHtml(before)}<mark class="mac-hit">${escapeHtml(mid)}</mark>${escapeHtml(after.slice(0, 48))}${after.length > 48 ? "…" : ""}`;
  }

  function gattWriteStats(services) {
    let writable = 0;
    let readable = 0;
    const writeChars = [];
    for (const svc of services || []) {
      for (const c of svc.characteristics || []) {
        const props = (c.properties || []).map((p) => String(p).toLowerCase());
        const isWrite = props.includes("write") || props.includes("write-without-response");
        const isRead = props.includes("read") && (c.value_hex || c.value_ascii);
        if (isWrite) {
          writable += 1;
          writeChars.push({ service: svc.uuid, char: c, props });
        }
        if (isRead) readable += 1;
      }
    }
    return { writable, readable, writeChars };
  }

  function propChips(props) {
    return (props || [])
      .map((p) => {
        const pl = String(p).toLowerCase();
        const writeish = pl.includes("write");
        return `<span class="prop-chip${writeish ? " prop-write" : ""}">${escapeHtml(p)}</span>`;
      })
      .join("");
  }

  function renderFindingCard(f) {
    const sev = sevClass(f.severity);
    const detail =
      typeof f.detail === "string"
        ? f.detail
        : Array.isArray(f.detail)
          ? ""
          : f.detail
            ? JSON.stringify(f.detail)
            : "";
    const evidence = f.evidence || (Array.isArray(f.detail) ? f.detail : null);
    return `<div class="finding">
      <span class="finding-sev risk-pill risk-${escapeHtml(sev)}">${escapeHtml(sev)}</span>
      <div>
        <div class="finding-title">${escapeHtml(f.finding || f.name || "")}</div>
        ${detail ? `<div class="finding-detail">${escapeHtml(detail)}</div>` : ""}
        ${evidenceList(evidence)}
      </div>
    </div>`;
  }

  function diveHasFmDemod(res) {
    const uhf = res?.analysis?.uhf || res?.analysis?.rf?.uhf || {};
    const methods = uhf?.methods || [];
    if (methods.includes("fm_demod") || methods.includes("multimon-ng")) return true;
    if (uhf?.wav_file || uhf?.ok) return true;
    const findings = res?.risk?.findings || [];
    return findings.some((f) => {
      const blob = `${f.finding || ""} ${(f.evidence || []).join(" ")} ${f.detail || ""}`.toLowerCase();
      return blob.includes("fm_demod") || blob.includes("fm/fsk") || blob.includes("uhf telemetry");
    });
  }

  function diveCanListen(res) {
    const target = res?.target || {};
    if ((target.radio || "").toLowerCase() === "ble") return false;
    if (target.freq_mhz == null) return false;
    if (diveHasFmDemod(res)) return true;
    const profile = String(
      (target.metadata || {}).attack_profile || target.attack_profile || ""
    ).toLowerCase();
    return ["uhf_telemetry", "cw_telemetry", "pocsag", "aprs_vhf", "nbfm", "fm_voice"].includes(
      profile
    );
  }

  function renderUhfListen(res) {
    const uhf = res?.analysis?.uhf || res?.analysis?.rf?.uhf;
    const can = diveCanListen(res);
    if (!uhf && !can) return "";
    const diveId = res.dive_id || "";
    const methodsArr = uhf?.methods || [];
    const wav = uhf?.wav_file || (diveHasFmDemod(res) ? "uhf_fm.wav" : null);
    const wavUrl =
      wav && diveId
        ? `/api/artifact/${encodeURIComponent(diveId)}/${encodeURIComponent(wav)}`
        : "";
    const methods = methodsArr.join(", ") || "fm_demod";
    const summary = uhf?.summary || uhf?.message || "FM demod available";
    const freq =
      res?.target?.freq_mhz != null ? `${Number(res.target.freq_mhz).toFixed(4)} MHz` : "";
    return `<div class="dive-section dive-listen-panel" id="dive-listen-section">
      <h4>${ICONS.wave} Listen · FM demod</h4>
      <p class="hint">${escapeHtml(summary)}${freq ? " · " + escapeHtml(freq) : ""}
        · ${escapeHtml(methods)}</p>
      <p class="hint">Digital FSK/telemetry often sounds like hiss or bursts — not voice. Useful to ear-check the carrier.</p>
      ${
        wavUrl
          ? `<audio class="dive-audio" controls preload="metadata" src="${escapeHtml(wavUrl)}"></audio>
             <div class="dive-listen-actions">
               <span class="hint">From this dive IQ</span>
             </div>`
          : `<div class="hint">No WAV from this dive yet — use live listen.</div>`
      }
      ${
        can
          ? `<div class="dive-listen-actions">
               <button type="button" class="btn btn-deep" id="btn-dive-listen-live">🎧 Escuchar en vivo (~8s)</button>
             </div>
             <div id="dive-listen-status" class="hint"></div>
             <div id="dive-listen-live-player"></div>`
          : ""
      }
    </div>`;
  }

  function wireDiveListen(res) {
    const btn = document.getElementById("btn-dive-listen-live");
    if (!btn) return;
    const status = document.getElementById("dive-listen-status");
    const player = document.getElementById("dive-listen-live-player");
    btn.onclick = async () => {
      btn.disabled = true;
      const prev = btn.textContent;
      btn.textContent = "Capturando…";
      if (status) status.textContent = "HackRF RX + FM demod (wardrive se pausa)…";
      try {
        const out = await api("/api/listen/audio", {
          method: "POST",
          body: JSON.stringify({ device: res.target || {}, duration_s: 8 }),
        });
        if (!out.ok) {
          if (status) status.textContent = out.error || "Listen failed";
          return;
        }
        if (status) status.textContent = out.hint || "Listo — dale al play.";
        if (player && out.wav_url) {
          player.innerHTML = `<audio class="dive-audio" controls autoplay preload="auto" src="${escapeHtml(
            out.wav_url
          )}"></audio>`;
        }
      } catch (e) {
        if (status) status.textContent = String(e.message || e);
      } finally {
        btn.disabled = false;
        btn.textContent = prev;
      }
    };
  }

  function renderFindings(risk) {
    const findings = risk?.findings || [];
    if (!findings.length) {
      return `<div class="hint">No findings recorded.</div>`;
    }
    return `<div class="findings-list">${findings.map(renderFindingCard).join("")}</div>`;
  }

  function renderGatt(ble, opts = {}) {
    if (!ble) return "";
    if (ble.error && !ble.connected) {
      return `<div class="dive-section"><h4>${ICONS.ble} BLE / GATT</h4>
        <div class="finding"><span class="finding-sev risk-pill risk-medium">error</span>
        <div><div class="finding-title">Could not connect</div>
        <div class="finding-detail">${escapeHtml(ble.error)}</div></div></div></div>`;
    }
    const services = ble.services || [];
    const statsG = gattWriteStats(services);
    const writeOnly = opts.writeOnly !== false && statsG.writable > 0;
    const kpi = `<div class="gatt-kpi">
      <span class="gatt-kpi-w">${statsG.writable} writable</span>
      <span>·</span>
      <span>${statsG.readable} open read(s)</span>
      <span>·</span>
      <span>${services.length} service(s)</span>
      ${writeOnly ? `<span class="hint"> · showing writables first</span>` : ""}
    </div>`;

    const renderSvc = (svc, chars) => {
      if (!chars.length) return "";
      return `<div class="gatt-service">
        <div class="gatt-svc-head">${escapeHtml(svc.uuid)}</div>
        ${chars
          .map((c) => {
            const props = c.properties || [];
            const val = c.value_ascii
              ? escapeHtml(c.value_ascii)
              : c.value_hex
                ? escapeHtml(c.value_hex)
                : c.read_error
                  ? `read error: ${escapeHtml(c.read_error)}`
                  : "";
            const isWrite = props.some((p) => String(p).toLowerCase().includes("write"));
            return `<div class="gatt-char${isWrite ? " gatt-char-write" : ""}">
              <div class="uuid">${escapeHtml(c.uuid)}</div>
              <div class="gatt-props">${propChips(props)}</div>
              ${val ? `<div class="gatt-value">${val}</div>` : ""}
            </div>`;
          })
          .join("")}
      </div>`;
    };

    let body = "";
    if (writeOnly) {
      for (const svc of services) {
        const chars = (svc.characteristics || []).filter((c) =>
          (c.properties || []).some((p) => String(p).toLowerCase().includes("write"))
        );
        body += renderSvc(svc, chars);
      }
      // also show non-write briefly collapsed count
      const other = services.reduce((n, svc) => {
        return (
          n +
          (svc.characteristics || []).filter(
            (c) => !(c.properties || []).some((p) => String(p).toLowerCase().includes("write"))
          ).length
        );
      }, 0);
      if (other) {
        body += `<div class="hint">${other} non-writable characteristic(s) hidden — open Raw JSON for full tree</div>`;
      }
    } else {
      body =
        services.map((svc) => renderSvc(svc, svc.characteristics || [])).join("") ||
        '<div class="hint">No services discovered.</div>';
    }

    return `<div class="dive-section">
      <h4>${ICONS.ble} GATT map · ${ble.connected ? "connected" : "offline"}</h4>
      ${kpi}
      ${body}
    </div>`;
  }

  function renderTpms(tpms) {
    if (!tpms) return "";
    const sensors = tpms.sensors || [];
    if (!sensors.length) {
      return `<div class="dive-section">
        <h4>${ICONS.chip} TPMS decode</h4>
        <div class="hint">${escapeHtml(tpms.message || "No frames decoded")}</div>
      </div>`;
    }
    return `<div class="dive-section">
      <h4>${ICONS.chip} TPMS telemetry · ${sensors.length} sensor(s)</h4>
      <p class="hint">${escapeHtml(tpms.message || "")}</p>
      <div class="tpms-grid">
        ${sensors
          .map((s) => {
            const psi = s.pressure_psi != null ? `${s.pressure_psi} PSI` : "—";
            const kpa = s.pressure_kpa != null ? `${s.pressure_kpa} kPa` : "—";
            const temp = s.temperature_c != null ? `${s.temperature_c} °C` : "—";
            const batt =
              s.battery_ok == null ? "—" : s.battery_ok ? "OK" : "LOW";
            return `<div class="tpms-card">
              <div class="tpms-model">${escapeHtml(String(s.model || "TPMS"))}</div>
              <div class="tpms-id">ID ${escapeHtml(String(s.id))}</div>
              <div class="tpms-metrics">
                <div><span>Pressure</span><strong>${escapeHtml(psi)}</strong></div>
                <div><span>kPa</span><strong>${escapeHtml(kpa)}</strong></div>
                <div><span>Temp</span><strong>${escapeHtml(temp)}</strong></div>
                <div><span>Battery</span><strong>${escapeHtml(String(batt))}</strong></div>
              </div>
            </div>`;
          })
          .join("")}
      </div>
    </div>`;
  }

  function showDiveReport(res) {
    const target = res.target || {};
    const rf = res.analysis?.rf || null;
    const ble = res.analysis?.ble || null;
    const tpms = res.analysis?.tpms || null;
    const fpv = res.analysis?.fpv || null;
    const risk = enrichRiskFromBle(res.risk || {}, ble);
    const sev = sevClass(risk.severity || risk.status || target.risk_status);
    const isBle = (target.radio || "").toLowerCase() === "ble" || !!ble;
    const name =
      target.name || target.device_type_name || target.mac || (target.freq_mhz ? `${target.freq_mhz} MHz` : "Target");
    const loc = target.mac || (target.freq_mhz != null ? `${target.freq_mhz} MHz` : "—");

    const tpms0 = (tpms?.sensors || [])[0];
    const kpis = isBle
      ? [
          { icon: ICONS.ble, label: "MAC", value: target.mac || ble?.mac || "—", hint: "Address" },
          { icon: ICONS.signal, label: "RSSI", value: target.rssi_dbm != null ? `${Math.round(target.rssi_dbm)} dBm` : "—", hint: "Last advertisement" },
          { icon: ICONS.chip, label: "Services", value: String((ble?.services || []).length), hint: ble?.connected ? "Connected" : "Not connected" },
          { icon: ICONS.shield, label: "Risk", value: (risk.exploitability || sev || "—").toString(), hint: sev },
        ]
      : tpms0
        ? [
            { icon: ICONS.chip, label: "Sensor ID", value: String(tpms0.id ?? "—"), hint: tpms0.model || "TPMS" },
            { icon: ICONS.signal, label: "Pressure", value: tpms0.pressure_psi != null ? `${tpms0.pressure_psi} PSI` : "—", hint: tpms0.pressure_kpa != null ? `${tpms0.pressure_kpa} kPa` : "Tire" },
            { icon: ICONS.wave, label: "Temp", value: tpms0.temperature_c != null ? `${tpms0.temperature_c} °C` : "—", hint: "Tire / sensor" },
            { icon: ICONS.shield, label: "Sensors", value: String((tpms?.sensors || []).length), hint: tpms?.message || "" },
          ]
      : [
          { icon: ICONS.signal, label: "SNR", value: rf?.snr_db != null ? `+${rf.snr_db} dB` : strengthText(target), hint: "Peak vs noise" },
          { icon: ICONS.wave, label: "Bandwidth", value: fmtHz(rf?.bandwidth_3db_hz), hint: "−3 dB width" },
          { icon: ICONS.chip, label: "Type", value: rf?.signal_type || (target.metadata || {}).classification || "—", hint: "Classification" },
          { icon: ICONS.clock, label: "Capture", value: rf?.duration_s != null ? `${fmtNum(rf.duration_s, 1)} s` : "—", hint: "IQ duration" },
        ];

    const spectrumHtml = rf?.spectrum?.length
      ? `<div class="dive-section"><h4>${ICONS.wave} Spectrum (FFT)</h4>${svgSpectrumChart(rf.spectrum)}</div>`
      : svgHistoryChart(target.signal_history);

    let fpvHtml = "";
    if (fpv) {
      const ch = fpv.channel || {};
      const frames = fpv.frames || [];
      const imgs = frames
        .map((fr) =>
          fr.png_base64
            ? `<img class="fpv-frame" alt="FPV" src="data:image/png;base64,${fr.png_base64}" />`
            : fr.file
              ? `<img class="fpv-frame" alt="FPV" src="/api/artifact/${encodeURIComponent(res.dive_id)}/${encodeURIComponent(fr.file)}" />`
              : ""
        )
        .join("");
      fpvHtml = `<div class="dive-section"><h4>${ICONS.wave} FPV / FM video</h4>
        <p class="hint">${escapeHtml(fpv.message || "")}
          ${ch.channel ? " · " + escapeHtml(`${ch.band || ""} ${ch.channel}`.trim()) : ""}
          ${fpv.sync?.standard ? " · " + escapeHtml(String(fpv.sync.standard).toUpperCase()) : ""}
          ${fpv.viability?.level ? " · viability " + escapeHtml(fpv.viability.level) : ""}</p>
        ${
          fpv.rf
            ? `<p class="hint">RF: ${escapeHtml(String(fpv.rf.kind || "—"))}
                · 3 dB ≈ ${escapeHtml(String(fpv.rf.bw3db_mhz ?? "—"))} MHz
                · 99% ≈ ${escapeHtml(String(fpv.rf.occupied99_mhz ?? "—"))} MHz
                ${fpv.ok ? "" : " · analog VTX needs wide FM (~MHz), not a CW spur"}</p>`
            : ""
        }
        ${
          (fpv.viability?.notes || []).length
            ? `<ul class="hint" style="margin:0.35rem 0 0.5rem;padding-left:1.1rem">${(fpv.viability.notes || [])
                .slice(0, 6)
                .map((n) => `<li>${escapeHtml(String(n))}</li>`)
                .join("")}</ul>`
            : ""
        }
        <div class="fpv-frames">${imgs || "<span class='hint'>No frames extracted</span>"}</div>
      </div>`;
    }

    const metaRows = [
      ["Dive ID", res.dive_id],
      ["Key", target.key],
      ["Radio", (target.radio || "").toUpperCase()],
      ["Profile", risk.profile || (target.metadata || {}).attack_profile],
      ["Peak offset", rf ? fmtHz(rf.peak_offset_hz) : null],
      ["Mean power", rf?.mean_dbfs != null ? `${fmtNum(rf.mean_dbfs, 1)} dBFS` : null],
      ["Noise floor", rf?.noise_floor_dbfs != null ? `${fmtNum(rf.noise_floor_dbfs, 1)} dBFS` : null],
      ["IQ artifact", rf?.iq_file],
      ["Completed", (res.completed_utc || "").replace("T", " ").slice(0, 19)],
    ].filter(([, v]) => v != null && v !== "");

    const html = `
      <div class="dive-report">
        <div class="dive-hero">
          <div class="dive-hero-main">
            <div class="dive-icon ${isBle ? "ble" : ""}">${isBle ? ICONS.ble : ICONS.rf}</div>
            <div>
              <div class="dive-title">${escapeHtml(name)}</div>
              <div class="dive-meta">${escapeHtml(loc)} · ${escapeHtml(target.device_type_name || target.device_type_id || "")}</div>
            </div>
          </div>
          <span class="dive-sev risk-pill risk-${escapeHtml(sev)}">${escapeHtml(sev)}</span>
        </div>

        <div class="kpi-grid">
          ${kpis
            .map(
              (k) => `<div class="kpi">
              <div class="kpi-label">${k.icon}${escapeHtml(k.label)}</div>
              <div class="kpi-value">${escapeHtml(k.value)}</div>
              <div class="kpi-hint">${escapeHtml(k.hint || "")}</div>
            </div>`
            )
            .join("")}
        </div>

        ${renderTpms(tpms)}
        ${fpvHtml}
        ${renderUhfListen(res)}
        <div class="dive-section">
          <h4>${ICONS.shield} Risk findings</h4>
          ${renderFindings(risk)}
        </div>
        ${spectrumHtml}
        ${renderGatt(ble)}

        <div class="dive-section">
          <h4>${ICONS.alert} Metadata</h4>
          <dl class="meta-table">
            ${metaRows
              .map(([k, v]) => `<dt>${escapeHtml(k)}</dt><dd>${escapeHtml(String(v))}</dd>`)
              .join("")}
          </dl>
        </div>
      </div>`;

    showModal("Deep dive report", html, {
      html: true,
      subtitle: res.dive_id || "",
      raw: res,
    });
    wireDiveListen(res);
  }

  async function api(path, opts = {}) {
    const r = await fetch(path, {
      headers: { "Content-Type": "application/json" },
      ...opts,
    });
    return r.json();
  }

  function escapeHtml(s) {
    const d = document.createElement("div");
    d.textContent = s == null ? "" : String(s);
    return d.innerHTML;
  }

  function selectedMode() {
    const el = document.querySelector('input[name="mode"]:checked');
    return el ? el.value : "wardrive";
  }

  function scanButtonLabel(mode) {
    if (mode === "wardrive") return "▶ Start wardrive";
    if (mode === "full_sweep") return "▶ Full sweep 1–6 GHz";
    return "▶ Start scan";
  }

  function syncModeHint() {
    const hint = $("#mode-hint");
    if (!hint) return;
    const mode = selectedMode();
    if (mode === "full_sweep") {
      hint.textContent =
        "Full sweep: HackRF 1→6000 MHz in 100 MHz chunks (~2–6 sweeps each). Slow; no type selection needed.";
    } else if (mode === "once") {
      hint.textContent = "Once: single pass over selected device types.";
    } else {
      hint.textContent = "Wardrive loops selected bands. Full sweep = HackRF 1–6000 MHz.";
    }
  }

  function levelClass(level) {
    if (level <= 3) return "level-low";
    if (level <= 6) return "level-mid";
    return "level-high";
  }

  function strengthText(d) {
    if (d.rssi_dbm != null) return `${Math.round(d.rssi_dbm)} dBm`;
    if (d.power_dbm != null) return `${d.power_dbm} dBm`;
    if (d.snr_db != null) return `+${d.snr_db} dB`;
    return "—";
  }

  function locText(d) {
    if ((d.radio || "").toLowerCase() === "wifi") {
      const ch = (d.metadata || {}).channel;
      const sec = (d.metadata || {}).security;
      const bits = [];
      if (ch != null) bits.push(`ch ${ch}`);
      if (d.freq_mhz) bits.push(`${d.freq_mhz} MHz`);
      if (sec) bits.push(sec);
      return bits.join(" · ") || d.mac || "—";
    }
    if (d.freq_mhz) return `${d.freq_mhz} MHz`;
    if (d.mac) return d.mac;
    return "—";
  }

  function deviceSev(d) {
    const r = d.risk || {};
    let s = (r.severity || d.risk_status || "unknown").toLowerCase();
    if (s === "vulnerable") s = "critical";
    if (s === "suspected") s = "medium";
    return s;
  }

  function deviceVendor(d) {
    return (
      d.vendor ||
      ((d.metadata || {}).fingerprint || {}).vendor ||
      (d.metadata || {}).oui_hint ||
      ""
    );
  }

  function deviceModel(d) {
    return (
      d.model_guess ||
      ((d.metadata || {}).fingerprint || {}).model_guess ||
      ""
    );
  }

  function deviceFamily(d) {
    return d.family || ((d.metadata || {}).fingerprint || {}).family || "";
  }

  function sparkHtml(hist) {
    if (!hist || !hist.length) return "";
    const mn = Math.min(...hist);
    const mx = Math.max(...hist);
    const span = Math.max(mx - mn, 1e-6);
    const blocks = "▁▂▃▄▅▆▇█";
    return hist
      .slice(-20)
      .map((v) => blocks[Math.min(7, Math.floor(((v - mn) / span) * 7))])
      .join("");
  }

  function anythingRunning() {
    return scanRunning || vulnRunning || monitoring;
  }

  function syncStopButton() {
    els.btnStop.disabled = !anythingRunning();
  }

  function visibleTypes() {
    return catalog.device_types.filter(
      (d) => activeCategory === "all" || d.category === activeCategory
    );
  }

  function updateSelectedCount() {
    const n = selected.size;
    const vis = new Set(visibleTypes().map((t) => t.id));
    const outside = [...selected].filter((id) => !vis.has(id)).length;
    let text = n === 1 ? "1 selected" : `${n} selected`;
    if (outside && activeCategory !== "all") {
      text += ` · ${outside} outside this tab`;
    }
    els.selectedCount.textContent = text;
    els.selectedCount.title = [...selected].sort().join(", ") || "None";
    els.btnSelectAll.classList.toggle("hidden", activeCategory === "all");
  }

  function updateScanBadge(status) {
    const map = {
      idle: ["Idle", "badge-muted"],
      running: ["Live…", "badge-run"],
      stopping: ["Stopping…", "badge-warn"],
      completed: ["Complete", "badge-ok"],
      stopped: ["Stopped", "badge-warn"],
      error: ["Error", "badge-warn"],
    };
    const [text, cls] = map[status] || ["Unknown", "badge-muted"];
    els.scanStatus.textContent = text;
    els.scanStatus.className = "badge " + cls;
    els.btnScan.disabled = status === "running" || status === "stopping" || vulnRunning;
    scanRunning = status === "running";
    syncStopButton();
    const mode = selectedMode();
    els.btnScan.textContent = scanButtonLabel(mode);
  }

  function updateVulnBadge(status, counts) {
    const running = status === "running";
    vulnRunning = running;
    els.vulnStatus.textContent = running ? "Vulns…" : status === "completed" ? "Vulns done" : "Vulns idle";
    els.vulnStatus.className = "badge " + (running ? "badge-run" : status === "completed" ? "badge-ok" : "badge-muted");
    els.btnVulnQuick.disabled = running || scanRunning;
    els.btnVulnFull.disabled = running || scanRunning;
    if (els.btnTpmsDecode) els.btnTpmsDecode.disabled = running || scanRunning;
    syncStopButton();
    if (counts) renderVulnCounts(counts);
  }

  function renderVulnCounts(counts) {
    const order = ["critical", "high", "medium", "low"];
    els.vulnCounts.innerHTML = order
      .map((k) => {
        const n = counts[k] || 0;
        return `<span class="risk-pill risk-${k}">${k}: ${n}</span>`;
      })
      .join("");
  }

  async function loadHealth() {
    const h = await api("/api/health");
    els.hackrf.textContent = h.hackrf ? "HackRF OK" : "HackRF N/A";
    els.hackrf.className = "badge " + (h.hackrf ? "badge-ok" : "badge-warn");
    updateGpsBadge(h.gps);
    updateScanBadge(h.scan_status);
    updateVulnBadge(h.vuln_status || "idle");
    els.trackCount.textContent = `${h.tracked || 0} devices`;
    if ((h.scan_status === "running" || h.vuln_status === "running") && !pollTimer) {
      startPolling();
    }
    // Sync accept flag from backend only on first paint when we haven't stopped locally.
    const backendWifi = h.wifi || {};
    if (!wifiLiveEnabled) {
      // Keep badge stopped even if a late process still reports running briefly.
      updateWifiBadge({
        ...backendWifi,
        status: "stopped",
        ap_count: wifiAps.length,
      });
      return;
    }
    updateWifiBadge(backendWifi);
    try {
      const w = await api("/api/wifi/aps?limit=300");
      if (!wifiLiveEnabled) return;
      if (w.aps) {
        wifiAps = w.aps;
        updateWifiBadge({ ...w, ap_count: w.count != null ? w.count : w.aps.length });
        refreshMapWifi();
        renderDeviceList();
      }
    } catch (_) {}
  }

  function updateGpsBadge(g) {
    if (!els.gpsStatus) return;
    if (!g) {
      els.gpsStatus.textContent = "GPS …";
      els.gpsStatus.className = "badge badge-muted";
      return;
    }
    const fix = g.fix;
    if (g.has_fix && fix) {
      els.gpsStatus.textContent = `GPS 3D · ${Number(fix.lat).toFixed(5)}, ${Number(fix.lon).toFixed(5)}`;
      els.gpsStatus.className = "badge badge-ok";
      gpsFix = fix;
      updateMapFixLabel();
      updateHunterMarker();
    } else if (g.status === "listening" || g.status === "connecting") {
      els.gpsStatus.textContent = "GPS searching…";
      els.gpsStatus.className = "badge badge-warn";
    } else if (g.status === "error") {
      els.gpsStatus.textContent = "GPS error";
      els.gpsStatus.className = "badge badge-warn";
      els.gpsStatus.title = g.error || "";
    } else {
      els.gpsStatus.textContent = `GPS ${g.status || "idle"}`;
      els.gpsStatus.className = "badge badge-muted";
    }
  }

  function updateWifiBadge(w) {
    if (!els.wifiStatus) return;
    wifiStatus = w || wifiStatus;
    if (!wifiStatus) {
      els.wifiStatus.textContent = "Wi‑Fi …";
      els.wifiStatus.className = "badge badge-muted";
      return;
    }
    const n = wifiStatus.ap_count != null ? wifiStatus.ap_count : wifiAps.length;
    const iface = wifiStatus.iface || "?";
    const st = wifiLiveEnabled ? wifiStatus.status : "stopped";
    if (st === "running") {
      els.wifiStatus.textContent = `Wi‑Fi ${iface} · ${n} AP`;
      els.wifiStatus.className = "badge badge-ok";
      els.wifiStatus.title = "Click to stop Wi‑Fi scan";
    } else if (st === "error") {
      els.wifiStatus.textContent = "Wi‑Fi error";
      els.wifiStatus.className = "badge badge-warn";
      els.wifiStatus.title = wifiStatus.error || "Click to retry Wi‑Fi scan";
    } else {
      els.wifiStatus.textContent = `Wi‑Fi ${st || "idle"}`;
      els.wifiStatus.className = "badge badge-muted";
      els.wifiStatus.title = "Click to start Wi‑Fi scan";
    }
    els.wifiStatus.style.cursor = "pointer";
  }

  async function stopWifiScan({ clear = true } = {}) {
    wifiLiveEnabled = false;
    try {
      await api("/api/wifi/stop", { method: "POST" });
    } catch (_) {}
    if (clear) clearWifiUi();
    updateWifiBadge({ ...(wifiStatus || {}), status: "stopped", ap_count: clear ? 0 : wifiAps.length });
  }

  async function startWifiScan() {
    wifiLiveEnabled = true;
    const res = await api("/api/wifi/start", { method: "POST" });
    updateWifiBadge(res);
    return res;
  }

  if (els.wifiStatus) {
    els.wifiStatus.onclick = async () => {
      try {
        if (wifiLiveEnabled) {
          await stopWifiScan({ clear: true });
          log("Wi‑Fi scan stopped");
        } else {
          const res = await startWifiScan();
          log(`Wi‑Fi scan started on ${res.iface || "?"}`);
        }
      } catch (e) {
        log("Wi‑Fi toggle error: " + e);
      }
    };
  }

  function updateMapFixLabel() {
    if (!els.mapFixLabel) return;
    if (!gpsFix) {
      els.mapFixLabel.textContent = "Waiting for GPS fix…";
      return;
    }
    const spd = gpsFix.speed != null ? `${(Number(gpsFix.speed) * 3.6).toFixed(1)} km/h` : "—";
    const alt = gpsFix.alt != null ? `${Number(gpsFix.alt).toFixed(0)} m` : "—";
    els.mapFixLabel.textContent = `${Number(gpsFix.lat).toFixed(6)}, ${Number(gpsFix.lon).toFixed(6)} · alt ${alt} · ${spd} · trail ${gpsTrail.length} · wifi ${wifiAps.length}`;
  }

  /** Basemap providers — no API key. Carto dark often blocks in-browser now. */
  const MAP_TILE_SOURCES = [
    {
      id: "versatiles",
      url: "https://tiles.versatiles.org/tiles/osm/{z}/{x}/{y}.png",
      attribution:
        '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> · <a href="https://versatiles.org">VersaTiles</a>',
      maxZoom: 19,
    },
    {
      id: "osm",
      url: "https://tile.openstreetmap.org/{z}/{x}/{y}.png",
      attribution:
        '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a>',
      maxZoom: 19,
    },
  ];

  function addMapBasemap() {
    if (!map || mapBasemapLayer) return;
    let idx = 0;
    const mount = () => {
      const src = MAP_TILE_SOURCES[idx];
      if (!src) return;
      if (mapBasemapLayer) {
        map.removeLayer(mapBasemapLayer);
        mapBasemapLayer = null;
      }
      mapBasemapLayer = L.tileLayer(src.url, {
        attribution: src.attribution,
        maxZoom: src.maxZoom,
      });
      mapBasemapLayer.on("tileerror", () => {
        if (idx >= MAP_TILE_SOURCES.length - 1) return;
        idx += 1;
        log(`Map tiles: ${src.id} failed — trying ${MAP_TILE_SOURCES[idx].id}`);
        mount();
      });
      mapBasemapLayer.addTo(map);
    };
    mount();
  }

  function ensureMap() {
    if (mapReady || typeof L === "undefined") return;
    const el = $("#wardrive-map");
    if (!el) return;
    const hasFix = gpsFix && gpsFix.lat != null && gpsFix.lon != null;
    const initLat = hasFix ? Number(gpsFix.lat) : 0;
    const initLon = hasFix ? Number(gpsFix.lon) : 0;
    const initZoom = hasFix ? 16 : 2;
    map = L.map(el, {
      zoomControl: true,
      attributionControl: true,
    }).setView([initLat, initLon], initZoom);

    addMapBasemap();

    mapLayerGroup = L.layerGroup().addTo(map);
    wifiLayerGroup = L.layerGroup().addTo(map);
    trailLine = L.polyline([], {
      color: "#c084fc",
      weight: 3,
      opacity: 0.75,
      lineJoin: "round",
    }).addTo(map);

    // Re-spider overlapping pins so screen spacing stays clickable at every zoom
    map.on("zoomend", () => {
      refreshMapDevices();
      refreshMapWifi();
    });

    mapReady = true;
    setTimeout(() => map.invalidateSize(), 80);
    refreshMapDevices();
    refreshMapWifi();
    updateHunterMarker();
    redrawTrail();
  }

  function geoBucketKey(ll) {
    // ~1 m buckets — wardrive pins that share the hunter fix stack together
    return `${Number(ll[0]).toFixed(5)},${Number(ll[1]).toFixed(5)}`;
  }

  /** Spread co-located pins in screen pixels (ring / spiral) so they stay clickable. */
  function spiderfyLatLng(baseLl, index, total) {
    if (!map || total <= 1) return baseLl;
    const pt = map.latLngToLayerPoint(L.latLng(baseLl[0], baseLl[1]));
    let dx;
    let dy;
    if (total <= 12) {
      const angle = (2 * Math.PI * index) / total - Math.PI / 2;
      const px = Math.max(20, 12 + total * 3.2);
      dx = Math.cos(angle) * px;
      dy = Math.sin(angle) * px;
    } else {
      const angle = index * 2.399963229728653;
      const px = 16 + index * 6.2;
      dx = Math.cos(angle) * px;
      dy = Math.sin(angle) * px;
    }
    const next = map.layerPointToLatLng(L.point(pt.x + dx, pt.y + dy));
    return [next.lat, next.lng];
  }

  function fmtCoord(v, digits = 5) {
    if (v == null || Number.isNaN(Number(v))) return null;
    return Number(v).toFixed(digits);
  }

  function aeroBlock(d) {
    return (d.metadata || {}).adsb || null;
  }

  function marineBlock(d) {
    return (d.metadata || {}).ais || null;
  }

  function trafficPopupHtml(d, ll) {
    const adsb = aeroBlock(d);
    const ais = marineBlock(d);
    const name = d.name || d.device_type_name || d.key || "?";
    // Clear filled traffic glyphs — line "plane" path looked like a star in popups
    const planeIco = `<span class="pop-ico pop-ico-fill" aria-hidden="true"><svg viewBox="0 0 24 24"><path d="M21 16v-2l-8-5V3.5a1.5 1.5 0 0 0-3 0V9l-8 5v2l8-2.5V19l-2 1.5V22l3.5-1 3.5 1v-1.5L13 19v-5.5l8 2.5z"/></svg></span>`;
    const shipIco = `<span class="pop-ico pop-ico-fill" aria-hidden="true"><svg viewBox="0 0 24 24"><path d="M3 17l2 3h14l2-3H3zm1-2h16V11H12V6h3l1 2h2L16 4H8L6 8h2l1-2h3v5H4v4z"/></svg></span>`;
    const glyph = adsb
      ? planeIco
      : ais
        ? shipIco
        : `<span class="pop-ico" aria-hidden="true">${typeGlyph(d)}</span>`;
    const lines = [];
    lines.push(`<div class="pop-title">${glyph}<span>${escapeHtml(name)}</span></div>`);

    if (adsb) {
      lines.push(`<div class="pop-grid">`);
      const rows = [
        ["ICAO", adsb.icao],
        ["Callsign", adsb.callsign],
        ["Lat", fmtCoord(adsb.lat ?? d.lat ?? ll?.[0])],
        ["Lon", fmtCoord(adsb.lon ?? d.lon ?? ll?.[1])],
        ["Alt", adsb.alt_ft != null ? `${Math.round(adsb.alt_ft)} ft (${adsb.alt_m != null ? Math.round(adsb.alt_m) : Math.round(adsb.alt_ft * 0.3048)} m)` : null],
        ["Speed", adsb.speed_kts != null ? `${Math.round(adsb.speed_kts)} kt (${adsb.speed_kmh != null ? Math.round(adsb.speed_kmh) : Math.round(adsb.speed_kts * 1.852)} km/h)` : null],
        ["Track", adsb.track_deg != null ? `${Math.round(adsb.track_deg)}°` : null],
        ["Heading", adsb.heading_deg != null ? `${Math.round(adsb.heading_deg)}°` : null],
        ["V/S", adsb.vertical_rate_fpm != null ? `${Math.round(adsb.vertical_rate_fpm)} fpm` : null],
        ["Squawk", adsb.squawk],
        [
          "Category",
          (() => {
            const w = adsb.wake_vortex || adsb.model;
            if (w && !/no category/i.test(String(w))) return w;
            if (adsb.category != null && adsb.category !== 0 && adsb.category !== "0") return adsb.category;
            return null;
          })(),
        ],
        ["Msgs", adsb.messages],
      ];
      rows.forEach(([k, v]) => {
        if (v == null || v === "") return;
        lines.push(`<div class="pop-row"><span>${escapeHtml(k)}</span><b>${escapeHtml(String(v))}</b></div>`);
      });
      if (adsb.speed_kts == null || (adsb.track_deg == null && adsb.heading_deg == null)) {
        lines.push(
          `<div class="pop-meta pop-warn">Sin velocidad/rumbo — otra escucha ADS‑B (wardrive). Con 1 trama el pin no se mueve.</div>`
        );
      } else if (adsb.kinematics_source === "position_delta") {
        lines.push(`<div class="pop-meta">Speed/track estimado entre posiciones</div>`);
      }
      lines.push(`</div>`);
    } else if (ais) {
      lines.push(`<div class="pop-grid">`);
      const rows = [
        ["MMSI", ais.mmsi],
        ["Name", ais.shipname || ais.name],
        ["Lat", fmtCoord(ais.lat ?? d.lat ?? ll?.[0])],
        ["Lon", fmtCoord(ais.lon ?? d.lon ?? ll?.[1])],
        ["SOG", ais.sog_kts != null ? `${ais.sog_kts} kt` : null],
        ["COG", ais.cog_deg != null ? `${ais.cog_deg}°` : null],
        ["Type", ais.ship_type || ais.type],
        ["Dest", ais.destination],
        ["Draft", ais.draught],
      ];
      rows.forEach(([k, v]) => {
        if (v == null || v === "") return;
        lines.push(`<div class="pop-row"><span>${escapeHtml(k)}</span><b>${escapeHtml(String(v))}</b></div>`);
      });
      lines.push(`</div>`);
    } else {
      const meta = d.metadata || {};
      const cap = meta.capability || "presence";
      const isPresence = cap === "presence" || !hasEmitterPosition(d);
      lines.push(
        `<div class="pop-meta">${escapeHtml(locText(d))} · ${(d.radio || "?").toUpperCase()} · ${escapeHtml(deviceSev(d))}</div>`
      );
      if (isPresence) {
        lines.push(
          `<div class="pop-meta pop-warn">RF presence at hunter GPS — not a live aircraft/vessel track. No ADS‑B position/speed.</div>`
        );
      }
      lines.push(
        `<div class="pop-meta">${ll[0].toFixed(5)}, ${ll[1].toFixed(5)}${
          isSignalGeo(d) && hasEmitterPosition(d) ? " · emitter position" : " · hunter pin (first seen)"
        }</div>`
      );
    }
    return lines.join("");
  }

  function pushTrafficMetaRows(rows, d) {
    const adsb = aeroBlock(d);
    const ais = marineBlock(d);
    if (adsb) {
      rows.push(["ICAO", adsb.icao]);
      if (adsb.callsign) rows.push(["Callsign / flight", adsb.callsign]);
      rows.push(["Lat", fmtCoord(adsb.lat ?? d.lat, 6)]);
      rows.push(["Lon", fmtCoord(adsb.lon ?? d.lon, 6)]);
      if (adsb.alt_ft != null) {
        rows.push([
          "Altitude",
          `${Math.round(adsb.alt_ft)} ft · ${
            adsb.alt_m != null ? Math.round(adsb.alt_m) : Math.round(Number(adsb.alt_ft) * 0.3048)
          } m`,
        ]);
      }
      if (adsb.speed_kts != null) {
        rows.push([
          "Speed",
          `${Math.round(adsb.speed_kts)} kt · ${
            adsb.speed_kmh != null ? Math.round(adsb.speed_kmh) : Math.round(Number(adsb.speed_kts) * 1.852)
          } km/h`,
        ]);
      }
      if (adsb.track_deg != null) rows.push(["Track", `${Math.round(adsb.track_deg)}°`]);
      if (adsb.heading_deg != null) rows.push(["Heading", `${Math.round(adsb.heading_deg)}°`]);
      if (adsb.vertical_rate_fpm != null) {
        rows.push(["Vertical rate", `${Math.round(adsb.vertical_rate_fpm)} fpm`]);
      }
      if (adsb.squawk != null) rows.push(["Squawk", adsb.squawk]);
      const wake =
        adsb.wake_vortex && !/no category/i.test(String(adsb.wake_vortex)) ? adsb.wake_vortex : null;
      if (wake) rows.push(["Wake / category", wake]);
      else if (adsb.category != null && adsb.category !== 0 && adsb.category !== "0") {
        rows.push(["Category", adsb.category]);
      }
      if (adsb.model && adsb.model !== wake && !/no category/i.test(String(adsb.model))) {
        rows.push(["Model / class", adsb.model]);
      }
      if (adsb.emergency_state != null) rows.push(["Emergency", adsb.emergency_state]);
      if (adsb.nac_p != null) rows.push(["NACp", adsb.nac_p]);
      if (adsb.sil != null) rows.push(["SIL", adsb.sil]);
      if (adsb.typecode != null) rows.push(["Typecode", adsb.typecode]);
      if (adsb.bds) rows.push(["BDS", adsb.bds]);
      if (adsb.messages != null) rows.push(["ADS-B msgs", adsb.messages]);
      if (adsb.last_msg) rows.push(["Last Mode-S", String(adsb.last_msg).slice(0, 28)]);
      const fields = adsb.fields || {};
      Object.keys(fields)
        .sort()
        .forEach((k) => {
          const v = fields[k];
          if (v == null || v === "") return;
          if (
            [
              "callsign",
              "latitude",
              "longitude",
              "altitude",
              "groundspeed",
              "airspeed",
              "track",
              "heading",
              "category",
              "wake_vortex",
              "squawk",
              "typecode",
              "bds",
            ].includes(k)
          ) {
            return;
          }
          rows.push([`ADS-B · ${k}`, typeof v === "object" ? JSON.stringify(v) : v]);
        });
    }
    if (ais) {
      rows.push(["MMSI", ais.mmsi]);
      rows.push(["Ship name", ais.shipname || ais.name]);
      rows.push(["Lat", fmtCoord(ais.lat ?? d.lat, 6)]);
      rows.push(["Lon", fmtCoord(ais.lon ?? d.lon, 6)]);
      if (ais.sog_kts != null) rows.push(["SOG", `${ais.sog_kts} kt`]);
      if (ais.cog_deg != null) rows.push(["COG", `${ais.cog_deg}°`]);
      if (ais.heading_deg != null) rows.push(["Heading", `${ais.heading_deg}°`]);
      if (ais.ship_type || ais.type) rows.push(["Ship type", ais.ship_type || ais.type]);
      if (ais.destination) rows.push(["Destination", ais.destination]);
      if (ais.draught != null) rows.push(["Draught", ais.draught]);
      if (ais.imo) rows.push(["IMO", ais.imo]);
      if (ais.callsign) rows.push(["Callsign", ais.callsign]);
      if (ais.status) rows.push(["Nav status", ais.status]);
      const fields = ais.fields || {};
      Object.keys(fields)
        .sort()
        .forEach((k) => {
          const v = fields[k];
          if (v == null || v === "") return;
          rows.push([`AIS · ${k}`, typeof v === "object" ? JSON.stringify(v) : v]);
        });
    }
  }

  function renderTrafficFocus(d) {
    if (!els.focusTraffic) return;
    const adsb = aeroBlock(d);
    const ais = marineBlock(d);
    if (!adsb && !ais) {
      els.focusTraffic.classList.add("hidden");
      els.focusTraffic.innerHTML = "";
      return;
    }
    els.focusTraffic.classList.remove("hidden");
    if (adsb) {
      const callsign = adsb.callsign || "—";
      const icao = adsb.icao || "—";
      const alt =
        adsb.alt_ft != null
          ? `${Math.round(adsb.alt_ft)} ft · ${
              adsb.alt_m != null ? Math.round(adsb.alt_m) : Math.round(adsb.alt_ft * 0.3048)
            } m`
          : "—";
      const spd =
        adsb.speed_kts != null
          ? `${Math.round(adsb.speed_kts)} kt · ${
              adsb.speed_kmh != null ? Math.round(adsb.speed_kmh) : Math.round(adsb.speed_kts * 1.852)
            } km/h`
          : "—";
      const trk = adsb.track_deg != null ? `${Math.round(adsb.track_deg)}°` : "—";
      const vs = adsb.vertical_rate_fpm != null ? `${Math.round(adsb.vertical_rate_fpm)} fpm` : "—";
      const model =
        adsb.model && !/no category/i.test(String(adsb.model))
          ? adsb.model
          : adsb.wake_vortex && !/no category/i.test(String(adsb.wake_vortex))
            ? adsb.wake_vortex
            : "—";
      const sq = adsb.squawk != null ? String(adsb.squawk) : "—";
      els.focusTraffic.innerHTML = `
        <div class="traffic-focus-head">
          <div class="traffic-callsign">${escapeHtml(callsign)}</div>
          <div class="traffic-icao">ICAO ${escapeHtml(String(icao))}</div>
        </div>
        <div class="traffic-stats">
          <div><span>Altitude</span><b>${escapeHtml(alt)}</b></div>
          <div><span>Speed</span><b>${escapeHtml(spd)}</b></div>
          <div><span>Track</span><b>${escapeHtml(trk)}</b></div>
          <div><span>V/S</span><b>${escapeHtml(vs)}</b></div>
          <div><span>Squawk</span><b>${escapeHtml(sq)}</b></div>
          <div><span>Category</span><b>${escapeHtml(String(model))}</b></div>
        </div>`;
      return;
    }
    const name = ais.shipname || ais.name || "—";
    const mmsi = ais.mmsi || "—";
    const sog = ais.sog_kts != null ? `${ais.sog_kts} kt` : "—";
    const cog = ais.cog_deg != null ? `${ais.cog_deg}°` : "—";
    els.focusTraffic.innerHTML = `
      <div class="traffic-focus-head">
        <div class="traffic-callsign">${escapeHtml(String(name))}</div>
        <div class="traffic-icao">MMSI ${escapeHtml(String(mmsi))}</div>
      </div>
      <div class="traffic-stats">
        <div><span>SOG</span><b>${escapeHtml(sog)}</b></div>
        <div><span>COG</span><b>${escapeHtml(cog)}</b></div>
      </div>`;
  }

  function ensureTrafficMapTick() {
    const any = devices.some((d) => isTrafficDevice(d) && hasEmitterPosition(d));
    if (!any) {
      if (trafficMapTick) {
        clearInterval(trafficMapTick);
        trafficMapTick = null;
      }
      return;
    }
    if (trafficMapTick) return;
    trafficMapTick = setInterval(() => {
      if (!mapReady) return;
      const mapPane = $("#view-map");
      if (mapPane && mapPane.classList.contains("hidden")) return;
      if (!devices.some((d) => isTrafficDevice(d) && hasEmitterPosition(d))) {
        clearInterval(trafficMapTick);
        trafficMapTick = null;
        return;
      }
      refreshMapDevices();
    }, 1000);
  }

  function markerColor(d) {
    const sev = deviceSev(d);
    if (sev === "critical") return "#f25c54";
    if (sev === "high") return "#fb7185";
    const radio = (d.radio || "").toLowerCase();
    if (radio === "adsb") return "#38bdf8";
    if (radio === "ais") return "#2dd4bf";
    if (radio === "ble") return "#3b9eff";
    return "#c084fc";
  }

  function isSignalGeo(d) {
    const meta = d.metadata || {};
    const radio = (d.radio || "").toLowerCase();
    return meta.geo_source === "signal" || radio === "adsb" || radio === "ais" || meta.see_on_map;
  }

  /** True only when we have the emitter's own lat/lon (not the hunter pin). */
  function hasEmitterPosition(d) {
    if (!d) return false;
    const meta = d.metadata || {};
    const adsb = meta.adsb || {};
    const ais = meta.ais || {};
    if (adsb.lat != null && adsb.lon != null) return true;
    if (ais.lat != null && ais.lon != null) return true;
    const gps = d.gps || {};
    if ((gps.source === "adsb" || gps.source === "ais") && d.lat != null && d.lon != null) {
      return true;
    }
    if (meta.geo_source === "signal" && d.lat != null && d.lon != null) return true;
    return false;
  }

  function isTrafficDevice(d) {
    const radio = (d.radio || "").toLowerCase();
    return radio === "adsb" || radio === "ais" || !!(d.metadata || {}).adsb || !!(d.metadata || {}).ais;
  }

  function deviceLatLng(d) {
    // ADS-B/AIS: live emitter position only. Wardrive RF/BLE: first-seen hunter pin.
    if (isTrafficDevice(d)) {
      if (!hasEmitterPosition(d)) return null;
      const adsb = (d.metadata || {}).adsb || {};
      const ais = (d.metadata || {}).ais || {};
      const lat = adsb.lat ?? ais.lat ?? d.lat ?? d.first_lat;
      const lon = adsb.lon ?? ais.lon ?? d.lon ?? d.first_lon;
      if (lat == null || lon == null || Number.isNaN(Number(lat)) || Number.isNaN(Number(lon))) {
        return null;
      }
      return [Number(lat), Number(lon)];
    }
    let lat;
    let lon;
    if (isSignalGeo(d)) {
      lat = d.lat ?? d.first_lat ?? d.gps?.lat;
      lon = d.lon ?? d.first_lon ?? d.gps?.lon;
    } else {
      lat = d.first_lat ?? d.lat ?? d.gps?.lat;
      lon = d.first_lon ?? d.lon ?? d.gps?.lon;
    }
    if (lat == null || lon == null || Number.isNaN(Number(lat)) || Number.isNaN(Number(lon))) {
      return null;
    }
    return [Number(lat), Number(lon)];
  }

  /** Extrapolate ADS-B/AIS between HackRF listens using last speed + track. */
  function trafficDisplayLatLng(d) {
    const ll = deviceLatLng(d);
    if (!ll || !isTrafficDevice(d)) return ll;
    const adsb = aeroBlock(d) || {};
    const ais = marineBlock(d) || {};
    const speedKts = adsb.speed_kts ?? ais.sog_kts;
    const track = trafficHeading(d);
    if (speedKts == null || track == null || Number(speedKts) < 5) return ll;
    const lastTs =
      (d.last_seen_ts != null ? Number(d.last_seen_ts) * 1000 : NaN) ||
      Date.parse(d.last_seen || "") ||
      0;
    if (!lastTs) return ll;
    // Keep coasting up to 3 min while waiting for the next ADS-B listen
    const ageS = Math.min(180, Math.max(0, (Date.now() - lastTs) / 1000));
    if (ageS < 0.5) return ll;
    const distM = Number(speedKts) * 0.514444 * ageS;
    const rad = (Number(track) * Math.PI) / 180;
    const dLat = (distM * Math.cos(rad)) / 111320;
    const cosLat = Math.cos((ll[0] * Math.PI) / 180);
    const dLon = cosLat !== 0 ? (distM * Math.sin(rad)) / (111320 * cosLat) : 0;
    return [ll[0] + dLat, ll[1] + dLon];
  }

  function trafficPeers(d) {
    if (!d || !isTrafficDevice(d)) return [];
    const wantAds = !!(aeroBlock(d) || (d.radio || "").toLowerCase() === "adsb");
    return devices.filter((x) => {
      if (!hasEmitterPosition(x)) return false;
      const isAds = !!(aeroBlock(x) || (x.radio || "").toLowerCase() === "adsb");
      const isAis = !!(marineBlock(x) || (x.radio || "").toLowerCase() === "ais");
      return wantAds ? isAds : isAis;
    });
  }

  function trafficHeading(d) {
    const adsb = aeroBlock(d) || {};
    const ais = marineBlock(d) || {};
    const gps = d.gps || {};
    const raw =
      adsb.track_deg ??
      adsb.heading_deg ??
      ais.cog_deg ??
      ais.heading_deg ??
      gps.track_deg ??
      null;
    if (raw == null || Number.isNaN(Number(raw))) return null;
    // Normalize 0–360
    let deg = Number(raw) % 360;
    if (deg < 0) deg += 360;
    return deg;
  }

  function trafficMapIcon(d, color) {
    const radio = (d.radio || "").toLowerCase();
    const heading = trafficHeading(d);
    const isPlane = radio === "adsb" || !!(d.metadata || {}).adsb;
    const isShip = radio === "ais" || !!(d.metadata || {}).ais;

    if (isPlane) {
      // Nose-up triangle; CSS rotate(deg) with 0° = north (Leaflet / aviation)
      const rot = heading != null ? heading : 0;
      const unknown = heading == null ? " is-unknown-hdg" : "";
      return L.divIcon({
        className: "dev-marker traffic-marker",
        html: `<div class="ac-tri${unknown}" style="--mk:${color};transform:rotate(${rot}deg)" title="${
          heading != null ? `track ${Math.round(heading)}°` : "no heading"
        }">
          <svg viewBox="0 0 24 28" width="22" height="26" aria-hidden="true">
            <path d="M12 1.5 L22.5 26.5 L12 20.5 L1.5 26.5 Z" />
          </svg>
        </div>`,
        iconSize: [28, 28],
        iconAnchor: [14, 14],
        popupAnchor: [0, -14],
      });
    }

    if (isShip) {
      const rot = heading != null ? heading : 0;
      const unknown = heading == null ? " is-unknown-hdg" : "";
      return L.divIcon({
        className: "dev-marker traffic-marker",
        html: `<div class="ship-tri${unknown}" style="--mk:${color};transform:rotate(${rot}deg)" title="${
          heading != null ? `COG ${Math.round(heading)}°` : "no heading"
        }">
          <svg viewBox="0 0 24 28" width="20" height="24" aria-hidden="true">
            <path d="M12 2 L20 10 L20 24 L4 24 L4 10 Z" />
          </svg>
        </div>`,
        iconSize: [26, 28],
        iconAnchor: [13, 14],
        popupAnchor: [0, -14],
      });
    }

    const glyph = typeGlyph(d);
    return L.divIcon({
      className: "dev-marker",
      html: `<div class="dev-marker-inner" style="--mk:${color}">${glyph}</div>`,
      iconSize: [28, 28],
      iconAnchor: [14, 14],
      popupAnchor: [0, -12],
    });
  }

  function mapLayerKey(d) {
    const radio = (d.radio || "").toLowerCase();
    if (radio === "adsb" || !!(d.metadata || {}).adsb) return "adsb";
    if (radio === "ais" || !!(d.metadata || {}).ais) return "ais";
    if (radio === "ble") return "ble";
    return "rf";
  }

  function deviceQuality(d) {
    return ((d && d.metadata) || {}).quality || {};
  }

  function deviceQualityTier(d) {
    return String(deviceQuality(d).tier || "suspect");
  }

  function deviceEvidence(d) {
    const meta = (d && d.metadata) || {};
    const cap = String(meta.capability || "").toLowerCase();
    if (cap === "decode" || cap === "ble") return "decode";
    if ((meta.adsb || {}).icao || (meta.ais || {}).mmsi) return "decode";
    if ((meta.live_decode || {}).ok || ((meta.tpms_decode || {}).sensors || []).length) return "decode";
    if ((meta.fpv_decode || {}).ok) return "decode";
    if ((d.radio || "").toLowerCase() === "ble") return "decode";
    return "presence";
  }

  function passesQualityFilter(d, mode) {
    if (!mode) return true;
    const tier = deviceQualityTier(d);
    const fp = !!deviceQuality(d).fp_likely;
    if (mode === "hide_noise") return tier !== "noise" && !fp;
    if (mode === "likely") return tier === "likely" || tier === "confirmed";
    if (mode === "confirmed") return tier === "confirmed";
    if (mode === "noise") return tier === "noise" || fp;
    return true;
  }

  function passesMapFilter(d) {
    if (!d) return false;
    if (mapFilters.critical_only) {
      const sev = deviceSev(d);
      if (sev !== "critical" && sev !== "high" && sev !== "vulnerable") return false;
    }
    if (mapFilters.hide_noise) {
      const tier = deviceQualityTier(d);
      if (tier === "noise" || deviceQuality(d).fp_likely) return false;
    }
    if (mapFilters.decode_only && deviceEvidence(d) !== "decode") return false;
    return !!mapFilters[mapLayerKey(d)];
  }

  function persistMapFilters() {
    try {
      localStorage.setItem("rfhunter.mapFilters", JSON.stringify(mapFilters));
    } catch (_) {}
  }

  function syncMapFilterUi() {
    document.querySelectorAll("[data-map-filter]").forEach((btn) => {
      const key = btn.getAttribute("data-map-filter");
      btn.classList.toggle("on", !!mapFilters[key]);
      btn.setAttribute("aria-pressed", mapFilters[key] ? "true" : "false");
    });
    document.querySelectorAll("[data-map-preset]").forEach((btn) => {
      btn.classList.toggle("active", btn.getAttribute("data-map-preset") === mapFilterPreset);
    });
  }

  function applyMapFilterPreset(name) {
    mapFilterPreset = name || "";
    if (name === "all") {
      mapFilters = {
        ...MAP_FILTER_DEFAULTS,
        rf: true,
        ble: true,
        wifi: true,
        adsb: true,
        ais: true,
        hunter: true,
        trail: true,
        critical_only: false,
        hide_noise: true,
        decode_only: false,
      };
    } else if (name === "traffic") {
      mapFilters = {
        ...MAP_FILTER_DEFAULTS,
        rf: false,
        ble: false,
        wifi: false,
        adsb: true,
        ais: true,
        hunter: true,
        trail: false,
        critical_only: false,
        hide_noise: true,
        decode_only: true,
      };
    } else if (name === "wardrive") {
      mapFilters = {
        ...MAP_FILTER_DEFAULTS,
        rf: true,
        ble: true,
        wifi: true,
        adsb: false,
        ais: false,
        hunter: true,
        trail: true,
        critical_only: false,
        hide_noise: true,
        decode_only: false,
      };
    }
    persistMapFilters();
    syncMapFilterUi();
    refreshMapDevices();
    refreshMapWifi();
    applyMapChromeVisibility();
  }

  function ensureMapLayerVisibleFor(d) {
    if (!d) return;
    const key = mapLayerKey(d);
    if (!mapFilters[key]) {
      mapFilters[key] = true;
      mapFilterPreset = "";
      persistMapFilters();
      syncMapFilterUi();
    }
    if (mapFilters.critical_only) {
      const sev = deviceSev(d);
      if (sev !== "critical" && sev !== "high" && sev !== "vulnerable") {
        mapFilters.critical_only = false;
        mapFilterPreset = "";
        persistMapFilters();
        syncMapFilterUi();
      }
    }
  }

  function applyMapChromeVisibility() {
    if (!mapReady) return;
    if (hunterMarker) {
      if (mapFilters.hunter) {
        if (!map.hasLayer(hunterMarker)) hunterMarker.addTo(map);
      } else if (map.hasLayer(hunterMarker)) {
        map.removeLayer(hunterMarker);
      }
    }
    if (trailLine) {
      trailLine.setStyle({
        opacity: mapFilters.trail ? 0.75 : 0,
        weight: mapFilters.trail ? 3 : 0,
      });
    }
  }

  function bindMapFilters() {
    const root = $("#map-filters");
    if (!root || root.dataset.bound) return;
    root.dataset.bound = "1";
    root.querySelectorAll("[data-map-filter]").forEach((btn) => {
      btn.onclick = () => {
        const key = btn.getAttribute("data-map-filter");
        if (!key || !(key in mapFilters)) return;
        mapFilters[key] = !mapFilters[key];
        mapFilterPreset = "";
        persistMapFilters();
        syncMapFilterUi();
        refreshMapDevices();
        refreshMapWifi();
        applyMapChromeVisibility();
      };
    });
    root.querySelectorAll("[data-map-preset]").forEach((btn) => {
      btn.onclick = () => applyMapFilterPreset(btn.getAttribute("data-map-preset"));
    });
    syncMapFilterUi();
  }

  function refreshMapDevices() {
    if (!mapReady || !mapLayerGroup) return;
    const placed = [];
    let eligible = 0;
    devices.forEach((d) => {
      if (isTrafficDevice(d) && !hasEmitterPosition(d)) return;
      const trueLl = deviceLatLng(d);
      if (!trueLl) return;
      eligible += 1;
      if (!passesMapFilter(d)) return;
      const ll = trafficDisplayLatLng(d) || trueLl;
      placed.push({ d, ll, trueLl, key: d.key || "" });
    });
    const buckets = new Map();
    placed.forEach((p) => {
      const bk = geoBucketKey(p.trueLl || p.ll);
      if (!buckets.has(bk)) buckets.set(bk, []);
      buckets.get(bk).push(p);
    });
    buckets.forEach((group) => group.sort((a, b) => a.key.localeCompare(b.key)));

    const seen = new Set();
    let pins = 0;
    buckets.forEach((group) => {
      group.forEach((p, i) => {
        const { d, ll, trueLl, key } = p;
        if (!key) return;
        seen.add(key);
        pins += 1;
        const displayLl = spiderfyLatLng(ll, i, group.length);
        const color = markerColor(d);
        const html = trafficPopupHtml(d, trueLl || ll);
        const icon = trafficMapIcon(d, color);
        if (deviceMarkers[key]) {
          deviceMarkers[key].setLatLng(displayLl);
          deviceMarkers[key].setIcon(icon);
          deviceMarkers[key].setPopupContent(html);
        } else {
          const m = L.marker(displayLl, { icon }).addTo(mapLayerGroup);
          m.bindPopup(html);
          m.on("click", () => {
            focusedKey = key;
            renderFocus(devicesByKey[key]);
            renderDeviceList();
          });
          deviceMarkers[key] = m;
        }
      });
    });
    Object.keys(deviceMarkers).forEach((k) => {
      if (!seen.has(k)) {
        mapLayerGroup.removeLayer(deviceMarkers[k]);
        delete deviceMarkers[k];
      }
    });
    const wifiShown = mapFilters.wifi ? wifiAps.length : 0;
    if (els.mapPinCount) {
      els.mapPinCount.textContent =
        pins === eligible
          ? `${pins} pins · ${wifiShown} AP`
          : `${pins}/${eligible} pins · ${wifiShown} AP`;
    }
    applyMapChromeVisibility();
  }

  function seeOnMap(d) {
    if (!d) return;
    const ll = trafficDisplayLatLng(d) || deviceLatLng(d);
    if (!ll) {
      alert(
        isTrafficDevice(d)
          ? "No aircraft/vessel position yet.\nWait for an ADS-B CPR / AIS position frame."
          : "No coordinates yet.\nADS-B needs a decoded position frame; other devices need a GPS fix while scanning."
      );
      return;
    }
    ensureMapLayerVisibleFor(d);
    const mapTab = document.querySelector('.view-tab[data-view="map"]');
    if (mapTab) mapTab.click();
    ensureMap();
    const key = d.key || "";
    setTimeout(() => {
      refreshMapDevices();
      if (isTrafficDevice(d)) {
        const peers = trafficPeers(d).filter(passesMapFilter);
        const pts = peers
          .map((x) => trafficDisplayLatLng(x) || deviceLatLng(x))
          .filter(Boolean);
        if (pts.length >= 2) {
          map.fitBounds(L.latLngBounds(pts).pad(0.35), { maxZoom: 11, animate: true });
        } else {
          map.setView(ll, 10);
        }
      } else {
        map.setView(ll, 16);
      }
      if (deviceMarkers[key]) deviceMarkers[key].openPopup();
      ensureTrafficMapTick();
    }, 120);
  }

  function refreshMapWifi() {
    if (!mapReady || !wifiLayerGroup) return;
    if (!mapFilters.wifi) {
      Object.keys(wifiMarkers).forEach((k) => {
        wifiLayerGroup.removeLayer(wifiMarkers[k]);
        delete wifiMarkers[k];
      });
      return;
    }
    const placed = [];
    wifiAps.forEach((ap) => {
      const lat = ap.first_lat ?? ap.lat;
      const lon = ap.first_lon ?? ap.lon;
      if (lat == null || lon == null) return;
      const bssid = ap.bssid || "";
      if (!bssid) return;
      placed.push({ ap, bssid, ll: [Number(lat), Number(lon)] });
    });
    const buckets = new Map();
    placed.forEach((p) => {
      const bk = geoBucketKey(p.ll);
      if (!buckets.has(bk)) buckets.set(bk, []);
      buckets.get(bk).push(p);
    });
    buckets.forEach((group) => group.sort((a, b) => a.bssid.localeCompare(b.bssid)));

    const seen = new Set();
    buckets.forEach((group) => {
      group.forEach((p, i) => {
        const { ap, bssid, ll } = p;
        seen.add(bssid);
        const displayLl = spiderfyLatLng(ll, i, group.length);
        const ssid = ap.ssid || "(hidden)";
        const html = `<div class="pop-title">Wi‑Fi · ${escapeHtml(ssid)}</div>
          <div class="pop-meta">${escapeHtml(bssid)}</div>
          <div class="pop-meta">${escapeHtml(ap.vendor || "—")} · ch ${escapeHtml(String(ap.channel || "?"))} · ${escapeHtml(String(ap.signal_dbm ?? "—"))} dBm · ${escapeHtml(ap.security || "")}</div>`;
        if (wifiMarkers[bssid]) {
          wifiMarkers[bssid].setLatLng(displayLl);
          wifiMarkers[bssid].setPopupContent(html);
        } else {
          const m = L.circleMarker(displayLl, {
            radius: 5,
            color: "#34d399",
            fillColor: "#34d399",
            fillOpacity: 0.55,
            weight: 1,
          }).addTo(wifiLayerGroup);
          m.bindPopup(html);
          wifiMarkers[bssid] = m;
        }
      });
    });
    Object.keys(wifiMarkers).forEach((k) => {
      if (!seen.has(k)) {
        wifiLayerGroup.removeLayer(wifiMarkers[k]);
        delete wifiMarkers[k];
      }
    });
  }

  function updateHunterMarker() {
    if (!mapReady || !gpsFix) return;
    const ll = [Number(gpsFix.lat), Number(gpsFix.lon)];
    if (!hunterMarker) {
      const icon = L.divIcon({
        className: "",
        html: '<div class="hunter-pulse"></div>',
        iconSize: [18, 18],
        iconAnchor: [9, 9],
      });
      hunterMarker = L.marker(ll, { icon, zIndexOffset: 1000 });
      if (mapFilters.hunter) hunterMarker.addTo(map);
      hunterMarker.bindPopup('<div class="pop-title">RF Hunter</div><div class="pop-meta">Live GPS</div>');
    } else {
      hunterMarker.setLatLng(ll);
      applyMapChromeVisibility();
    }
    if (mapFollow && mapFilters.hunter) {
      map.panTo(ll, { animate: true, duration: 0.4 });
    }
  }

  function redrawTrail() {
    if (!mapReady || !trailLine) return;
    const pts = gpsTrail
      .filter((p) => p.lat != null && p.lon != null)
      .map((p) => [Number(p.lat), Number(p.lon)]);
    trailLine.setLatLngs(pts);
    applyMapChromeVisibility();
  }

  function fitMapAll() {
    if (!mapReady) return;
    const pts = [];
    if (gpsFix && mapFilters.hunter) pts.push([Number(gpsFix.lat), Number(gpsFix.lon)]);
    devices.forEach((d) => {
      if (!passesMapFilter(d)) return;
      if (isTrafficDevice(d) && !hasEmitterPosition(d)) return;
      const ll = trafficDisplayLatLng(d) || deviceLatLng(d);
      if (ll) pts.push(ll);
    });
    if (mapFilters.trail) {
      gpsTrail.forEach((p) => {
        if (p.lat != null) pts.push([Number(p.lat), Number(p.lon)]);
      });
    }
    if (mapFilters.wifi) {
      wifiAps.forEach((ap) => {
        const lat = ap.first_lat ?? ap.lat;
        const lon = ap.first_lon ?? ap.lon;
        if (lat != null) pts.push([Number(lat), Number(lon)]);
      });
    }
    if (pts.length) map.fitBounds(pts, { padding: [36, 36], maxZoom: 18 });
  }

  async function loadGpsTrail() {
    try {
      const res = await api("/api/gps/trail?limit=800");
      if (res.fix) gpsFix = res.fix;
      gpsTrail = res.trail || [];
      updateMapFixLabel();
      redrawTrail();
      updateHunterMarker();
    } catch (_) {}
  }

  async function loadCatalog() {
    catalog = await api("/api/catalog");
    wowTypeIds = catalog.wow_type_ids || [
      "tuya_ble", "ble_sensors", "smart_tv_bt", "garage_433", "garage_315", "alarm_869",
    ];
    wowBleTypeIds = catalog.wow_ble_type_ids || [
      "tuya_ble", "ble_sensors", "smart_tv_bt",
    ];
    renderTabs();
    renderGrid();
    updateSelectedCount();
  }

  function renderTabs() {
    els.tabs.innerHTML = "";
    const all = document.createElement("button");
    all.className = "tab active";
    all.textContent = "All";
    all.onclick = () => filterCategory("all", all);
    els.tabs.appendChild(all);
    catalog.categories.forEach((c) => {
      const t = document.createElement("button");
      t.className = "tab";
      t.innerHTML = `${typeIconHtml(c, "tab-glyph")} ${escapeHtml(c.label)}`;
      t.onclick = () => filterCategory(c.id, t);
      els.tabs.appendChild(t);
    });
  }

  function filterCategory(id, btn) {
    activeCategory = id;
    document.querySelectorAll(".tab").forEach((t) => t.classList.remove("active"));
    btn.classList.add("active");
    renderGrid();
    updateSelectedCount();
  }

  function renderGrid() {
    els.grid.innerHTML = "";
    visibleTypes().forEach((dt) => {
      const band = dt.bands?.[0];
      const freqLabel =
        dt.radio === "ble"
          ? "BLE"
          : band
            ? `${band.freq_min_mhz}–${band.freq_max_mhz} MHz`
            : "RF";
      const cap = dt.capability || (dt.metadata || {}).capability || "presence";
      const card = document.createElement("div");
      card.className = "device-card" + (selected.has(dt.id) ? " selected" : "");
      card.innerHTML = `
        <div class="check">${selected.has(dt.id) ? "✓" : ""}</div>
        <div class="type-icon-lg mono-ico">${typeGlyph(dt)}</div>
        <div>
          <h3>${escapeHtml(dt.name)}${(dt.wow && dt.wow.tier === "wow") ? ' <span class="wow-pill">WOW</span>' : ""}</h3>
          <p>${escapeHtml(dt.description || "")}</p>
          <span class="tag">${dt.radio.toUpperCase()} · ${freqLabel}</span>
          <span class="cap-pill cap-${escapeHtml(cap)}">${escapeHtml(cap)}</span>
        </div>`;
      card.onclick = () => {
        if (selected.has(dt.id)) selected.delete(dt.id);
        else selected.add(dt.id);
        updateSelectedCount();
        renderGrid();
      };
      els.grid.appendChild(card);
    });
  }

  function setDevices(list) {
    devices = list || [];
    devicesByKey = {};
    devices.forEach((d) => {
      const k = d.key || (d.mac ? `ble:${String(d.mac).toUpperCase()}` : `rf:${d.freq_mhz}`);
      devicesByKey[k] = d;
    });
    refreshTypeFilterOptions();
    renderDeviceList();
    refreshStatsFromDevices();
    refreshTpmsStatsHint();
    refreshMapDevices();
    ensureTrafficMapTick();
    renderLiveFindings();
    maybeTriggerDemoVuln();
    if (focusedKey && devicesByKey[focusedKey]) renderFocus(devicesByKey[focusedKey]);
  }

  function collectLiveFindings() {
    const leaks = [];
    const writables = [];
    const criticals = [];
    for (const d of devices) {
      const risk = d.risk || {};
      const leak =
        detectMacInMfg(d) ||
        (risk.findings || []).some((f) =>
          /manufacturer_data|BD_ADDR embedded/i.test(f.finding || "")
        );
      if (leak) leaks.push(d);
      const wcount = gattWriteStats(risk.gatt_snapshot?.services || []).writable;
      const wFinding = (risk.findings || []).some((f) => /writable GATT/i.test(f.finding || ""));
      if (wcount || wFinding) writables.push(d);
      if (deviceSev(d) === "critical") criticals.push(d);
    }
    return { leaks, writables, criticals };
  }

  function renderLiveFindings() {
    if (!els.dashFindings) return;
    const { leaks, writables, criticals } = collectLiveFindings();
    const top = [];
    const seen = new Set();
    for (const d of [...criticals, ...writables, ...leaks]) {
      const k = d.key;
      if (!k || seen.has(k)) continue;
      seen.add(k);
      top.push(d);
      if (top.length >= 5) break;
    }
    const pills = `
      <div class="findings-pills">
        <span class="findings-pill leak">${leaks.length} identity leak(s)</span>
        <span class="findings-pill write">${writables.length} writable GATT</span>
        <span class="findings-pill crit">${criticals.length} critical</span>
      </div>`;
    const list = top.length
      ? `<ul class="findings-top">${top
          .map((d) => {
            const bits = [];
            if (detectMacInMfg(d)) bits.push("MAC-in-mfg");
            const w = gattWriteStats(d.risk?.gatt_snapshot?.services || []).writable;
            if (w) bits.push(`${w} writable`);
            bits.push(deviceSev(d));
            return `<li data-key="${escapeHtml(d.key)}">
              <strong>${escapeHtml(d.name || d.device_type_name || d.mac || d.key)}</strong>
              <span class="hint">${escapeHtml(bits.join(" · "))}</span>
            </li>`;
          })
          .join("")}</ul>`
      : `<div class="hint">Run Demo Mode or Quick triage to populate.</div>`;
    els.dashFindings.innerHTML = pills + list;
    els.dashFindings.querySelectorAll("li[data-key]").forEach((li) => {
      li.onclick = () => {
        const key = li.getAttribute("data-key");
        if (!key || !devicesByKey[key]) return;
        focusedKey = key;
        renderFocus(devicesByKey[key]);
        renderDeviceList();
        document.querySelector('.view-tab[data-view="devices"]')?.click();
      };
    });
  }

  function maybeTriggerDemoVuln() {
    if (!demoModeActive || demoVulnTriggered || vulnRunning) return;
    if (devices.length < 5) return;
    demoVulnTriggered = true;
    log("Demo Mode: auto Quick triage…");
    startVuln("quick").then(() => {
      // counts refresh as vuln findings arrive; log snapshot after kickoff
      setTimeout(() => {
        const { leaks, criticals } = collectLiveFindings();
        log(`Demo: ${leaks.length} identity leaks · ${criticals.length} critical`);
      }, 800);
    }).catch(() => {});
  }

  function upsertDevice(d) {
    const k = d.key || (d.mac ? `ble:${String(d.mac).toUpperCase()}` : null);
    if (!k) return;
    devicesByKey[k] = d;
    const idx = devices.findIndex((x) => (x.key || "") === k);
    if (idx >= 0) devices[idx] = d;
    else devices.push(d);
    devices.sort((a, b) => {
      const sa = a.stale ? 1 : 0;
      const sb = b.stale ? 1 : 0;
      if (sa !== sb) return sa - sb;
      return (b.signal_level || 0) - (a.signal_level || 0);
    });
    setDevices(devices);
  }

  function refreshTypeFilterOptions() {
    const types = [...new Set(devices.map((d) => d.device_type_name || d.device_type_id).filter(Boolean))].sort();
    const cur = filters.type;
    els.filterType.innerHTML =
      `<option value="">All types</option>` +
      types.map((t) => `<option value="${escapeHtml(t)}">${escapeHtml(t)}</option>`).join("");
    els.filterType.value = cur;
  }

  function lastSeenTs(d) {
    if (d.last_seen_ts) return Number(d.last_seen_ts);
    if (d.last_seen) {
      const t = Date.parse(d.last_seen);
      return Number.isNaN(t) ? 0 : t / 1000;
    }
    return 0;
  }

  function sevRank(d) {
    const order = { critical: 4, high: 3, medium: 2, low: 1, unknown: 0, suspected: 2 };
    return order[deviceSev(d)] || 0;
  }

  function deviceWow(d) {
    if (d && d.wow) return d.wow;
    const profile = ((d && d.metadata) || {}).attack_profile || "";
    const fallback = {
      tuya_ble: 95, ble_generic: 80, bt_av: 70, ism_433: 88, ism_315: 85, alarm_869: 65,
    };
    const score = fallback[profile] || 20;
    return {
      score,
      tier: score >= 70 ? "wow" : score >= 45 ? "solid" : "niche",
      headline: profile || "generic",
      demo: "",
      profile,
    };
  }

  function sortDevices(list) {
    const arr = list.slice();
    const cmp = {
      wow: (a, b) => {
        const wa = deviceWow(a).score || 0;
        const wb = deviceWow(b).score || 0;
        if (wb !== wa) return wb - wa;
        const sa = a.stale ? 1 : 0;
        const sb = b.stale ? 1 : 0;
        if (sa !== sb) return sa - sb;
        return (b.signal_level || 0) - (a.signal_level || 0);
      },
      smart: (a, b) => {
        const sa = a.stale ? 1 : 0;
        const sb = b.stale ? 1 : 0;
        if (sa !== sb) return sa - sb;
        const cov = (b.signal_level || 0) - (a.signal_level || 0);
        if (cov) return cov;
        return lastSeenTs(b) - lastSeenTs(a);
      },
      coverage: (a, b) => {
        const sa = a.stale ? 1 : 0;
        const sb = b.stale ? 1 : 0;
        if (sa !== sb) return sa - sb;
        return (b.signal_level || 0) - (a.signal_level || 0);
      },
      newest: (a, b) => lastSeenTs(b) - lastSeenTs(a),
      active: (a, b) => {
        const sa = a.stale ? 1 : 0;
        const sb = b.stale ? 1 : 0;
        if (sa !== sb) return sa - sb;
        return lastSeenTs(b) - lastSeenTs(a);
      },
      hits: (a, b) => (b.hit_count || 0) - (a.hit_count || 0),
      severity: (a, b) => sevRank(b) - sevRank(a) || (b.signal_level || 0) - (a.signal_level || 0),
      name: (a, b) =>
        String(a.name || a.device_type_name || "").localeCompare(
          String(b.name || b.device_type_name || "")
        ),
    };
    arr.sort(cmp[sortBy] || cmp.wow);
    return arr;
  }

  function wifiToDevice(ap) {
    const bssid = ap.bssid || "";
    const ssid = (ap.ssid || "").trim();
    const rssi = ap.signal_dbm;
    let level = 1;
    if (rssi != null) {
      if (rssi >= -45) level = 10;
      else if (rssi >= -55) level = 8;
      else if (rssi >= -65) level = 6;
      else if (rssi >= -75) level = 4;
      else if (rssi >= -85) level = 2;
    }
    const sec = ap.security || "unknown";
    return {
      key: ap.key || `wifi:${bssid}`,
      id: bssid.replace(/:/g, "").slice(-8).toLowerCase(),
      radio: "wifi",
      name: ssid || "(hidden Wi‑Fi)",
      device_type_id: "wifi_ap",
      device_type_name: "Wi‑Fi AP",
      mac: bssid,
      vendor: ap.vendor || null,
      family: "Wi‑Fi",
      rssi_dbm: rssi,
      power_dbm: rssi,
      freq_mhz: ap.freq_mhz,
      signal_level: level,
      hit_count: ap.hit_count || 1,
      first_seen: ap.first_seen,
      last_seen: ap.last_seen,
      last_seen_ts: ap.last_seen_ts,
      lat: ap.lat,
      lon: ap.lon,
      first_lat: ap.first_lat,
      first_lon: ap.first_lon,
      stale: !!ap.stale,
      risk_status: sec.toLowerCase().includes("open") ? "medium" : "unknown",
      metadata: {
        capability: "presence",
        attack_profile: "wifi_ap",
        channel: ap.channel,
        security: sec,
        security_family: ap.security_family || null,
        wifi_ies: ap.wifi_ies || null,
        wps: ap.wps,
        pmf: ap.pmf,
        hidden_ssid: ap.hidden_ssid,
        quality: {
          tier: "confirmed",
          score: 72,
          fp_likely: false,
          summary: `${sec} · ch ${ap.channel ?? "?"} · ${rssi ?? "—"} dBm`,
        },
      },
      wow: {
        score: sec.toLowerCase().includes("open") ? 70 : 42,
        tier: sec.toLowerCase().includes("open") ? "wow" : "solid",
        headline: ssid ? `Wi‑Fi · ${ssid}` : "Wi‑Fi AP (hidden)",
        demo: "Map + security / channel / RSSI",
        profile: "wifi_ap",
      },
    };
  }

  function isWifiDevice(d) {
    return (d.radio || "").toLowerCase() === "wifi" || d.device_type_id === "wifi_ap";
  }

  function wifiListWanted() {
    // Keep RF/BLE lists clean — Wi‑Fi APs only when explicitly filtered to Wi‑Fi.
    const radio = (filters.radio || "").toLowerCase();
    if (radio === "wifi") return true;
    if (radio && radio !== "wifi") return false;
    const t = filters.type || "";
    if (t === "Wi‑Fi AP" || t === "wifi_ap" || t.toLowerCase().includes("wi-fi") || t.toLowerCase().includes("wifi")) {
      return true;
    }
    // Text for wifi/ssid explicitly
    const q = (filters.text || "").trim().toLowerCase();
    if (q === "wifi" || q === "wi-fi" || q === "wi‑fi" || q.startsWith("wifi:")) return true;
    return false;
  }

  function allDisplayDevices() {
    const wifiDevs = (wifiAps || []).map(wifiToDevice);
    // Keep devicesByKey in sync so focus / triage work when Wi‑Fi rows are shown
    wifiDevs.forEach((d) => {
      if (d.key) devicesByKey[d.key] = d;
    });
    if (!wifiListWanted()) return devices.slice();
    return devices.concat(wifiDevs);
  }

  function filteredDevices() {
    const q = filters.text.trim().toLowerCase();
    const filtered = allDisplayDevices().filter((d) => {
      // Double-check: never mix Wi‑Fi into RF type/radio searches
      if (isWifiDevice(d) && !wifiListWanted()) return false;
      // Scope to types actually requested on last Start (avoids leftover garage after "aviation")
      if (
        scopeToLastScan &&
        lastScanTypeIds &&
        lastScanTypeIds.size &&
        !isWifiDevice(d) &&
        !lastScanTypeIds.has(d.device_type_id)
      ) {
        return false;
      }
      if (filters.type && (d.device_type_name || d.device_type_id) !== filters.type) return false;
      if (filters.radio && (d.radio || "").toLowerCase() !== filters.radio) return false;
      if (filters.wow === "wow" && deviceWow(d).tier !== "wow") return false;
      if (filters.wow === "solid" && !["wow", "solid"].includes(deviceWow(d).tier)) return false;
      if (!passesQualityFilter(d, filters.quality)) return false;
      if (filters.evidence && deviceEvidence(d) !== filters.evidence) return false;
      if (filters.sev) {
        const sev = deviceSev(d);
        if (filters.sev === "unknown") {
          if (!d.risk && (!d.risk_status || d.risk_status === "unknown" || d.risk_status === "suspected")) {
            /* keep */
          } else if (sev !== "unknown") {
            return false;
          }
        } else if (sev !== filters.sev) {
          return false;
        }
      }
      if (q) {
        const hay = [
          d.name,
          d.device_type_name,
          d.mac,
          d.freq_mhz,
          d.key,
          d.vendor,
          d.family,
          d.model_guess,
          (d.metadata || {}).attack_profile,
          (d.metadata || {}).security,
          (d.metadata || {}).channel,
          ((d.metadata || {}).fingerprint || {}).vendor,
          ((d.metadata || {}).fingerprint || {}).family,
          (deviceQuality(d).summary || ""),
          deviceQualityTier(d),
        ]
          .join(" ")
          .toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });
    return sortDevices(filtered);
  }

  function normalizeLayout(mode) {
    if (mode === "rows") return "list";
    if (mode === "table" || mode === "list" || mode === "cards") return mode;
    return "cards";
  }

  function syncLayoutSwitch() {
    const root = els.layoutMode;
    if (!root) return;
    root.querySelectorAll(".layout-btn").forEach((btn) => {
      btn.classList.toggle("active", btn.dataset.layout === layoutMode);
    });
  }

  function deviceBadgesHtml(d) {
    const w = deviceWow(d);
    const meta = d.metadata || {};
    const code = (meta.code_class || {}).class;
    const liveOk = (meta.live_decode || {}).ok;
    const tpmsN = ((meta.tpms_decode || {}).sensors || []).length;
    const q = deviceQuality(d);
    const qt = q.tier || "";
    return [
      w.tier === "wow" ? '<span class="wow-pill">WOW</span>' : "",
      qt
        ? `<span class="q-pill q-${escapeHtml(qt)}" title="${escapeHtml(q.summary || qt)}">${escapeHtml(qt)}</span>`
        : "",
      q.fp_likely ? '<span class="q-pill q-fp" title="Likely false positive">FP?</span>' : "",
      liveOk || tpmsN ? '<span class="cap-pill cap-decode">decoded</span>' : "",
      deviceEvidence(d) === "presence" && !liveOk
        ? '<span class="cap-pill cap-presence">presence</span>'
        : "",
      code
        ? `<span class="cap-pill cap-${code.includes("roll") ? "presence" : "decode"}">${escapeHtml(code)}</span>`
        : "",
    ].join(" ");
  }

  function pruneTriageSelection() {
    for (const k of [...triageSelected]) {
      if (!devicesByKey[k]) triageSelected.delete(k);
    }
  }

  function updateTriageUi() {
    pruneTriageSelection();
    const n = triageSelected.size;
    const label = n
      ? `⚡ Quick triage (${n})`
      : "⚡ Quick triage (all)";
    const labelFull = n
      ? `🔬 Full dive (${n})`
      : "🔬 Full dive (all)";
    if (els.btnVulnQuick) els.btnVulnQuick.textContent = label;
    if (els.btnVulnFull) els.btnVulnFull.textContent = labelFull;
    if (els.triageSelCount) {
      els.triageSelCount.textContent = n
        ? `${n} selected for triage`
        : "0 selected — triage runs on all";
    }
    if (els.triageSelHint) {
      els.triageSelHint.textContent = n
        ? `Triage selection: ${n} device(s)`
        : "Triage selection: none (all devices)";
    }
    if (els.vulnHint) {
      els.vulnHint.textContent = n
        ? `Will assess the ${n} ticked device(s) only.`
        : "Tick devices in cards / list / table to focus triage, or leave empty for all.";
    }
    if (els.chkTriageVisible) {
      const visible = filteredDevices();
      const keys = visible.map((d) => d.key).filter(Boolean);
      const allOn = keys.length > 0 && keys.every((k) => triageSelected.has(k));
      const someOn = keys.some((k) => triageSelected.has(k));
      els.chkTriageVisible.checked = allOn;
      els.chkTriageVisible.indeterminate = someOn && !allOn;
    }
  }

  function toggleTriageKey(key, on) {
    if (!key) return;
    if (on) triageSelected.add(key);
    else triageSelected.delete(key);
    updateTriageUi();
  }

  function triageCheckboxHtml(key) {
    const checked = triageSelected.has(key) ? " checked" : "";
    return `<label class="triage-pick" title="Select for triage" data-triage-wrap="${escapeHtml(key)}">
      <input type="checkbox" class="triage-cb" data-triage-key="${escapeHtml(key)}"${checked} />
    </label>`;
  }

  function wireTriageCheckboxes(root) {
    root.querySelectorAll(".triage-cb").forEach((cb) => {
      cb.onclick = (ev) => ev.stopPropagation();
      cb.onchange = (ev) => {
        ev.stopPropagation();
        toggleTriageKey(cb.dataset.triageKey, cb.checked);
        // refresh selected class without full re-render if possible
        const row = cb.closest("[data-key]");
        if (row) row.classList.toggle("triage-selected", cb.checked);
      };
    });
  }

  function renderDeviceList() {
    const list = filteredDevices();
    els.count.textContent = String(list.length);
    const wifiN = (wifiAps || []).length;
    const wifiInList = list.filter(isWifiDevice).length;
    els.trackCount.textContent =
      wifiN > 0
        ? wifiInList
          ? `${devices.length} RF/BLE · ${wifiInList} Wi‑Fi`
          : `${devices.length} devices · ${wifiN} Wi‑Fi (filter Radio→Wi‑Fi)`
        : `${devices.length} devices`;
    layoutMode = normalizeLayout(layoutMode);

    els.results.classList.toggle("device-cards", layoutMode === "cards");
    els.results.classList.toggle("device-list", layoutMode === "list");
    els.results.classList.toggle("device-rows", layoutMode === "list");
    els.results.classList.toggle("device-table", layoutMode === "table");
    syncLayoutSwitch();
    updateTriageUi();

    if (!list.length) {
      els.results.innerHTML = `
        <div class="empty-state" style="grid-column:1/-1">
          <p>${devices.length ? "No matches for filters." : "No devices yet."}</p>
          <p class="hint">${devices.length ? "Clear filters or keep scanning." : "Select types and start wardrive."}</p>
        </div>`;
      return;
    }

    if (layoutMode === "table") {
      const th = (key, label) => {
        const sorted = sortBy === key ? " sorted" : "";
        const ind = sortBy === key ? "▾" : "▴";
        return `<th class="${sorted}" data-sort="${key}">${label}<span class="sort-ind">${ind}</span></th>`;
      };
      els.results.innerHTML = `
        <table class="devices-table">
          <thead>
            <tr>
              <th class="col-triage" title="Triage">☑</th>
              ${th("name", "Name")}
              <th>Vendor</th>
              <th>Loc</th>
              <th>Radio</th>
              <th>Type</th>
              ${th("severity", "Sev")}
              ${th("coverage", "Signal")}
              ${th("hits", "Hits")}
              ${th("wow", "Tier")}
            </tr>
          </thead>
          <tbody>
            ${list
              .map((d) => {
                const key = d.key || "";
                const level = d.signal_level || 0;
                const pct = level * 10;
                const risk = deviceSev(d);
                const name = d.name || d.device_type_name || "?";
                const live = scanRunning && !d.stale;
                const dim = scanRunning && d.stale;
                const w = deviceWow(d);
                const vendor = deviceVendor(d) || "—";
                const family = deviceFamily(d);
                const sel = triageSelected.has(key) ? " triage-selected" : "";
                return `<tr class="${focusedKey === key ? "active" : ""}${dim ? " stale" : ""}${live ? " live-pulse" : ""}${sel}" data-key="${escapeHtml(key)}">
                  <td class="col-triage">${triageCheckboxHtml(key)}</td>
                  <td class="col-name">${typeIconHtml(d)} <span class="name-text">${escapeHtml(name)}</span> ${deviceBadgesHtml(d)}</td>
                  <td class="col-vendor" title="${escapeHtml(family)}">${escapeHtml(vendor)}</td>
                  <td class="col-loc">${escapeHtml(locText(d))}</td>
                  <td><span class="radio-tag">${escapeHtml((d.radio || "?").toUpperCase())}</span></td>
                  <td>${escapeHtml(d.device_type_name || d.device_type_id || "—")}</td>
                  <td><span class="risk-pill risk-${escapeHtml(risk)}">${escapeHtml(risk)}</span></td>
                  <td class="col-signal">
                    <div class="db-label">${escapeHtml(strengthText(d))}</div>
                    <div class="sig-bar"><div class="sig-fill ${levelClass(level)}" style="width:${pct}%"></div></div>
                  </td>
                  <td class="col-hits">×${d.hit_count || 1}</td>
                  <td>${w.tier === "wow" ? '<span class="wow-pill">WOW</span>' : escapeHtml(w.tier || "—")}</td>
                </tr>`;
              })
              .join("")}
          </tbody>
        </table>`;
      els.results.querySelectorAll("thead th[data-sort]").forEach((thEl) => {
        thEl.onclick = (ev) => {
          ev.stopPropagation();
          sortBy = thEl.dataset.sort || "wow";
          if (els.sortBy) els.sortBy.value = sortBy;
          try {
            localStorage.setItem("rfh_sort", sortBy);
          } catch (_) {}
          renderDeviceList();
        };
      });
    } else if (layoutMode === "list") {
      els.results.innerHTML = list
        .map((d) => {
          const key = d.key || "";
          const level = d.signal_level || 0;
          const pct = level * 10;
          const risk = deviceSev(d);
          const name = d.name || d.device_type_name || "?";
          const live = scanRunning && !d.stale;
          const dim = scanRunning && d.stale;
          const sel = triageSelected.has(key) ? " triage-selected" : "";
          return `
          <article class="live-row${focusedKey === key ? " active" : ""}${dim ? " stale" : ""}${live ? " live-pulse" : ""}${sel}" data-key="${escapeHtml(key)}">
            ${triageCheckboxHtml(key)}
            <div>
              <div class="name">${typeIconHtml(d)} ${escapeHtml(name)} ${deviceBadgesHtml(d)}</div>
              <div class="sub">${escapeHtml(deviceVendor(d) || "—")}${deviceFamily(d) ? " · " + escapeHtml(deviceFamily(d)) : ""}${deviceModel(d) ? " · " + escapeHtml(deviceModel(d)) : ""} · ${escapeHtml(locText(d))}</div>
              <div class="sub mono-line">${[
                d.freq_mhz != null ? `${Number(d.freq_mhz).toFixed(1)} MHz` : null,
                d.rssi_dbm != null ? `${d.rssi_dbm} dBm` : (d.power_dbm != null ? `${d.power_dbm} dBm` : null),
                d.mac ? String(d.mac) : null,
                (d.wifi_nearby || []).length ? `${(d.wifi_nearby || []).length} Wi‑Fi` : null,
              ].filter(Boolean).map(escapeHtml).join(" · ")}</div>
            </div>
            <div class="row-signal">
              <div class="db-label">${escapeHtml(strengthText(d))}</div>
              <div class="sig-bar"><div class="sig-fill ${levelClass(level)}" style="width:${pct}%"></div></div>
            </div>
            <span class="radio-tag">${escapeHtml((d.radio || "?").toUpperCase())}</span>
            <span class="risk-pill risk-${escapeHtml(risk)}">${escapeHtml(risk)}</span>
            <div class="row-meta">
              <div class="sub">${escapeHtml(d.device_type_name || "")}</div>
              <div class="hits">×${d.hit_count || 1}</div>
            </div>
          </article>`;
        })
        .join("");
    } else {
      els.results.innerHTML = list
        .map((d) => {
          const key = d.key || "";
          const level = d.signal_level || 0;
          const pct = level * 10;
          const risk = deviceSev(d);
          const name = d.name || d.device_type_name || "?";
          const live = scanRunning && !d.stale;
          const dim = scanRunning && d.stale;
          const w = deviceWow(d);
          const wowCls = w.tier === "wow" ? " wow-tier" : "";
          const wifiN = (d.wifi_nearby || (d.metadata || {}).wifi_nearby || []).length;
          const sel = triageSelected.has(key) ? " triage-selected" : "";
          return `
          <article class="live-card${focusedKey === key ? " active" : ""}${dim ? " stale" : ""}${live ? " live-pulse" : ""}${wowCls}${sel}" data-key="${escapeHtml(key)}">
            <div class="card-top">
              ${triageCheckboxHtml(key)}
              <div class="name">${typeIconHtml(d)} ${escapeHtml(name)} ${deviceBadgesHtml(d)}${wifiN ? ` <span class="cap-pill cap-wifi">${wifiN}AP</span>` : ""}</div>
            </div>
            <div class="sub">${escapeHtml(locText(d))}</div>
            ${deviceVendor(d) ? `<div class="sub vendor-line">${escapeHtml(deviceVendor(d))}${deviceFamily(d) ? " · " + escapeHtml(deviceFamily(d)) : ""}${deviceModel(d) ? " · " + escapeHtml(deviceModel(d)) : ""}</div>` : ""}
            <div class="sub mono-line">${[
              d.freq_mhz != null ? `${Number(d.freq_mhz).toFixed(1)} MHz` : null,
              d.rssi_dbm != null ? `${d.rssi_dbm} dBm` : null,
              d.mac ? String(d.mac) : null,
            ].filter(Boolean).map(escapeHtml).join(" · ") || "—"}</div>
            <div class="sig-bar"><div class="sig-fill ${levelClass(level)}" style="width:${pct}%"></div></div>
            <div class="db-label">${escapeHtml(strengthText(d))}</div>
            <div class="card-foot">
              <span class="radio-tag">${escapeHtml((d.radio || "?").toUpperCase())}</span>
              <span class="risk-pill risk-${escapeHtml(risk)}">${escapeHtml(risk)}</span>
              <span class="hits">×${d.hit_count || 1}</span>
            </div>
          </article>`;
        })
        .join("");
    }

    wireTriageCheckboxes(els.results);

    els.results.querySelectorAll("[data-key]").forEach((row) => {
      row.onclick = (ev) => {
        if (ev.target.closest(".triage-pick, .triage-cb")) return;
        focusedKey = row.dataset.key;
        const d = devicesByKey[focusedKey];
        if (d) renderFocus(d);
        renderDeviceList();
      };
    });
  }

  function renderFocus(d) {
    if (!d) {
      els.focusEmpty.classList.remove("hidden");
      els.focusPanel.classList.add("hidden");
      return;
    }
    els.focusEmpty.classList.add("hidden");
    els.focusPanel.classList.remove("hidden");

    const name = d.name || d.device_type_name || "?";
    const level =
      lastSample?.device_key === d.key && lastSample.level != null
        ? lastSample.level
        : d.signal_level || 0;
    const pct = level * 10;
    const db =
      lastSample?.device_key === d.key && lastSample.db != null
        ? `${lastSample.db} dB`
        : strengthText(d);

    els.focusTitle.innerHTML = `${typeIconHtml(d, "focus-glyph")} ${escapeHtml(name)}`;
    const fill = els.focusBar.querySelector(".sig-fill");
    fill.style.width = pct + "%";
    fill.className = "sig-fill " + levelClass(level);
    els.focusDb.textContent = db;
    els.focusHint.textContent =
      lastSample?.device_key === d.key ? lastSample.hint || "" : "";
    els.focusSpark.textContent = sparkHtml(d.signal_history);

    const meta = d.metadata || {};
    const fp = meta.fingerprint || {};
    const wifiNear = d.wifi_nearby || meta.wifi_nearby || [];
    const tpmsDec = meta.tpms_decode || {};
    const tpmsSensors = tpmsDec.sensors || [];
    const uhf = meta.uhf_decode || {};
    const liveDec = meta.live_decode || {};
    const code = meta.code_class || {};

    if (els.focusIdentity) {
      const chips = [
        deviceVendor(d) ? `<span class="id-chip vendor">${escapeHtml(deviceVendor(d))}</span>` : "",
        deviceFamily(d) ? `<span class="id-chip">${escapeHtml(deviceFamily(d))}</span>` : "",
        deviceModel(d) ? `<span class="id-chip model">${escapeHtml(deviceModel(d))}</span>` : "",
        (meta.adsb || {}).callsign
          ? `<span class="id-chip model">${escapeHtml(meta.adsb.callsign)}</span>`
          : "",
        (meta.adsb || {}).icao
          ? `<span class="id-chip">ICAO ${escapeHtml(meta.adsb.icao)}</span>`
          : "",
        (meta.ais || {}).mmsi
          ? `<span class="id-chip">MMSI ${escapeHtml(String(meta.ais.mmsi))}</span>`
          : "",
        (meta.ais || {}).shipname || (meta.ais || {}).name
          ? `<span class="id-chip model">${escapeHtml((meta.ais || {}).shipname || (meta.ais || {}).name)}</span>`
          : "",
        fp.confidence ? `<span class="id-chip conf">${escapeHtml(fp.confidence)}</span>` : "",
        fp.matched_rule ? `<span class="id-chip rule">${escapeHtml(fp.matched_rule)}</span>` : "",
        wifiNear.length ? `<span class="id-chip wifi">${wifiNear.length} Wi‑Fi</span>` : "",
      ].filter(Boolean);
      els.focusIdentity.innerHTML = chips.length
        ? `<div class="id-chips">${chips.join("")}</div>`
        : `<div class="hint">No fingerprint yet</div>`;
    }

    const bwMhz =
      d.bandwidth_hz != null
        ? `${(Number(d.bandwidth_hz) / 1e6).toFixed(3)} MHz`
        : meta.band_mhz != null
          ? `${meta.band_mhz} MHz`
          : null;
    const rows = [
      ["Key", d.key],
      ["MAC / ID", d.mac || d.id || null],
      ["Loc", locText(d)],
      ["Radio", (d.radio || "").toUpperCase()],
      ["Type", d.device_type_name],
      ["Freq", d.freq_mhz != null ? `${Number(d.freq_mhz).toFixed(3)} MHz` : null],
      ["Bandwidth", bwMhz],
      ["Power", d.power_dbm != null ? `${d.power_dbm} dBm` : null],
      ["RSSI", d.rssi_dbm != null ? `${d.rssi_dbm} dBm` : null],
      ["SNR", d.snr_db != null ? `${d.snr_db} dB` : null],
      ["TX power", meta.tx_power != null ? `${meta.tx_power} dBm` : null],
      ["Connectable", meta.connectable === true ? "yes" : meta.connectable === false ? "no" : null],
      ["Severity", deviceSev(d)],
      ["Profile", meta.attack_profile],
      ["Modulation", meta.modulation_hint || null],
      ["Vendor", deviceVendor(d) || null],
      ["OUI vendor", fp.oui_vendor || meta.oui_hint || null],
      ["Company ID", (fp.company_ids || []).join(", ") || null],
      ["Company", (fp.company_names || []).join(" · ") || null],
      ["Family", deviceFamily(d) || null],
      ["Model", deviceModel(d) || null],
      ["FP rule", fp.matched_rule || null],
      ["FP conf", fp.confidence || null],
      ["Random MAC", fp.random_mac === true ? "yes" : fp.random_mac === false ? "no" : null],
      ["Tuya", meta.tuya_detected === true ? "yes" : null],
      ["Class", meta.classification || null],
      ["Capability", meta.capability || null],
      [
        "Quality",
        meta.quality
          ? `${meta.quality.tier || "?"} · ${meta.quality.score ?? "?"} · ${meta.quality.summary || ""}`
          : null,
      ],
      ["Hits", d.hit_count],
      ["First seen", d.first_seen],
      ["Last seen", d.last_seen],
      ["GPS last", d.lat != null ? `${Number(d.lat).toFixed(6)}, ${Number(d.lon).toFixed(6)}` : null],
      ["GPS first", d.first_lat != null ? `${Number(d.first_lat).toFixed(6)}, ${Number(d.first_lon).toFixed(6)}` : null],
      ["Code class", code.class || null],
      ["Live decode", liveDec.ok != null ? `${liveDec.ok ? "ok" : "empty"} · ${liveDec.kind || ""} · ${liveDec.message || ""}` : null],
    ];
    if (tpmsSensors[0]) {
      const s0 = tpmsSensors[0];
      rows.push(["TPMS ID", s0.id]);
      rows.push(["TPMS model", s0.model]);
      if (s0.pressure_psi != null) rows.push(["Pressure", `${s0.pressure_psi} PSI`]);
      if (s0.temperature_c != null) rows.push(["Temp", `${s0.temperature_c} °C`]);
    }
    const adsb = meta.adsb || {};
    const ais = meta.ais || {};
    pushTrafficMetaRows(rows, d);
    if (!adsb.icao && !ais.mmsi) {
      // keep legacy GPS rows for non-traffic
    }
    if (uhf.summary) rows.push(["UHF", uhf.summary]);
    const filtered = rows.filter(([, v]) => v != null && v !== "");

    renderTrafficFocus(d);

    els.focusMeta.innerHTML = filtered
      .map(([k, v]) => `<dt>${escapeHtml(k)}</dt><dd>${escapeHtml(String(v))}</dd>`)
      .join("");

    if (els.btnSeeMap) {
      const hasGeo = !!deviceLatLng(d);
      const peers = isTrafficDevice(d) ? trafficPeers(d).length : 0;
      els.btnSeeMap.disabled = !hasGeo;
      els.btnSeeMap.title = hasGeo
        ? isTrafficDevice(d)
          ? peers > 1
            ? `Show ${peers} aircraft/vessels on map`
            : "Fly to aircraft / vessel position"
          : "Fly to first-seen GPS pin"
        : isTrafficDevice(d)
          ? "Waiting for ADS-B/AIS position frame"
          : "No coordinates yet";
      els.btnSeeMap.classList.toggle("btn-wardrive", (isSignalGeo(d) || isTrafficDevice(d)) && hasGeo);
    }

    const fpvTarget = isFpvDevice(d);
    if (els.btnFpvDecode) {
      els.btnFpvDecode.classList.toggle("hidden", !fpvTarget);
      els.btnFpvDecode.disabled = scanRunning || vulnRunning;
      els.btnFpvDecode.title = fpvTarget
        ? `Capture IQ @ ${d.freq_mhz != null ? Number(d.freq_mhz).toFixed(3) + " MHz" : "?"} and try FM video frames`
        : "";
    }
    if (els.btnDive) {
      // Always keep Deep dive — FPV uses the dedicated button (avoids duplicate labels)
      els.btnDive.textContent = "Deep dive";
      els.btnDive.title = fpvTarget
        ? "General deep dive (use Decode FPV for analog video frames)"
        : "Deep dive analysis";
    }

    if (els.focusAdv) {
      const uuids = meta.service_uuids || [];
      const mfg = meta.manufacturer_data || {};
      const svcData = meta.service_data || {};
      const mfgEntries = Object.entries(mfg);
      const svcEntries = Object.entries(svcData);
      const leakHit = detectMacInMfg(d);
      const bits = [];
      if (uuids.length) {
        bits.push(`<div class="adv-block"><div class="adv-label">Service UUIDs</div>
          <ul class="adv-list">${uuids
            .slice(0, 12)
            .map((u) => `<li><code>${escapeHtml(String(u))}</code></li>`)
            .join("")}${uuids.length > 12 ? `<li class="hint">+${uuids.length - 12} more</li>` : ""}</ul></div>`);
      }
      if (mfgEntries.length) {
        bits.push(`<div class="adv-block"><div class="adv-label">Manufacturer data</div>
          <ul class="adv-list">${mfgEntries
            .slice(0, 8)
            .map(([cid, hex]) => {
              const highlighted =
                leakHit && String(cid) === String(leakHit.company_id)
                  ? highlightMacInHex(hex, leakHit.match_hex)
                  : escapeHtml(String(hex).slice(0, 64)) + (String(hex).length > 64 ? "…" : "");
              return `<li><code>${escapeHtml(String(cid))}</code>
                  <span class="adv-hex">${highlighted}</span></li>`;
            })
            .join("")}</ul></div>`);
      }
      if (svcEntries.length) {
        bits.push(`<div class="adv-block"><div class="adv-label">Service data</div>
          <ul class="adv-list">${svcEntries
            .slice(0, 8)
            .map(
              ([uid, hex]) =>
                `<li><code>${escapeHtml(String(uid))}</code>
                  <span class="adv-hex">${escapeHtml(String(hex).slice(0, 64))}${String(hex).length > 64 ? "…" : ""}</span></li>`
            )
            .join("")}</ul></div>`);
      }
      els.focusAdv.innerHTML = bits.length
        ? `<h4 class="focus-h">Advertisement</h4>${bits.join("")}`
        : "";
    }

    if (els.focusLeak) {
      const leakHit = detectMacInMfg(d);
      const leakFinding = (d.risk?.findings || []).find((f) =>
        /manufacturer_data|BD_ADDR embedded/i.test(f.finding || "")
      );
      if (leakHit || leakFinding) {
        const cid = leakHit?.company_id || "—";
        const order = leakHit?.byte_reversed ? "byte-reversed" : "forward";
        els.focusLeak.innerHTML = `<div class="identity-leak-banner">
          <div class="identity-leak-title">Identity leak</div>
          <div class="identity-leak-body">BD_ADDR embedded in manufacturer_data
            · company <code>${escapeHtml(String(cid))}</code>
            ${leakHit ? `· match ${escapeHtml(order)} @ byte ${leakHit.offset}` : ""}
          </div>
        </div>`;
      } else {
        els.focusLeak.innerHTML = "";
      }
    }

    if (els.focusGattSnap) {
      const snap = d.risk?.gatt_snapshot;
      if (snap?.services?.length) {
        const st = gattWriteStats(snap.services);
        const rows = st.writeChars
          .slice(0, 8)
          .map(
            (w) =>
              `<li><code>${escapeHtml(String(w.char.uuid || "").slice(0, 36))}</code>
                <span class="gatt-props">${propChips(w.props)}</span></li>`
          )
          .join("");
        els.focusGattSnap.innerHTML = `<h4 class="focus-h">GATT writables (last dive)</h4>
          <div class="gatt-kpi"><span class="gatt-kpi-w">${st.writable} writable</span>
            <span>·</span><span>${st.readable} open read(s)</span></div>
          ${rows ? `<ul class="adv-list gatt-write-list">${rows}</ul>` : '<div class="hint">No writable chars</div>'}`;
      } else {
        els.focusGattSnap.innerHTML = "";
      }
    }

    if (els.focusWifi) {
      if (wifiNear.length) {
        els.focusWifi.innerHTML = `<h4 class="focus-h">Wi‑Fi nearby</h4>
          <ul class="wifi-list">${wifiNear
            .map(
              (ap) => `<li>
              <div class="wifi-ssid">${escapeHtml(ap.ssid || "(hidden)")}
                <span class="wifi-score">${escapeHtml(String(ap.score ?? ""))}</span>
              </div>
              <div class="wifi-meta">${escapeHtml(ap.vendor || "—")} · ${escapeHtml(ap.bssid || "")}
                · ch ${escapeHtml(String(ap.channel ?? "?"))} · ${escapeHtml(String(ap.freq_mhz ?? ""))} MHz
                · ${ap.signal_dbm != null ? escapeHtml(String(ap.signal_dbm)) + " dBm" : ""}
                ${ap.dist_m != null ? " · " + escapeHtml(String(ap.dist_m)) + " m" : ""}
                · ${escapeHtml(ap.security || "")}
              </div>
              <div class="wifi-why">${escapeHtml((ap.reasons || []).join(" · "))}</div>
            </li>`
            )
            .join("")}</ul>`;
      } else {
        els.focusWifi.innerHTML = `<h4 class="focus-h">Wi‑Fi nearby</h4>
          <div class="hint">${wifiAps.length ? "No correlated APs within range/vendor." : "Wi‑Fi scan idle or no APs yet."}</div>`;
      }
    }

    if (els.focusDecode) {
      const bits = [];
      const fpv = meta.fpv_decode || {};
      if (fpv.frames && fpv.frames.length) {
        const ch = fpv.channel || {};
        const chLabel = ch.channel
          ? `${ch.band || ""} ${ch.channel}`.trim()
          : "";
        bits.push(`<div><strong>FPV</strong> · ${escapeHtml(fpv.message || "frames")}
          ${chLabel ? " · " + escapeHtml(chLabel) : ""}
          ${fpv.sync?.standard ? " · " + escapeHtml(String(fpv.sync.standard).toUpperCase()) : ""}</div>
          <div class="fpv-frames">${fpv.frames
            .map((fr) =>
              fr.png_base64
                ? `<img class="fpv-frame" alt="FPV frame" src="data:image/png;base64,${fr.png_base64}" />`
                : fr.file && fr.dive_id
                  ? `<img class="fpv-frame" alt="FPV frame" src="/api/artifact/${encodeURIComponent(fr.dive_id)}/${encodeURIComponent(fr.file)}" />`
                  : ""
            )
            .join("")}</div>`);
      } else if (fpv.message) {
        bits.push(`<div><strong>FPV</strong> · ${escapeHtml(fpv.message)}
          ${fpv.viability?.level ? " · viability " + escapeHtml(fpv.viability.level) : ""}</div>`);
      }
      if (tpmsSensors.length) {
        bits.push(`<div><strong>TPMS</strong> · ${escapeHtml(
          tpmsSensors.slice(0, 3).map((s) => {
            const p = [`id=${s.id}`];
            if (s.pressure_psi != null) p.push(`${s.pressure_psi} PSI`);
            if (s.temperature_c != null) p.push(`${s.temperature_c}°C`);
            return p.join(" ");
          }).join(" | ")
        )}</div>`);
      }
      if (uhf.ok) {
        bits.push(`<div><strong>UHF</strong> · ${escapeHtml(uhf.summary || uhf.message || "ok")}
          ${(uhf.methods || []).length ? " · " + escapeHtml(uhf.methods.join(", ")) : ""}</div>`);
      }
      if ((meta.rtl433_frames || []).length) {
        bits.push(`<div><strong>rtl_433</strong> · ${escapeHtml(String(meta.rtl433_frames.length))} frame(s)
          · ${escapeHtml(code.class || "")}</div>`);
      }
      if ((fp.company_ids || []).length) {
        bits.push(`<div><strong>BLE mfg</strong> · ${escapeHtml((fp.company_names || fp.company_ids).join(" · "))}</div>`);
      }
      if (meta.temporal) {
        bits.push(`<div><strong>Temporal</strong> · <code>${escapeHtml(JSON.stringify(meta.temporal).slice(0, 120))}</code></div>`);
      }
      els.focusDecode.innerHTML = bits.length
        ? `<h4 class="focus-h">Decode / evidence</h4>${bits.join("")}`
        : "";
    }

    const risk = d.risk || {};
    if (risk.findings?.length) {
      const findingsHtml = risk.findings
        .slice(0, 8)
        .map((f) => {
          const ev = (f.evidence || []).slice(0, 4);
          const evHtml = ev.length
            ? `<ul class="finding-ev">${ev
                .map((e) => {
                  if (e == null) return "";
                  if (typeof e === "string" || typeof e === "number") {
                    return `<li><code>${escapeHtml(String(e))}</code></li>`;
                  }
                  const line = [
                    e.uuid || e.name || "",
                    e.description || "",
                    e.props || (Array.isArray(e.properties) ? e.properties.join(",") : ""),
                    e.service || e.service_uuid || "",
                  ]
                    .filter(Boolean)
                    .join(" · ");
                  return `<li><code>${escapeHtml(line || JSON.stringify(e))}</code></li>`;
                })
                .join("")}</ul>`
            : "";
          return `<div class="finding-row">
            <span class="risk-pill risk-${escapeHtml(f.severity || "low")}">${escapeHtml(f.severity || "?")}</span>
            <div class="finding-body">
              <div class="finding-title">${escapeHtml(f.finding || f.title || "")}</div>
              <div class="finding-detail">${escapeHtml(f.detail || "")}</div>
              ${evHtml}
            </div>
          </div>`;
        })
        .join("");
      els.focusRisk.innerHTML = `<div class="risk-head"><strong>${escapeHtml(deviceSev(d))}</strong>
        · ${escapeHtml(risk.exploitability || "")}</div>
        ${(risk.summary || []).length ? `<div class="hint">${escapeHtml(risk.summary.slice(0, 4).join(" · "))}</div>` : ""}
        ${findingsHtml}`;
    } else if (tpmsSensors.length) {
      els.focusRisk.innerHTML = `<strong>TPMS decode</strong><br>${escapeHtml(
        tpmsSensors.slice(0, 3).map((s) => `id=${s.id}`).join(" | ")
      )}`;
    } else if (
      d.device_type_id === "tpms_us" ||
      d.device_type_id === "tpms_eu" ||
      meta.attack_profile === "tpms_315" ||
      meta.attack_profile === "tpms_433"
    ) {
      els.focusRisk.innerHTML = `<span style="color:var(--text-muted)">TPMS — Deep dive (~20s) while the sensor transmits</span>`;
    } else {
      els.focusRisk.innerHTML = `<span style="color:var(--text-muted)">No triage yet — Quick vulns or Deep dive</span>`;
    }

    els.btnMonitor.textContent =
      monitoring && lastSample?.device_key === d.key ? "Stop monitor" : "Monitor";

    if (els.btnReplay) {
      const radio = (d.radio || "").toLowerCase();
      if (radio === "ble" || radio === "wifi") {
        els.btnReplay.textContent = "⚡ Attack";
        els.btnReplay.disabled = false;
        els.btnReplay.title =
          radio === "wifi"
            ? "Wi‑Fi security assessment (catalog) — no active exploit"
            : "Run lab attack vectors";
      } else {
        els.btnReplay.textContent = "▶ Replay";
        els.btnReplay.disabled = false;
        els.btnReplay.title = "RF listen / replay lab";
      }
    }

    const w = deviceWow(d);
    if (els.focusWowHint) {
      if (fpvTarget) {
        els.focusWowHint.textContent =
          "FPV: pulsa «Decode FPV» con un VTX analógico activo. Digital (DJI/Walksnail) no se decodifica.";
      } else if (w.tier === "wow") {
        els.focusWowHint.innerHTML = `<span class="wow-pill">WOW</span> ${escapeHtml(w.headline || "")} — ${escapeHtml(w.demo || "Run Attack")}`;
      } else {
        els.focusWowHint.textContent = w.headline ? `${w.tier}: ${w.headline}` : "";
      }
    }
  }

  /* ── Dashboard cakes ─────────────────────────────────────── */

  function refreshStatsFromDevices() {
    const byType = {};
    const byRadio = {};
    const bySev = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 };
    devices.forEach((d) => {
      const t = d.device_type_name || d.device_type_id || "unknown";
      byType[t] = (byType[t] || 0) + 1;
      const r = (d.radio || "unknown").toLowerCase();
      byRadio[r] = (byRadio[r] || 0) + 1;
      let sev = deviceSev(d);
      if (!d.risk && (!d.risk_status || d.risk_status === "unknown" || d.risk_status === "suspected")) {
        sev = "unknown";
      }
      bySev[sev] = (bySev[sev] || 0) + 1;
    });
    const toSlices = (m) => {
      const total = Object.values(m).reduce((a, b) => a + b, 0) || 1;
      return Object.entries(m)
        .filter(([, v]) => v > 0)
        .sort((a, b) => b[1] - a[1])
        .map(([label, count]) => ({ label, count, pct: Math.round((1000 * count) / total) / 10 }));
    };
    stats = {
      total: devices.length,
      by_type: toSlices(byType),
      by_radio: toSlices(byRadio),
      by_severity: toSlices(bySev),
    };
    renderDashboard();
  }

  function paintCake(elCake, elLegend, slices, colorFn) {
    if (!slices.length) {
      elCake.style.background = "conic-gradient(#243044 0 100%)";
      elLegend.innerHTML = `<li class="hint">No data</li>`;
      return;
    }
    let acc = 0;
    const parts = [];
    slices.forEach((s, i) => {
      const color = colorFn(s, i);
      const start = acc;
      acc += s.pct;
      parts.push(`${color} ${start}% ${acc}%`);
    });
    elCake.style.background = `conic-gradient(${parts.join(", ")})`;
    elLegend.innerHTML = slices
      .map((s, i) => {
        const color = colorFn(s, i);
        return `<li><span class="swatch" style="background:${color}"></span>
          ${escapeHtml(s.label)} <span class="pct">${s.count} · ${s.pct}%</span></li>`;
      })
      .join("");
  }

  function renderDashboard() {
    paintCake(
      $("#cake-type"),
      $("#legend-type"),
      stats.by_type || [],
      (_s, i) => PIE_COLORS[i % PIE_COLORS.length]
    );
    paintCake(
      $("#cake-sev"),
      $("#legend-sev"),
      stats.by_severity || [],
      (s) => SEV_COLORS[s.label] || PIE_COLORS[0]
    );
    paintCake(
      $("#cake-radio"),
      $("#legend-radio"),
      stats.by_radio || [],
      (_s, i) => PIE_COLORS[(i + 3) % PIE_COLORS.length]
    );

    const sevOrder = ["critical", "high", "medium", "low", "unknown"];
    const map = Object.fromEntries((stats.by_severity || []).map((s) => [s.label, s]));
    const max = Math.max(1, ...sevOrder.map((k) => (map[k] || {}).count || 0));
    $("#sev-bars").innerHTML = sevOrder
      .map((k) => {
        const n = (map[k] || {}).count || 0;
        const pct = Math.round((100 * n) / max);
        return `<div class="sev-row">
          <span>${k}</span>
          <div class="sev-track"><div class="sev-fill ${k}" style="width:${pct}%"></div></div>
          <span>${n}</span>
        </div>`;
      })
      .join("");
    renderLiveFindings();
  }

  /* ── Status / WS ─────────────────────────────────────────── */

  function updateSweepLive(s) {
    if (!els.sweepLive) return;
    const running = s.status === "running" || s.status === "stopping";
    const band = s.current_band;
    const idx = s.band_index || 0;
    const tot = s.band_total || 0;
    let text = s.message || "";
    if (running && band && band.freq_min_mhz != null) {
      const lo = Number(band.freq_min_mhz);
      const hi = Number(band.freq_max_mhz);
      const range =
        hi != null && hi !== lo
          ? `${lo.toFixed(0)}–${hi.toFixed(0)} MHz`
          : `${lo.toFixed(0)} MHz`;
      const chunk = tot ? ` · ${idx}/${tot}` : "";
      text = `▶ ${range}${chunk}` + (s.message && !String(s.message).startsWith("Sweeping") ? ` · ${s.message}` : "");
      if (s.message && String(s.message).includes("peak")) {
        text = `▶ ${s.message}`;
      } else if (s.message) {
        text = `▶ ${s.message}`;
      } else {
        text = `▶ Sweeping ${range}${chunk}`;
      }
    } else if (!running) {
      text = s.message || (s.status === "completed" ? "Done" : "Idle — pick a mode and start");
    }
    els.sweepLive.textContent = text;
    els.sweepLive.classList.toggle("is-idle", !running);
  }

  function applyStatus(s) {
    updateScanBadge(s.status);
    els.progress.style.width = (s.progress || 0) + "%";
    els.progressLabel.textContent = Math.round(s.progress || 0) + "%";
    updateSweepLive(s);
    if (s.logs?.length) {
      const joined = s.logs.join("\n");
      if (joined !== els.log.textContent.trim()) els.log.textContent = joined + "\n";
    }
    if (s.devices) setDevices(s.devices);
    if (s.vuln) {
      updateVulnBadge(s.vuln.status, s.vuln.counts);
      els.vulnProgress.style.width = (s.vuln.progress || 0) + "%";
      els.vulnProgressLabel.textContent = Math.round(s.vuln.progress || 0) + "%";
    }
    if (s.status !== "running" && (!s.vuln || s.vuln.status !== "running")) {
      stopPolling();
    }
  }

  async function pollStatus() {
    try {
      applyStatus(await api("/api/scan/status"));
    } catch (e) {
      log("Poll error: " + e);
    }
  }

  function startPolling() {
    stopPolling();
    // Faster while scanning so freq label stays live even if WS hiccups
    pollTimer = setInterval(pollStatus, 700);
  }

  function stopPolling() {
    if (pollTimer) {
      clearInterval(pollTimer);
      pollTimer = null;
    }
  }

  function connectWs() {
    const proto = location.protocol === "https:" ? "wss" : "ws";
    ws = new WebSocket(`${proto}://${location.host}/ws/scan`);
    ws.onopen = () => log("Live feed connected.");
    ws.onmessage = (ev) => {
      const msg = JSON.parse(ev.data);
      if (msg.type === "log") log(msg.message);
      if (msg.type === "progress") {
        els.progress.style.width = msg.progress + "%";
        els.progressLabel.textContent = Math.round(msg.progress) + "%";
        updateSweepLive({
          status: "running",
          message: msg.message,
          current_band: msg.current_band,
          band_index: msg.band_index,
          band_total: msg.band_total,
        });
      }
      if (msg.type === "device" || msg.type === "device_update") {
        if (msg.device) upsertDevice(msg.device);
      }
      if (msg.type === "tracker_snapshot") setDevices(msg.devices || []);
      if (msg.type === "stats") {
        stats = msg;
        renderDashboard();
      }
      if (msg.type === "monitor_sample") {
        lastSample = msg;
        monitoring = true;
        syncStopButton();
        if (focusedKey && devicesByKey[focusedKey]) renderFocus(devicesByKey[focusedKey]);
      }
      if (msg.type === "monitor_stop") {
        monitoring = false;
        lastSample = null;
        syncStopButton();
      }
      if (msg.type === "vuln_finding") {
        els.vulnProgress.style.width = (msg.progress || 0) + "%";
        els.vulnProgressLabel.textContent = Math.round(msg.progress || 0) + "%";
        if (msg.counts) renderVulnCounts(msg.counts);
      }
      if (msg.type === "vuln_scan_start") {
        updateVulnBadge("running");
        startPolling();
      }
      if (msg.type === "vuln_scan_complete") {
        updateVulnBadge(msg.status || "completed", msg.counts);
        refreshStatsFromDevices();
        renderLiveFindings();
        if (demoModeActive) {
          const { leaks, criticals, writables } = collectLiveFindings();
          log(
            `Demo: ${leaks.length} identity leaks · ${writables.length} writable GATT · ${criticals.length} critical`
          );
        }
      }
      if (msg.type === "complete" || msg.type === "error") {
        updateScanBadge(msg.status || "error");
        if (msg.type === "error") log("ERROR: " + msg.message);
        pollStatus();
      }
      if (msg.type === "gps_fix") {
        gpsFix = msg.fix || gpsFix;
        updateMapFixLabel();
        updateHunterMarker();
        updateGpsBadge({ has_fix: !!gpsFix, fix: gpsFix, status: "fix" });
      }
      if (msg.type === "gps_status") {
        updateGpsBadge(msg);
        if (msg.fix) {
          gpsFix = msg.fix;
          updateMapFixLabel();
          updateHunterMarker();
        }
      }
      if (msg.type === "gps_trail") {
        gpsTrail = msg.trail || [];
        if (msg.fix) gpsFix = msg.fix;
        updateMapFixLabel();
        redrawTrail();
        updateHunterMarker();
      }
      if (msg.type === "wifi_status") {
        if (!wifiLiveEnabled) {
          updateWifiBadge({ ...msg, status: "stopped", ap_count: wifiAps.length });
          return;
        }
        updateWifiBadge(msg);
      }
      if (msg.type === "wifi_snapshot") {
        if (!wifiLiveEnabled) {
          // Only allow empty clears while frozen.
          if (!(msg.aps || []).length) {
            wifiAps = [];
            updateWifiBadge({ ...(wifiStatus || {}), status: "stopped", ap_count: 0 });
            refreshMapWifi();
            renderDeviceList();
          }
          return;
        }
        const aps = msg.aps || [];
        wifiAps = aps;
        updateWifiBadge({
          ...(wifiStatus || {}),
          status: "running",
          ap_count: msg.count != null ? msg.count : wifiAps.length,
          iface: msg.iface || (wifiStatus || {}).iface,
        });
        updateMapFixLabel();
        refreshMapWifi();
        // Re-render focus so wifi_nearby refreshes after next tracker enrich;
        // also refresh device list badges
        renderDeviceList();
        if (focusedKey && devicesByKey[focusedKey]) renderFocus(devicesByKey[focusedKey]);
      }
    };
    ws.onerror = () => log("WebSocket error — polling fallback.");
    ws.onclose = () => setTimeout(connectWs, 3000);
  }

  /* ── Events ──────────────────────────────────────────────── */

  document.querySelectorAll(".view-tab").forEach((btn) => {
    btn.onclick = () => {
      document.querySelectorAll(".view-tab").forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
      const view = btn.dataset.view;
      $("#view-devices").classList.toggle("hidden", view !== "devices");
      const mapPane = $("#view-map");
      if (mapPane) mapPane.classList.toggle("hidden", view !== "map");
      $("#view-dashboard").classList.toggle("hidden", view !== "dashboard");
      if (view === "dashboard") renderDashboard();
      if (view === "map") {
        ensureMap();
        setTimeout(() => {
          if (map) map.invalidateSize();
          refreshMapDevices();
          refreshMapWifi();
          updateHunterMarker();
          redrawTrail();
        }, 50);
      }
    };
  });

  if (els.btnMapFit) els.btnMapFit.onclick = () => fitMapAll();
  if (els.btnMapFollow) {
    els.btnMapFollow.onclick = () => {
      mapFollow = !mapFollow;
      els.btnMapFollow.textContent = mapFollow ? "Following" : "Follow GPS";
      if (mapFollow) updateHunterMarker();
    };
  }
  if (els.btnMapTrailClear) {
    els.btnMapTrailClear.onclick = async () => {
      await api("/api/gps/trail/clear", { method: "POST" });
      gpsTrail = [];
      redrawTrail();
      updateMapFixLabel();
      log("GPS trail cleared");
    };
  }
  bindMapFilters();

  document.querySelectorAll('input[name="mode"]').forEach((el) => {
    el.addEventListener("change", () => {
      syncModeHint();
      if (!scanRunning) {
        els.btnScan.textContent = scanButtonLabel(selectedMode());
      }
    });
  });
  syncModeHint();

  function bindFilters() {
    const apply = () => {
      filters.text = els.filterText.value || "";
      filters.type = els.filterType.value || "";
      filters.radio = els.filterRadio.value || "";
      filters.sev = els.filterSev.value || "";
      filters.wow = els.filterWow?.value || "";
      filters.quality = els.filterQuality?.value || "";
      filters.evidence = els.filterEvidence?.value || "";
      sortBy = els.sortBy?.value || "wow";
      try {
        localStorage.setItem("rfh_sort", sortBy);
        localStorage.setItem("rfh_layout", layoutMode);
        localStorage.setItem("rfh_quality", filters.quality);
        localStorage.setItem("rfh_evidence", filters.evidence);
      } catch (_) {}
      renderDeviceList();
    };
    els.filterText.oninput = apply;
    els.filterType.onchange = apply;
    els.filterRadio.onchange = apply;
    els.filterSev.onchange = apply;
    if (els.filterWow) els.filterWow.onchange = apply;
    if (els.filterQuality) els.filterQuality.onchange = apply;
    if (els.filterEvidence) els.filterEvidence.onchange = apply;
    if (els.sortBy) els.sortBy.onchange = apply;
    if (els.layoutMode) {
      els.layoutMode.querySelectorAll(".layout-btn").forEach((btn) => {
        btn.onclick = () => {
          layoutMode = normalizeLayout(btn.dataset.layout);
          try {
            localStorage.setItem("rfh_layout", layoutMode);
          } catch (_) {}
          renderDeviceList();
        };
      });
    }
    els.btnClearFilters.onclick = () => {
      els.filterText.value = "";
      els.filterType.value = "";
      els.filterRadio.value = "";
      els.filterSev.value = "";
      if (els.filterWow) els.filterWow.value = "";
      if (els.filterQuality) els.filterQuality.value = "hide_noise";
      if (els.filterEvidence) els.filterEvidence.value = "";
      apply();
    };
    // restore prefs
    try {
      const s = localStorage.getItem("rfh_sort");
      const l = localStorage.getItem("rfh_layout");
      const qq = localStorage.getItem("rfh_quality");
      const ev = localStorage.getItem("rfh_evidence");
      if (s && els.sortBy) {
        els.sortBy.value = s;
        sortBy = s;
      }
      if (l) {
        layoutMode = normalizeLayout(l);
      }
      if (qq != null && els.filterQuality) {
        els.filterQuality.value = qq;
        filters.quality = qq;
      } else if (els.filterQuality) {
        els.filterQuality.value = filters.quality || "hide_noise";
      }
      if (ev != null && els.filterEvidence) {
        els.filterEvidence.value = ev;
        filters.evidence = ev;
      }
    } catch (_) {}
    syncLayoutSwitch();
  }

  function clearWifiUi() {
    wifiAps = [];
    updateWifiBadge({ ...(wifiStatus || {}), status: "stopped", ap_count: 0 });
    updateMapFixLabel();
    refreshMapWifi();
  }

  async function doStartScan({ clearResults }) {
    const mode = selectedMode();
    const passesVal = +$("#passes").value;
    const body = {
      device_type_ids: mode === "full_sweep" ? ["full_spectrum"] : [...selected],
      duration_s: +$("#duration").value,
      lna_db: +$("#lna").value,
      vga_db: +$("#vga").value,
      // Full sweep: fewer sweeps per chunk (range is huge)
      passes: mode === "full_sweep" ? Math.min(passesVal, 6) : passesVal,
      mode,
      live_decode: mode !== "full_sweep",
      clear_results: !!clearResults,
    };

    if (clearResults) {
      setDevices([]);
      clearWifiUi();
      triageSelected.clear();
      focusedKey = null;
      renderFocus(null);
      els.log.textContent = "";
      log(
        mode === "full_sweep"
          ? "Starting full spectrum sweep (HackRF 1–6000 MHz)…"
          : `Starting ${mode} (fresh)…`
      );
    } else {
      log(
        mode === "full_sweep"
          ? `Full sweep — keeping ${devices.length} device(s)…`
          : `Resuming ${mode} — keeping ${devices.length} device(s)…`
      );
    }

    const res = await api("/api/scan/start", { method: "POST", body: JSON.stringify(body) });
    if (!res.ok) {
      log("Start failed: " + (res.error || "unknown"));
      return;
    }
    log(
      clearResults
        ? `Session ${res.session_id} (fresh start)`
        : `Session ${res.session_id} — tracked ${res.tracked || devices.length}`
    );
    updateScanBadge("running");
    startPolling();
  }

  els.btnScan.onclick = async () => {
    const mode = selectedMode();
    if (mode !== "full_sweep" && !selected.size) {
      alert("Select at least one device type (or choose Full sweep).");
      return;
    }
    if (mode === "full_sweep") {
      const go = confirm(
        "Full spectrum sweep covers HackRF 1–6000 MHz in ~100 MHz chunks.\n" +
          "This can take several minutes. Continue?"
      );
      if (!go) return;
    }
    const n = devices.length;
    if (!n) {
      await doStartScan({ clearResults: mode === "full_sweep" });
      return;
    }
    openConfirm({
      title: mode === "full_sweep" ? "Full spectrum sweep" : "¿Cómo quieres arrancar?",
      subtitle: `${n} device(s) en el tracker`,
      okLabel: "Continuar (mantener)",
      okClass: "btn-wardrive",
      altLabel: "Empezar de cero",
      bodyHtml: `
        <p>${
          mode === "full_sweep"
            ? "Barrido completo 1–6000 MHz. Puedes acumular hits o empezar limpio."
            : "Puedes <strong>parar y arrancar</strong> sin perder lo ya encontrado."
        }</p>
        <p class="confirm-count">${n} device(s) guardados · GPS trail se mantiene al continuar</p>
        <p class="hint"><strong>Continuar</strong> acumula hits. <strong>Empezar de cero</strong> borra devices + trail (como Cleanup).</p>`,
      onOk: () => doStartScan({ clearResults: false }),
      onAlt: () => doStartScan({ clearResults: true }),
    });
  };

  els.btnStop.onclick = async () => {
    // Instant UI feedback — don't wait for HackRF to die
    log("Stop all…");
    updateScanBadge("stopping");
    updateVulnBadge("idle");
    monitoring = false;
    lastSample = null;
    vulnRunning = false;
    scanRunning = false;
    syncStopButton();
    els.btnStop.disabled = true;
    els.btnStop.textContent = "Stopping…";

    try {
      const res = await api("/api/stop-all", { method: "POST" });
      if (res.killed?.length) log("Killed: " + res.killed.join(", "));
      await stopWifiScan({ clear: true });
      log("Wi‑Fi scan stopped with Stop all");
    } catch (e) {
      log("Stop error: " + e);
    }
    els.btnStop.textContent = "■ Stop all";
    demoModeActive = false;
    updateScanBadge("stopped");
    syncStopButton();
    pollStatus();
  };

  let confirmOnOk = null;
  let confirmOnAlt = null;

  function openConfirm({ title, subtitle, bodyHtml, okLabel, onOk, altLabel, onAlt, okClass }) {
    els.confirmTitle.textContent = title || "Confirm";
    els.confirmSubtitle.textContent = subtitle || "";
    els.confirmBody.innerHTML = bodyHtml || "";
    els.btnConfirmOk.textContent = okLabel || "Confirmar";
    els.btnConfirmOk.className = "btn " + (okClass || "btn-danger");
    confirmOnOk = typeof onOk === "function" ? onOk : null;
    confirmOnAlt = typeof onAlt === "function" ? onAlt : null;
    if (els.btnConfirmAlt) {
      if (altLabel && onAlt) {
        els.btnConfirmAlt.textContent = altLabel;
        els.btnConfirmAlt.classList.remove("hidden");
      } else {
        els.btnConfirmAlt.classList.add("hidden");
      }
    }
    els.confirmModal.classList.remove("hidden");
  }

  function closeConfirm() {
    els.confirmModal.classList.add("hidden");
    confirmOnOk = null;
    confirmOnAlt = null;
    if (els.btnConfirmAlt) els.btnConfirmAlt.classList.add("hidden");
  }

  els.confirmModal.querySelectorAll("[data-confirm-dismiss]").forEach((el) => {
    el.onclick = closeConfirm;
  });
  els.btnConfirmOk.onclick = async () => {
    const fn = confirmOnOk;
    closeConfirm();
    if (fn) await fn();
  };
  if (els.btnConfirmAlt) {
    els.btnConfirmAlt.onclick = async () => {
      const fn = confirmOnAlt;
      closeConfirm();
      if (fn) await fn();
    };
  }

  els.btnCleanup.onclick = () => {
    const n = devices.length + (wifiAps || []).length;
    openConfirm({
      title: "Cleanup results?",
      subtitle: "This cannot be undone from the UI",
      okLabel: "Sí, borrar todo",
      bodyHtml: `
        <p>Vas a <strong>borrar todos los devices detectados</strong> (RF/BLE + Wi‑Fi), el historial de señal, el triage de vulns y el focus actual.</p>
        <p class="hint">Si hay un wardrive, monitor o escaneo Wi‑Fi en marcha, también se detendrá. Empezarás de cero. Para volver a ver APs: clic en el badge Wi‑Fi o arranca un wardrive.</p>
        <p class="confirm-count">${n ? `${n} item(s) en tracker/Wi‑Fi se eliminarán.` : "El tracker ya está vacío — puedes limpiar igual."}</p>`,
      onOk: async () => {
        log("Cleanup…");
        updateScanBadge("stopped");
        monitoring = false;
        lastSample = null;
        vulnRunning = false;
        scanRunning = false;
        focusedKey = null;
        renderFocus(null);
        wifiLiveEnabled = false;
        try {
          const res = await api("/api/tracker/clear", { method: "POST" });
          triageSelected.clear();
          setDevices([]);
          clearWifiUi();
          updateTriageUi();
          renderVulnCounts({ critical: 0, high: 0, medium: 0, low: 0 });
          els.vulnProgress.style.width = "0%";
          els.vulnProgressLabel.textContent = "0%";
          els.progress.style.width = "0%";
          els.progressLabel.textContent = "0%";
          log(`Cleanup done — removed ${res.cleared || 0} RF/BLE device(s) + Wi‑Fi APs (Wi‑Fi scan stopped). Ready for a new wardrive.`);
          updateScanBadge("idle");
          updateVulnBadge("idle");
          syncStopButton();
          renderDeviceList();
        } catch (e) {
          log("Cleanup error: " + e);
        }
      },
    });
  };

  function refreshTpmsStatsHint() {
    if (!els.tpmsStatsHint) return;
    const tpms = devices.filter(
      (d) =>
        d.device_type_id === "tpms_us" ||
        d.device_type_id === "tpms_eu" ||
        (d.metadata || {}).attack_profile === "tpms_315" ||
        (d.metadata || {}).attack_profile === "tpms_433"
    );
    const decoded = tpms.filter(
      (d) => ((d.metadata || {}).tpms_decode || {}).sensors?.length
    ).length;
    els.tpmsStatsHint.textContent = tpms.length
      ? `TPMS: ${tpms.length} tracked · ${decoded} decoded · ${tpms.length - decoded} pending`
      : "TPMS: none tracked — wardrive tpms_us / tpms_eu first";
  }

  async function startVuln(mode) {
    if (!devices.length) {
      alert("No tracked devices — run a wardrive first.");
      return;
    }
    pruneTriageSelection();
    const keys = [...triageSelected];
    const scope = keys.length
      ? `${keys.length} selected`
      : `all ${devices.length}`;
    if (mode === "full" && !keys.length && devices.length > 30) {
      if (
        !confirm(
          `Full dive on ALL ${devices.length} devices can take a long time. Tick a subset first, or continue anyway?`
        )
      ) {
        return;
      }
    } else if (mode === "full" && keys.length) {
      if (
        !confirm(
          `Full dive runs IQ/GATT on ${keys.length} selected device(s). Continue?`
        )
      ) {
        return;
      }
    }
    log(`Vuln scan (${mode}) on ${scope}…`);
    const body = { mode };
    if (keys.length) body.device_keys = keys;
    const res = await api("/api/vuln-scan/start", {
      method: "POST",
      body: JSON.stringify(body),
    });
    if (!res.ok) {
      log("Vuln start failed: " + (res.error || ""));
      return;
    }
    updateVulnBadge("running");
    startPolling();
  }

  els.btnVulnQuick.onclick = () => startVuln("quick");
  els.btnVulnFull.onclick = () => startVuln("full");

  if (els.chkTriageVisible) {
    els.chkTriageVisible.onchange = () => {
      const visible = filteredDevices();
      const on = els.chkTriageVisible.checked;
      visible.forEach((d) => {
        if (!d.key) return;
        if (on) triageSelected.add(d.key);
        else triageSelected.delete(d.key);
      });
      renderDeviceList();
    };
  }
  if (els.btnTriageClear) {
    els.btnTriageClear.onclick = () => {
      triageSelected.clear();
      renderDeviceList();
      log("Triage selection cleared.");
    };
  }
  if (els.btnTpmsDecode) {
    els.btnTpmsDecode.onclick = () => {
      const tpms = devices.filter(
        (d) =>
          d.device_type_id === "tpms_us" ||
          d.device_type_id === "tpms_eu" ||
          (d.metadata || {}).attack_profile === "tpms_315" ||
          (d.metadata || {}).attack_profile === "tpms_433"
      );
      const pending = tpms.filter(
        (d) => !((d.metadata || {}).tpms_decode || {}).sensors?.length
      ).length;
      if (!tpms.length) {
        alert("No TPMS tracked — select tpms_us / tpms_eu and Start wardrive first.");
        return;
      }
      openConfirm({
        title: "Decode all TPMS?",
        subtitle: "HackRF listen ~20s per target · rtl_433",
        okLabel: "Sí, decodificar",
        bodyHtml: `
          <p>Vas a deep-divear hasta <strong>16</strong> candidatos TPMS (rankeados cerca de 315 / 433.92 MHz).</p>
          <p class="confirm-count">${tpms.length} tracked · ${pending} pending · ~${Math.min(16, pending || tpms.length) * 20}s peor caso</p>
          <p class="hint">Para el coche/rueda en movimiento mientras corre. Stop all cancela. Ya decodificados se saltan.</p>`,
        onOk: async () => {
          log("TPMS decode-all…");
          try {
            const res = await api("/api/tpms/decode-all", {
              method: "POST",
              body: JSON.stringify({
                max_devices: 16,
                skip_decoded: true,
                band: "all",
              }),
            });
            if (!res.ok) {
              log("TPMS decode failed: " + (res.error || ""));
              alert(res.error || "TPMS decode failed");
              return;
            }
            log(res.message || `Decoding ${res.selected} TPMS…`);
            updateVulnBadge("running");
            startPolling();
            // Prefer showing TPMS types in the list
            if (els.filterType) {
              const us = "TPMS US (315 MHz)";
              const eu = "TPMS EU (433.92 MHz)";
              const opts = [...els.filterType.options].map((o) => o.value);
              if (opts.includes(us)) els.filterType.value = us;
              else if (opts.includes(eu)) els.filterType.value = eu;
              filters.type = els.filterType.value || "";
              renderDeviceList();
            }
          } catch (e) {
            log("TPMS decode ERROR: " + e);
          }
        },
      });
    };
  }

  els.btnSelectAll.onclick = () => {
    // Replace selection with the visible tab only — do NOT keep leftover garage/LoRa
    // when user clicks Select all under Aviation (etc.).
    selected.clear();
    visibleTypes().forEach((dt) => selected.add(dt.id));
    renderGrid();
    updateSelectedCount();
    log(`Selected ${selected.size} type(s) in tab “${activeCategory}”: ${[...selected].join(", ")}`);
  };

  if (els.btnSelectWow) {
    els.btnSelectWow.onclick = () => {
      selected.clear();
      (wowTypeIds.length ? wowTypeIds : ["smart_tv_bt", "tuya_ble", "ble_sensors", "garage_433", "garage_315", "alarm_869"])
        .forEach((id) => selected.add(id));
      renderGrid();
      updateSelectedCount();
      log("WOW types selected — Start wardrive for demo targets.");
    };
  }

  if (els.btnSelectLabTvs) {
    els.btnSelectLabTvs.onclick = () => {
      selected.clear();
      selected.add("smart_tv_bt");
      renderGrid();
      updateSelectedCount();
      log("Lab TVs: smart_tv_bt only — wardrive then Attack a [TV] Samsung for LAN :8001 control.");
    };
  }

  const btnPortapack = $("#btn-select-portapack");
  if (btnPortapack) {
    btnPortapack.onclick = () => {
      selected.clear();
      const known = new Set((catalog.device_types || []).map((t) => t.id));
      PORTAPACK_TYPE_IDS.forEach((id) => {
        if (known.has(id)) selected.add(id);
      });
      renderGrid();
      updateSelectedCount();
      log(`PortaPack pack: ${selected.size} type(s) — ADS-B, AIS, FPV, pagers, BLE…`);
    };
  }

  if (els.btnSeeMap) {
    els.btnSeeMap.onclick = () => {
      const d = focusedKey ? devicesByKey[focusedKey] : null;
      if (d) seeOnMap(d);
    };
  }

  if (els.btnDemoMode) {
    els.btnDemoMode.onclick = async () => {
      const ids = wowBleTypeIds.length
        ? wowBleTypeIds
        : ["smart_tv_bt", "ble_sensors", "tuya_ble"];
      selected.clear();
      ids.forEach((id) => selected.add(id));
      // Prefer TV-first for lab demos
      if (selected.has("smart_tv_bt")) {
        log("Demo Mode: Smart TV first — Attack uses BLE identity + LAN KEY_VOLDOWN.");
      }
      renderGrid();
      updateSelectedCount();
      if (els.filterRadio) els.filterRadio.value = "ble";
      filters.radio = "ble";
      if (els.filterWow) els.filterWow.value = "wow";
      filters.wow = "wow";
      if (els.sortBy) els.sortBy.value = "wow";
      sortBy = "wow";
      demoModeActive = true;
      demoVulnTriggered = false;
      log("Demo Mode: BLE types · filter BLE · sort WOW — starting fresh wardrive…");
      renderDeviceList();
      await doStartScan({ clearResults: true });
    };
  }

  function showAttackReport(res) {
    const vectors = res.vectors || [];
    const target = res.target || {};
    const isWifi = (res.profile || "") === "wifi_ap" || (target.radio || "").toLowerCase() === "wifi";

    if (isWifi) {
      const inv = vectors.find((v) => v.name === "wifi_inventory");
      const tech = vectors.filter((v) => v.name !== "wifi_inventory");
      const classic = tech.filter((v) => (v.era || "") === "classic");
      const modern = tech.filter((v) => (v.era || "") !== "classic");
      const remediations = [
        ...new Set(tech.map((v) => v.remediation).filter(Boolean)),
      ].slice(0, 12);
      const high = tech.filter((v) =>
        ["critical", "high"].includes(String(v.severity || "").toLowerCase())
      );
      const renderGroup = (title, list) => {
        if (!list.length) return "";
        return `<div class="dive-section"><h4>${ICONS.shield} ${escapeHtml(title)}</h4>
          <div class="findings-list">${list
            .map((v) =>
              renderFindingCard({
                severity: v.severity || "medium",
                finding: v.finding || v.name,
                detail: [
                  typeof v.detail === "string" ? v.detail : "",
                  v.client_impact ? `Impact: ${v.client_impact}` : "",
                  v.hardware ? `Hardware (${v.hardware}): not executed` : "",
                ]
                  .filter(Boolean)
                  .join(" — "),
                evidence: v.evidence || null,
              })
            )
            .join("")}</div></div>`;
      };
      const html = `
        <div class="dive-report">
          <div class="dive-hero">
            <div class="dive-hero-main">
              <div class="dive-icon">${ICONS.wifi}</div>
              <div>
                <div class="dive-title">${escapeHtml(target.name || inv?.finding || "Wi‑Fi AP")}</div>
                <div class="dive-meta">${escapeHtml(target.mac || "")} · ${escapeHtml(
                  (target.metadata || {}).security || ""
                )} · ch ${escapeHtml(String((target.metadata || {}).channel ?? "?"))}</div>
              </div>
            </div>
            <span class="dive-sev risk-pill risk-${escapeHtml(
              (res.exploitability || "low").toLowerCase() === "high" ? "critical" : "medium"
            )}">${escapeHtml(res.exploitability || "?")}</span>
          </div>
          <p class="hint">${escapeHtml(
            res.note ||
              "Catalog-driven assessment from passive scan facts. Active exploits / Pineapple not executed."
          )}</p>
          ${
            inv
              ? `<div class="attack-hero-write">
                  <div class="attack-hero-title">${escapeHtml(inv.finding || "Inventory")}</div>
                  <div class="hint">${escapeHtml(inv.detail || "")}</div>
                  ${evidenceList(inv.evidence)}
                </div>`
              : ""
          }
          ${
            high.length
              ? `<div class="dive-section"><h4>${ICONS.alert} Priority findings</h4>
                  <div class="findings-list">${high
                    .map((v) =>
                      renderFindingCard({
                        severity: v.severity,
                        finding: v.finding || v.name,
                        detail: typeof v.detail === "string" ? v.detail : "",
                        evidence: v.evidence,
                      })
                    )
                    .join("")}</div></div>`
              : ""
          }
          ${renderGroup("Classic techniques", classic)}
          ${renderGroup("Modern techniques", modern)}
          ${
            remediations.length
              ? `<div class="dive-section"><h4>${ICONS.chip} Remediation checklist</h4>
                  <ul class="finding-evidence">${remediations
                    .map((r) => `<li><code>${escapeHtml(r)}</code></li>`)
                    .join("")}</ul></div>`
              : ""
          }
        </div>`;
      showModal("Wi‑Fi Attack report", html, {
        html: true,
        subtitle: res.attack_id || "",
        raw: res,
      });
      return;
    }

    const writeSurface = vectors.find((v) => v.name === "gatt_write_surface");
    const marker = vectors.filter((v) => v.name === "gatt_write_marker");
    const lanApi = vectors.find((v) => v.name === "samsung_lan_api" && v.success);
    const labKey = vectors.find((v) => v.name === "samsung_lab_key");
    const identity = vectors.find((v) => v.name === "samsung_mac_in_mfg" && v.success);
    const wowHits = vectors.filter((v) => v.wow || v.severity === "critical");
    const heroLan = lanApi
      ? `<div class="attack-hero-write">
          <div class="attack-hero-title">${escapeHtml(lanApi.finding || "Samsung LAN remote API")}</div>
          <div class="hint">${escapeHtml(
            labKey && labKey.success
              ? labKey.finding
              : labKey
                ? labKey.finding
                : "TV remote HTTP API reachable on lab LAN"
          )}</div>
        </div>`
      : "";
    const heroId = identity && !lanApi
      ? `<div class="attack-hero-write">
          <div class="attack-hero-title">${escapeHtml(identity.finding || "Samsung identity leak")}</div>
          <div class="hint">BD_ADDR embedded in manufacturer_data — passive re-ID</div>
        </div>`
      : "";
    const heroWrite = writeSurface
      ? `<div class="attack-hero-write">
          <div class="attack-hero-title">${escapeHtml(writeSurface.finding || "Writable GATT surface")}</div>
          <div class="hint">${escapeHtml(writeSurface.detail || "")}</div>
          ${evidenceList(writeSurface.evidence)}
        </div>`
      : "";
    const heroMarker = marker.length
      ? `<div class="dive-section"><h4>${ICONS.shield} Write probe</h4>
          <div class="findings-list">${marker
            .map((v) =>
              renderFindingCard({
                severity: v.success ? "critical" : "medium",
                finding: v.finding || (v.success ? "Marker write accepted" : "Write rejected"),
                detail: typeof v.detail === "string" ? v.detail : JSON.stringify(v.detail || {}),
                evidence: v.evidence || null,
              })
            )
            .join("")}</div></div>`
      : "";
    const html = `
      <div class="dive-report">
        <div class="dive-hero">
          <div class="dive-hero-main">
            <div class="dive-icon">${ICONS.alert}</div>
            <div>
              <div class="dive-title">Attack probe · ${escapeHtml(res.profile || "")}</div>
              <div class="dive-meta">${escapeHtml(res.attack_id || "")} · exploitability ${escapeHtml(res.exploitability || "?")}</div>
            </div>
          </div>
          <span class="dive-sev risk-pill risk-${escapeHtml((res.exploitability || "low").toLowerCase() === "high" || (res.exploitability || "").toLowerCase() === "critical" ? "critical" : "medium")}">${escapeHtml(res.exploitability || "?")}</span>
        </div>
        ${heroLan}
        ${heroId}
        ${heroWrite}
        ${heroMarker}
        ${wowHits.length && !writeSurface && !lanApi ? `<div class="dive-section"><h4>${ICONS.shield} WOW findings</h4>
          <div class="findings-list">${wowHits.map((v) => renderFindingCard({
            severity: v.severity || "high",
            finding: v.finding || v.name,
            detail: typeof v.detail === "string" ? v.detail : "",
            evidence: v.evidence || (Array.isArray(v.detail) ? v.detail : null),
          })).join("")}</div></div>` : ""}
        <div class="dive-section"><h4>${ICONS.chip} All vectors</h4>
          <div class="findings-list">${vectors.map((v) => renderFindingCard({
            severity: v.severity || (v.success ? "medium" : "low"),
            finding: `${v.name || ""}${v.wow ? " · WOW" : ""}`,
            detail: [v.finding, typeof v.detail === "string" ? v.detail : ""].filter(Boolean).join(" — "),
            evidence: v.evidence || (Array.isArray(v.detail) ? v.detail : null),
          })).join("") || '<div class="hint">No vectors</div>'}</div>
        </div>
      </div>`;
    showModal("Attack report", html, { html: true, subtitle: res.attack_id || "", raw: res });
  }

  async function runReplayAttack(d) {
    const isWifi = (d.radio || "").toLowerCase() === "wifi";
    log((isWifi ? "Wi‑Fi assess " : "Attack probe ") + (d.key || "") + "…");
    showModal(
      isWifi ? "Wi‑Fi assessment" : "Attack",
      `<div class="dive-loading"><div class="spinner"></div><p>${
        isWifi
          ? "Matching AP facts to Wi‑Fi technique catalog…"
          : "Running lab attack vectors…"
      }</p></div>`,
      { html: true, subtitle: deviceWow(d).headline || "" }
    );
    els.modalToggleRaw.classList.add("hidden");
    try {
      const res = await api("/api/attack", {
        method: "POST",
        body: JSON.stringify({ device: d }),
      });
      showAttackReport(res);
      log(
        `Attack done — ${res.exploitability || "?"} · ${(res.risk_summary || [])
          .slice(0, 2)
          .join("; ")}`
      );
      if (!isWifi) {
        const snap = await api("/api/tracker");
        setDevices(snap.devices || []);
      } else {
        renderDeviceList();
      }
    } catch (e) {
      showModal("Attack error", String(e));
      log("Attack ERROR: " + e);
    }
  }

  let replayTarget = null;
  let replayCaptureId = null;
  let replayBusy = false;

  function closeReplayModal() {
    els.replayModal.classList.add("hidden");
    replayBusy = false;
  }

  function setReplayStatus(html, cls) {
    const el = $("#replay-status");
    if (!el) return;
    el.className = "replay-status" + (cls ? " " + cls : "");
    el.innerHTML = html;
  }

  function openReplayModal(d) {
    replayTarget = d;
    replayCaptureId = null;
    const name = d.name || d.device_type_name || d.key || "device";
    const loc =
      d.mac ||
      (d.freq_mhz != null ? `${Number(d.freq_mhz).toFixed(3)} MHz` : "—");
    const radio = (d.radio || "?").toLowerCase();
    const isRf = radio !== "ble" && d.freq_mhz != null;

    els.replayTitle.textContent = "Replay lab";
    els.replaySubtitle.textContent = deviceWow(d).headline || "Authorized lab use only";
    els.btnReplayTx.disabled = true;
    els.btnReplayListen.disabled = !isRf;
    els.btnReplayListen.textContent = isRf ? "🎧 Escuchar (~12s)" : "🎧 Escuchar (RF only)";

    els.replayBody.innerHTML = `
      <p>Target: <strong>${escapeHtml(name)}</strong></p>
      <p class="confirm-count">${escapeHtml(String(loc))} · ${escapeHtml(radio.toUpperCase())}</p>
      ${
        isRf
          ? `<p class="hint">1) Pulsa <strong>Escuchar</strong> y, mientras captura, activa el mando/sensor.<br>
             2) Si oye ráfagas o decodifica frames, activa <strong>Replicar TX</strong>.</p>`
          : `<p class="hint">Este target es BLE — no hay listen/TX con HackRF. Usa el probe GATT o elige un mando RF.</p>`
      }
      <div id="replay-status" class="replay-status">Listo para escuchar.</div>
      ${
        isRf
          ? ""
          : `<p style="margin-top:0.75rem"><button type="button" class="btn btn-attack" id="btn-replay-probe">⚡ Probe GATT</button></p>`
      }
    `;

    const probeBtn = $("#btn-replay-probe");
    if (probeBtn) {
      probeBtn.onclick = () => {
        closeReplayModal();
        runReplayAttack(d);
      };
    }

    els.replayModal.classList.remove("hidden");
  }

  els.replayModal.querySelectorAll("[data-replay-dismiss]").forEach((el) => {
    el.onclick = () => {
      if (replayBusy) return;
      closeReplayModal();
    };
  });

  els.btnReplayListen.onclick = async () => {
    if (!replayTarget || replayBusy) return;
    if ((replayTarget.radio || "").toLowerCase() === "ble") {
      setReplayStatus("Replay listen is RF-only.", "fail");
      return;
    }
    replayBusy = true;
    replayCaptureId = null;
    els.btnReplayTx.disabled = true;
    els.btnReplayListen.disabled = true;
    setReplayStatus(
      `<div class="spinner" style="width:18px;height:18px;margin-bottom:0.5rem"></div>
       <strong>HackRF en escucha…</strong><br>
       Pulsa el mando ahora (${Number(replayTarget.freq_mhz).toFixed(3)} MHz).`,
      "listening"
    );
    log(`Listen @ ${replayTarget.freq_mhz} MHz…`);
    try {
      const res = await api("/api/replay/listen", {
        method: "POST",
        body: JSON.stringify({ device: replayTarget, duration_s: 12 }),
      });
      if (!res.ok) {
        setReplayStatus(escapeHtml(res.error || "Listen failed"), "fail");
        log("Listen failed: " + (res.error || ""));
        return;
      }
      replayCaptureId = res.capture_id;
      const a = res.analysis || {};
      const frames = res.decoded || [];
      const frameBits = frames
        .slice(0, 4)
        .map((f) => {
          const model = f.model || f.protocol || f.type || "frame";
          const id = f.id != null ? ` id=${f.id}` : "";
          return `<li>${escapeHtml(String(model))}${escapeHtml(id)}</li>`;
        })
        .join("");
          setReplayStatus(
            `<strong>${escapeHtml(res.message || "Capture done")}</strong>
         <div class="mono">${escapeHtml(res.capture_id)} · ${(res.iq_bytes / 1e6).toFixed(1)} MB IQ
         · energy ${a.energy_dbfs ?? "—"} dBFS · bursts ${a.burst_count ?? 0}
         · decoded ${res.decoded_count || 0}
         ${res.code_class?.class ? " · code " + escapeHtml(res.code_class.class) : ""}</div>
         ${frameBits ? `<ul>${frameBits}</ul>` : ""}
         <div class="mono" style="margin-top:0.4rem">${escapeHtml(a.note || "")}${
              res.code_class?.replay_advice
                ? " · " + escapeHtml(res.code_class.replay_advice)
                : ""
            }</div>`,
            res.replay_ready ? "ok" : "fail"
          );
      els.btnReplayTx.disabled = !res.replay_ready;
      log(
        `Listen ${res.capture_id}: ready=${res.replay_ready} bursts=${a.burst_count || 0} decoded=${res.decoded_count || 0}`
      );
    } catch (e) {
      setReplayStatus(escapeHtml(String(e)), "fail");
      log("Listen ERROR: " + e);
    } finally {
      replayBusy = false;
      els.btnReplayListen.disabled = false;
    }
  };

  els.btnReplayTx.onclick = () => {
    if (!replayCaptureId || replayBusy) return;
    if (!txArmed) {
      openConfirm({
        title: "TX is disarmed",
        subtitle: "Lab safety interlock",
        okLabel: "Arm TX now",
        bodyHtml: `<p>Debes <strong>armar TX</strong> antes de retransmitir (bandas 315/433/868, gain ≤20).</p>`,
        onOk: async () => {
          await setTxArmed(true);
          els.btnReplayTx.click();
        },
      });
      return;
    }
    const d = replayTarget;
    const freq = d?.freq_mhz != null ? Number(d.freq_mhz).toFixed(3) + " MHz" : "?";
    openConfirm({
      title: "Transmitir captura?",
      subtitle: "HackRF TX — authorized lab only",
      okLabel: "Sí, transmitir",
      bodyHtml: `
        <p>Vas a <strong>retransmitir</strong> la captura <span class="confirm-count">${escapeHtml(replayCaptureId)}</span> en ${escapeHtml(freq)}.</p>
        <p class="hint">Esto emite RF de verdad. Solo en lab autorizado.</p>`,
      onOk: async () => {
        replayBusy = true;
        els.btnReplayTx.disabled = true;
        const est = 8;
        setReplayStatus(
          `<strong>HackRF transmitting…</strong>
           <div class="clone-tx-progress active" style="display:block;margin-top:0.5rem">
             <div class="clone-tx-label" id="replay-tx-label">TX starting…</div>
             <div class="progress-wrap">
               <div class="progress-bar"><div id="replay-tx-fill" class="progress-fill" style="width:2%"></div></div>
               <span id="replay-tx-pct" class="progress-label">2%</span>
             </div>
           </div>`,
          "listening"
        );
        setTxLiveProgress(2, "TX starting…");
        log(`TX ${replayCaptureId}…`);
        const t0 = Date.now();
        const anim = setInterval(() => {
          const elapsed = (Date.now() - t0) / 1000;
          const pct = Math.min(92, 5 + (elapsed / est) * 87);
          const fill = $("#replay-tx-fill");
          const pctEl = $("#replay-tx-pct");
          const lab = $("#replay-tx-label");
          if (fill) fill.style.width = Math.round(pct) + "%";
          if (pctEl) pctEl.textContent = Math.round(pct) + "%";
          if (lab) lab.textContent = `Transmitting IQ… ${elapsed.toFixed(1)}s`;
          setTxLiveProgress(pct, `Transmitting IQ… ${elapsed.toFixed(1)}s`);
        }, 200);
        try {
          const res = await api("/api/replay/transmit", {
            method: "POST",
            body: JSON.stringify({
              capture_id: replayCaptureId,
              confirm: true,
              tx_gain: 20,
            }),
          });
          clearInterval(anim);
          setTxLiveProgress(100, res.ok ? "TX complete" : "TX failed");
          setReplayStatus(
            escapeHtml(res.message || (res.ok ? "TX done" : res.error || "TX failed")),
            res.ok ? "ok" : "fail"
          );
          log(res.ok ? `TX ok @ ${res.freq_mhz}` : `TX fail: ${res.error || res.message}`);
        } catch (e) {
          clearInterval(anim);
          setTxLiveProgress(100, "TX error");
          setReplayStatus(escapeHtml(String(e)), "fail");
          log("TX ERROR: " + e);
        } finally {
          clearInterval(anim);
          replayBusy = false;
          els.btnReplayTx.disabled = !replayCaptureId;
          setTimeout(hideTxLiveProgress, 2500);
        }
      },
    });
  };

  if (els.btnReplay) {
    els.btnReplay.onclick = () => {
      const d = focusedKey ? devicesByKey[focusedKey] : null;
      if (!d) return;
      const radio = (d.radio || "").toLowerCase();
      if (radio === "ble" || radio === "wifi") {
        runReplayAttack(d);
        return;
      }
      openReplayModal(d);
    };
  }

  /* ── RF CLONE modal ───────────────────────────────────────── */
  let clonePresets = [];
  let clonePreset = null;
  let cloneTuneMhz = null; // optional override from Find freq
  let cloneCaptureId = null;
  let cloneCaptureMeta = null; // last listen result (duration / bytes)
  let cloneBusy = false;
  let cloneLive = false;
  let cloneLiveTimer = null;
  let cloneTxAnim = null;

  function setCloneStatus(html, cls) {
    if (!els.cloneStatus) return;
    els.cloneStatus.className = "replay-status" + (cls ? " " + cls : "");
    els.cloneStatus.innerHTML = html;
  }

  function setCloneTxProgress(pct, label) {
    const wrap = els.cloneTxProgress;
    if (wrap) {
      const p = Math.max(0, Math.min(100, Math.round(pct)));
      wrap.classList.add("active");
      if (els.cloneTxFill) els.cloneTxFill.style.width = p + "%";
      if (els.cloneTxPct) els.cloneTxPct.textContent = p + "%";
      if (els.cloneTxLabel) els.cloneTxLabel.textContent = label || `Transmitting… ${p}%`;
    }
    setTxLiveProgress(pct, label);
  }

  function setTxLiveProgress(pct, label) {
    const overlay = els.txLiveOverlay;
    if (!overlay) return;
    const p = Math.max(0, Math.min(100, Math.round(pct)));
    overlay.classList.remove("hidden");
    overlay.setAttribute("aria-hidden", "false");
    if (els.txLiveFill) els.txLiveFill.style.width = p + "%";
    if (els.txLivePct) els.txLivePct.textContent = p + "%";
    if (els.txLiveLabel) els.txLiveLabel.textContent = label || `Transmitting… ${p}%`;
  }

  function hideTxLiveProgress() {
    if (!els.txLiveOverlay) return;
    els.txLiveOverlay.classList.add("hidden");
    els.txLiveOverlay.setAttribute("aria-hidden", "true");
    if (els.txLiveFill) els.txLiveFill.style.width = "0%";
    if (els.txLivePct) els.txLivePct.textContent = "0%";
  }

  function hideCloneTxProgress() {
    if (els.cloneTxProgress) els.cloneTxProgress.classList.remove("active");
    if (els.cloneTxFill) els.cloneTxFill.style.width = "0%";
    if (els.cloneTxPct) els.cloneTxPct.textContent = "0%";
    hideTxLiveProgress();
  }

  function stopCloneTxAnim() {
    if (cloneTxAnim) {
      clearInterval(cloneTxAnim);
      cloneTxAnim = null;
    }
  }

  function estimateTxSeconds(meta) {
    if (!meta) return 8;
    const repeats = Math.max(1, Number(els.cloneTxRepeats?.value || 1));
    const src = els.cloneTxSource?.value || "burst";
    const rate = Number(meta.sample_rate) || 2e6;
    let bytes = Number(meta.iq_bytes) || 0;
    if (src === "best" && meta.iq_best_bytes) bytes = Number(meta.iq_best_bytes);
    else if (src === "burst" && meta.iq_burst_bytes) bytes = Number(meta.iq_burst_bytes);
    else if (src === "burst" && meta.duration_s) {
      // burst is usually shorter than full; estimate ~70%
      return Math.max(2, Number(meta.duration_s) * 0.7) * repeats;
    }
    if (bytes > 1000) return Math.max(2, Math.min(90, (bytes / (rate * 2)) * repeats));
    if (meta.duration_s) return Math.max(2, Number(meta.duration_s)) * repeats;
    return 8 * repeats;
  }

  async function runCloneTransmit() {
    if (!cloneCaptureId) return;
    stopCloneTxAnim();
    cloneBusy = true;
    if (els.btnCloneTx) els.btnCloneTx.disabled = true;
    if (els.btnCloneRecord) els.btnCloneRecord.disabled = true;
    if (els.btnCloneLive) els.btnCloneLive.disabled = true;

    const iqSource = els.cloneTxSource?.value || "burst";
    const repeats = Math.max(1, Math.min(5, Number(els.cloneTxRepeats?.value || 3)));
    const est = estimateTxSeconds(cloneCaptureMeta);
    const freq =
      clonePreset && clonePreset.center_mhz != null
        ? Number(clonePreset.center_mhz).toFixed(3)
        : cloneCaptureMeta?.freq_mhz != null
          ? Number(cloneCaptureMeta.freq_mhz).toFixed(3)
          : "?";

    setCloneStatus(
      `<strong>HackRF transmitting</strong> · ${escapeHtml(String(cloneCaptureId))} @ ${escapeHtml(freq)} MHz<br>
       <span class="hint">${escapeHtml(iqSource)} IQ ×${repeats} — keep confirm closed; watch the bar.</span>`,
      "listening"
    );
    setCloneTxProgress(2, `TX starting @ ${freq} MHz…`);
    log(`CLONE TX ${cloneCaptureId} ${iqSource}×${repeats} (~${est.toFixed(1)}s est)…`);

    const t0 = Date.now();
    cloneTxAnim = setInterval(() => {
      const elapsed = (Date.now() - t0) / 1000;
      // Ease toward ~92% until API returns
      const pct = Math.min(92, 5 + (elapsed / est) * 87);
      setCloneTxProgress(pct, `Transmitting IQ… ${elapsed.toFixed(1)}s / ~${est.toFixed(0)}s`);
    }, 200);

    try {
      const res = await api("/api/replay/transmit", {
        method: "POST",
        body: JSON.stringify({
          capture_id: cloneCaptureId,
          confirm: true,
          tx_gain: 20,
          iq_source: iqSource,
          repeats,
        }),
      });
      stopCloneTxAnim();
      setCloneTxProgress(100, res.ok ? "TX complete" : "TX failed");
      setCloneStatus(
        escapeHtml(res.message || (res.ok ? "TX done" : res.error || "TX failed")),
        res.ok ? "ok" : "fail"
      );
      log(res.ok ? `CLONE TX ok @ ${res.freq_mhz}` : `CLONE TX fail: ${res.error || res.message}`);
    } catch (e) {
      stopCloneTxAnim();
      setCloneTxProgress(100, "TX error");
      setCloneStatus(escapeHtml(String(e)), "fail");
      log("CLONE TX ERROR: " + e);
    } finally {
      stopCloneTxAnim();
      cloneBusy = false;
      if (els.btnCloneTx) els.btnCloneTx.disabled = !cloneCaptureId;
      if (els.btnCloneRecord) els.btnCloneRecord.disabled = !clonePreset;
      if (els.btnCloneLive) els.btnCloneLive.disabled = false;
      setTimeout(hideCloneTxProgress, 2500);
    }
  }

  function drawCloneSpectrum(bins, peak, noise) {
    const canvas = els.cloneSpectrum;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    const w = canvas.width;
    const h = canvas.height;
    ctx.clearRect(0, 0, w, h);
    ctx.fillStyle = "#0a1218";
    ctx.fillRect(0, 0, w, h);
    const floor = noise != null ? noise - 5 : -90;
    const ceil = peak != null ? Math.max(peak + 3, floor + 20) : -20;
    const list = bins || [];
    if (!list.length) {
      ctx.fillStyle = "#5a6a78";
      ctx.font = "14px JetBrains Mono, monospace";
      ctx.fillText("Waiting for sweep…", 16, h / 2);
      return;
    }
    const barW = Math.max(2, (w - 8) / list.length - 1);
    list.forEach((b, i) => {
      const p = Number(b.power_dbm);
      const t = (p - floor) / (ceil - floor);
      const bh = Math.max(1, Math.min(1, t) * (h - 12));
      const x = 4 + i * (barW + 1);
      const hot = peak != null && p >= peak - 1.5;
      ctx.fillStyle = hot ? "#14b8a6" : "#3b82f6";
      ctx.fillRect(x, h - 6 - bh, barW, bh);
    });
    if (els.clonePeak) {
      els.clonePeak.textContent = `peak ${peak != null ? peak + " dBm" : "—"} · noise ${
        noise != null ? noise + " dBm" : "—"
      } · ${list.length} bins`;
    }
  }

  function cloneCenterMhz() {
    if (cloneTuneMhz != null && Number.isFinite(Number(cloneTuneMhz))) {
      return Number(cloneTuneMhz);
    }
    return clonePreset ? Number(clonePreset.center_mhz) : null;
  }

  /** Lab TX bands — keep UI lock inside allowlist (snap GSM clutter → 868.35). */
  function snapLabMhz(mhz) {
    const f = Number(mhz);
    if (!Number.isFinite(f)) return null;
    if (f >= 240 && f <= 360) return f;
    if (f >= 420 && f <= 450) return f;
    if (f >= 863 && f <= 870) return f;
    if (f > 870 && f <= 915) return 868.35; // GSM next to 868
    const centers = [315, 330, 433.92, 868.35];
    let best = centers[0];
    let bestD = Math.abs(f - best);
    for (const c of centers) {
      const d = Math.abs(f - c);
      if (d < bestD) {
        best = c;
        bestD = d;
      }
    }
    return bestD <= 20 ? best : null;
  }

  function lockCloneTune(mhz, note) {
    const snapped = snapLabMhz(mhz);
    if (snapped == null) {
      setCloneStatus(
        `Rejected ${Number(mhz).toFixed(1)} MHz — outside lab TX bands (315/433/868).`,
        "fail"
      );
      return false;
    }
    const was = Number(mhz);
    cloneTuneMhz = snapped;
    if (snapped >= 863) {
      const p = clonePresets.find((x) => x.id === "garage_868");
      if (p) clonePreset = p;
    } else if (snapped >= 420 && snapped <= 450) {
      const p = clonePresets.find((x) => x.id === "garage_433");
      if (p && (!clonePreset || clonePreset.icon === "gate")) clonePreset = p;
    }
    renderClonePresets();
    refreshCloneFreqLabel();
    const snapNote =
      Math.abs(was - snapped) > 0.05
        ? ` (snapped from ${was.toFixed(1)} MHz clutter)`
        : "";
    setCloneStatus(
      note ||
        `Locked <strong>${snapped.toFixed(3)} MHz</strong>${snapNote} — Live / Record when ready.`,
      "ok"
    );
    return true;
  }

  function refreshCloneFreqLabel() {
    if (!els.cloneFreq || !clonePreset) return;
    const c = cloneCenterMhz();
    const tuned = cloneTuneMhz != null;
    els.cloneFreq.textContent = `${Number(c).toFixed(3)} MHz · span ~${clonePreset.span_mhz || 10} MHz${
      tuned ? " · locked from Find" : ""
    }`;
  }

  function renderClonePresets() {
    if (!els.clonePresets) return;
    els.clonePresets.innerHTML = clonePresets
      .map((p) => {
        const icon = ICONS[p.icon] || ICONS.rf;
        const active = clonePreset && clonePreset.id === p.id ? " active" : "";
        return `<button type="button" class="clone-preset${active}" data-clone-id="${escapeHtml(p.id)}" role="option" aria-selected="${active ? "true" : "false"}">
          ${icon}
          <span>${escapeHtml(p.label)}</span>
        </button>`;
      })
      .join("");
    els.clonePresets.querySelectorAll("[data-clone-id]").forEach((btn) => {
      btn.onclick = () => selectClonePreset(btn.getAttribute("data-clone-id"));
    });
  }

  function selectClonePreset(id) {
    clonePreset = clonePresets.find((p) => p.id === id) || null;
    cloneTuneMhz = null;
    cloneCaptureId = null;
    cloneCaptureMeta = null;
    hideCloneTxProgress();
    if (els.btnCloneTx) els.btnCloneTx.disabled = true;
    if (els.btnCloneRecord) els.btnCloneRecord.disabled = !clonePreset;
    renderClonePresets();
    refreshCloneFreqLabel();
    setCloneStatus(
      clonePreset
        ? `Preset <strong>${escapeHtml(clonePreset.label)}</strong> — if Live stays flat, press <strong>Find freq</strong> while holding the button (many EU gates are 868).`
        : "Select an icon."
    );
    if (cloneLive) pollCloneSpectrum();
  }

  async function ensureClonePresets() {
    if (clonePresets.length) return;
    const res = await api("/api/clone/presets");
    clonePresets = res.presets || [];
    renderClonePresets();
  }

  async function pollCloneSpectrum() {
    if (!cloneLive || !clonePreset || cloneBusy) return;
    const center = cloneCenterMhz();
    try {
      const res = await api("/api/clone/spectrum", {
        method: "POST",
        body: JSON.stringify(
          cloneTuneMhz != null
            ? { freq_mhz: center, span_mhz: clonePreset.span_mhz || 10 }
            : { preset_id: clonePreset.id }
        ),
      });
      if (!res.ok) {
        setCloneStatus(escapeHtml(res.error || "Spectrum failed"), "fail");
        stopCloneLive();
        return;
      }
      drawCloneSpectrum(res.bins || [], res.peak_dbm, res.noise_dbm);
    } catch (e) {
      setCloneStatus(escapeHtml(String(e)), "fail");
      stopCloneLive();
    }
  }

  function startCloneLive() {
    if (!clonePreset) {
      setCloneStatus("Pick a preset first.", "fail");
      return;
    }
    cloneLive = true;
    if (els.btnCloneLive) {
      els.btnCloneLive.textContent = "■ Stop live";
      els.btnCloneLive.classList.add("btn-danger");
    }
    const c = cloneCenterMhz();
    setCloneStatus(
      `<strong>Live</strong> @ ${Number(c).toFixed(3)} MHz — press the remote and watch the peak.<br>
       <span class="hint">Flat peak? Use Find freq (315 / 433 / 868 hunt). Stop wardrive if HackRF is busy.</span>`,
      "listening"
    );
    pollCloneSpectrum();
    if (cloneLiveTimer) clearInterval(cloneLiveTimer);
    cloneLiveTimer = setInterval(pollCloneSpectrum, 900);
  }

  function stopCloneLive() {
    cloneLive = false;
    if (cloneLiveTimer) {
      clearInterval(cloneLiveTimer);
      cloneLiveTimer = null;
    }
    if (els.btnCloneLive) {
      els.btnCloneLive.textContent = "Live";
      els.btnCloneLive.classList.remove("btn-danger");
    }
  }

  function closeCloneModal() {
    stopCloneLive();
    if (els.cloneModal) els.cloneModal.classList.add("hidden");
  }

  async function openCloneModal() {
    cloneCaptureId = null;
    cloneCaptureMeta = null;
    hideCloneTxProgress();
    if (els.btnCloneTx) els.btnCloneTx.disabled = true;
    await ensureClonePresets();
    if (!clonePreset && clonePresets[0]) selectClonePreset(clonePresets[0].id);
    else renderClonePresets();
    drawCloneSpectrum([], null, null);
    setCloneStatus("Authorized lab use only · stop wardrive if HackRF is busy · Arm TX before replay.");
    if (els.cloneModal) els.cloneModal.classList.remove("hidden");
  }

  if (els.btnRfClone) {
    els.btnRfClone.onclick = () => openCloneModal();
  }
  if (els.cloneModal) {
    els.cloneModal.querySelectorAll("[data-clone-dismiss]").forEach((el) => {
      el.onclick = () => {
        if (cloneBusy) return;
        closeCloneModal();
      };
    });
  }
  if (els.btnCloneLive) {
    els.btnCloneLive.onclick = () => {
      if (cloneBusy) return;
      if (cloneLive) {
        stopCloneLive();
        setCloneStatus("Live stopped.");
      } else {
        startCloneLive();
      }
    };
  }
  if (els.btnCloneCompare) {
    els.btnCloneCompare.onclick = async () => {
      if (cloneBusy) return;
      const center = cloneCenterMhz();
      const lo = center != null ? center - 20 : 280;
      const hi = center != null ? center + 20 : 320;
      setCloneStatus(`Comparing CAPs in ${lo.toFixed(0)}–${hi.toFixed(0)} MHz…`, "listening");
      try {
        const res = await api(
          `/api/replay/compare?lo_mhz=${encodeURIComponent(lo)}&hi_mhz=${encodeURIComponent(hi)}&limit=20`
        );
        if (!res.ok) {
          setCloneStatus(escapeHtml(res.error || "Compare failed"), "fail");
          return;
        }
        const rows = (res.captures || [])
          .map((c) => {
            const top = (c.top && c.top[0]) || null;
            const mark =
              c.strength === "strong" ? "●" : c.strength === "ok" ? "◐" : "○";
            const hx = top ? top.hex : "—";
            const n = top ? `×${top.count}` : "";
            return `<div class="mono">${mark} ${escapeHtml(c.capture_id)} · ${c.strength} · peak ${c.peak_dbfs} dB · ${escapeHtml(String(hx))} ${n}</div>`;
          })
          .join("");
        const cons = res.consensus
          ? `<div class="mono" style="margin-top:0.35rem"><strong>Consensus</strong> ${escapeHtml(
              res.consensus.hex
            )} in ${res.consensus.cap_count} CAP(s)</div>`
          : "";
        setCloneStatus(
          `<strong>Compare</strong> · strong ${res.strong_count || 0} · weak ${res.weak_count || 0}
           <div class="hint" style="margin:0.35rem 0">${escapeHtml(res.note || "")}</div>
           ${cons}
           <div style="margin-top:0.4rem;max-height:10rem;overflow:auto">${rows || "<div class='hint'>No CAPs</div>"}</div>
           <div class="hint" style="margin-top:0.35rem">● strong = use for TX · ○ weak = mando flojo / ignora</div>`,
          res.strong_count > 0 ? "ok" : "listening"
        );
        log(`CLONE compare: strong=${res.strong_count} weak=${res.weak_count} consensus=${res.consensus?.hex || "—"}`);
      } catch (e) {
        setCloneStatus(escapeHtml(String(e)), "fail");
      }
    };
  }
  if (els.btnCloneHunt) {
    els.btnCloneHunt.onclick = async () => {
      if (cloneBusy) return;
      stopCloneLive();
      cloneBusy = true;
      if (els.btnCloneHunt) els.btnCloneHunt.disabled = true;
      if (els.btnCloneRecord) els.btnCloneRecord.disabled = true;
      if (els.btnCloneLive) els.btnCloneLive.disabled = true;
      setCloneStatus(
        `<div class="spinner" style="width:18px;height:18px;margin-bottom:0.5rem"></div>
         <strong>Finding frequency (~8s)…</strong><br>
         Hold / mash the garage remote button now. Hunting 315 · 433 · 868.`,
        "listening"
      );
      log("CLONE hunt start…");
      try {
        const res = await api("/api/clone/hunt", {
          method: "POST",
          body: JSON.stringify({ hold_s: 8 }),
        });
        if (!res.ok) {
          setCloneStatus(escapeHtml(res.error || "Hunt failed"), "fail");
          return;
        }
        const best = res.best;
        const cands = res.candidates || [];
        if (!best) {
          setCloneStatus(
            escapeHtml(res.note || "No peak found") +
              `<div class="hint">Try closer to the antenna, fresh battery, or check if the remote is 40 MHz / other (outside lab allowlist).</div>`,
            "fail"
          );
          log("CLONE hunt: no peak");
          return;
        }
        if (res.suggested_preset) {
          const p = clonePresets.find((x) => x.id === res.suggested_preset);
          if (p) clonePreset = p;
        } else if (!clonePreset) {
          clonePreset = clonePresets.find((x) => x.id === "garage_433") || clonePresets[0];
        }
        if (!lockCloneTune(best.freq_mhz, null)) return;
        const list = cands
          .slice(0, 5)
          .map(
            (c) =>
              `<button type="button" class="btn btn-ghost" data-hunt-mhz="${c.freq_mhz}">${Number(
                c.freq_mhz
              ).toFixed(3)} (${c.snr_db >= 0 ? "+" : ""}${c.snr_db} dB)</button>`
          )
          .join(" ");
        setCloneStatus(
          `<strong>Found ${Number(cloneTuneMhz).toFixed(3)} MHz</strong> · SNR ${best.snr_db} dB${
            best.snapped_from_mhz
              ? ` <span class="hint">(was ${Number(best.snapped_from_mhz).toFixed(1)} clutter)</span>`
              : ""
          }<br>
           <span class="hint">${escapeHtml(res.note || "")}</span>
           <div style="margin-top:0.45rem;display:flex;flex-wrap:wrap;gap:0.35rem">${list}</div>
           <div class="hint" style="margin-top:0.35rem">Locked — run Live to confirm the peak, then Record. TX only on 315/433/868.</div>`,
          "ok"
        );
        els.cloneStatus.querySelectorAll("[data-hunt-mhz]").forEach((btn) => {
          btn.onclick = () => lockCloneTune(btn.getAttribute("data-hunt-mhz"));
        });
        log(`CLONE hunt best=${cloneTuneMhz} SNR=${best.snr_db}`);
      } catch (e) {
        setCloneStatus(escapeHtml(String(e)), "fail");
        log("CLONE hunt ERROR: " + e);
      } finally {
        cloneBusy = false;
        if (els.btnCloneHunt) els.btnCloneHunt.disabled = false;
        if (els.btnCloneLive) els.btnCloneLive.disabled = false;
        if (els.btnCloneRecord) els.btnCloneRecord.disabled = !clonePreset;
      }
    };
  }
  if (els.btnCloneRecord) {
    els.btnCloneRecord.onclick = async () => {
      if (!clonePreset || cloneBusy) return;
      stopCloneLive();
      cloneBusy = true;
      cloneCaptureId = null;
      if (els.btnCloneTx) els.btnCloneTx.disabled = true;
      if (els.btnCloneRecord) els.btnCloneRecord.disabled = true;
      const center = cloneCenterMhz();
      const duration_s = Math.max(4, Math.min(30, Number(els.cloneRecordDur?.value || 8)));
      const device = {
        radio: "hackrf",
        freq_mhz: center,
        name: clonePreset.label,
        device_type_id: clonePreset.device_type_id || clonePreset.id,
        device_type_name: clonePreset.label,
        key: `clone:${clonePreset.id}`,
        metadata: {
          attack_profile: clonePreset.attack_profile,
          clone_preset: clonePreset.id,
          code_hint: clonePreset.code_hint,
          clone_note: clonePreset.note,
          tune_mhz: center,
        },
      };
      setCloneStatus(
        `<div class="spinner" style="width:18px;height:18px;margin-bottom:0.5rem"></div>
         <strong>Recording IQ (~${duration_s}s)…</strong><br>
         Tap the remote 2–3 times now (${Number(center).toFixed(3)} MHz). Keep antenna away if peak clips.`,
        "listening"
      );
      log(`RF CLONE listen @ ${center} MHz × ${duration_s}s…`);
      try {
        const res = await api("/api/replay/listen", {
          method: "POST",
          body: JSON.stringify({
            device,
            duration_s,
            lna_db: 24,
            vga_db: 28,
          }),
        });
        if (!res.ok) {
          setCloneStatus(escapeHtml(res.error || "Listen failed"), "fail");
          log("CLONE listen failed: " + (res.error || ""));
          return;
        }
        cloneCaptureId = res.capture_id;
        cloneCaptureMeta = {
          capture_id: res.capture_id,
          duration_s: res.duration_s,
          sample_rate: res.sample_rate,
          iq_bytes: res.iq_bytes,
          freq_mhz: res.freq_mhz,
          tx_freq_mhz: res.tx_freq_mhz,
          freq_offset_hz: res.freq_offset_hz,
          iq_burst_file: res.iq_burst_file,
          iq_best_file: res.iq_best_file,
          iq_burst_bytes: res.analysis?.burst_bytes,
        };
        const a = res.analysis || {};
        const off = res.freq_offset_hz;
        const tune =
          res.tx_freq_mhz != null
            ? Number(res.tx_freq_mhz).toFixed(6)
            : Number(res.freq_mhz).toFixed(3);
        const wavHref = res.wav_am_file
          ? `/api/artifact/${encodeURIComponent(res.capture_id)}/listen_am.wav`
          : "";
        const rolling =
          res.code_class?.class === "rolling" || res.code_class?.class === "likely_rolling";
        const pwm = res.pwm_decode || {};
        const pwmLine =
          pwm.hex
            ? `<div class="mono">PWM ${escapeHtml(String(pwm.hex))} · ${escapeHtml(
                String(pwm.bits || "")
              )} · ×${pwm.repeat_count ?? "?"} · ${pwm.short_on_ms ?? "?"}ms/${pwm.long_on_ms ?? "?"}ms</div>`
            : "";
        const clipWarn = a.clipped
          ? `<div class="hint" style="color:var(--warning);margin-top:0.35rem">IQ clipped (${Math.round(
              (a.clip_frac || 0) * 100
            )}%) — move remote farther / use 5s taps and re-record before TX.</div>`
          : "";
        setCloneStatus(
          `<strong>${escapeHtml(res.message || "Capture done")}</strong>
           <div class="mono">${escapeHtml(res.capture_id)} · ${((res.iq_bytes || 0) / 1e6).toFixed(1)} MB
           · bursts ${a.burst_count ?? 0} · presses ${a.press_count ?? "—"}
           · decoded ${res.decoded_count || 0}
           ${a.burst_trimmed ? " · trimmed TX IQ" : ""}
           ${res.iq_best_file ? " · best-press IQ" : ""}
           ${res.code_class?.class ? " · code " + escapeHtml(res.code_class.class) : ""}</div>
           ${pwmLine}
           <div class="mono">TX @ ${escapeHtml(tune)} MHz${
             off != null && Math.abs(Number(off)) >= 2000
               ? ` (offset ${Number(off) >= 0 ? "+" : ""}${(Number(off) / 1000).toFixed(1)} kHz)`
               : ""
           }</div>
           ${clipWarn}
           ${
             rolling
               ? `<div class="hint" style="color:var(--warning);margin-top:0.35rem">Rolling / car key — IQ replay almost never unlocks (Hitag AES). Prove the path with a fixed garage remote; for RF check, capture out of car range then TX once.</div>`
               : ""
           }
           ${
             (a.burst_count || 0) === 0
               ? `<div class="hint" style="color:var(--warning);margin-top:0.35rem">No bursts — wrong frequency or weak signal. Run <strong>Find freq</strong> while pressing.</div>`
               : ""
           }
           ${
             wavHref
               ? `<div style="margin-top:0.4rem"><a class="btn btn-ghost" href="${wavHref}" target="_blank" rel="noopener">Open AM WAV</a>
                  <span class="hint"> · Audacity / waveform view</span></div>`
               : ""
           }
           <div class="mono">${escapeHtml(a.note || "")}${
             res.code_class?.replay_advice ? " · " + escapeHtml(res.code_class.replay_advice) : ""
           }</div>`,
          res.replay_ready ? (rolling ? "listening" : "ok") : "fail"
        );
        if (els.btnCloneTx) els.btnCloneTx.disabled = !res.replay_ready;
        log(
          `CLONE ${res.capture_id}: ready=${res.replay_ready} bursts=${a.burst_count || 0} tx@${tune} clip=${a.clipped}`
        );
      } catch (e) {
        setCloneStatus(escapeHtml(String(e)), "fail");
        log("CLONE listen ERROR: " + e);
      } finally {
        cloneBusy = false;
        if (els.btnCloneRecord) els.btnCloneRecord.disabled = !clonePreset;
      }
    };
  }
  if (els.btnCloneTx) {
    els.btnCloneTx.onclick = () => {
      if (!cloneCaptureId || cloneBusy) return;
      if (!txArmed) {
        openConfirm({
          title: "TX is disarmed",
          subtitle: "Lab safety interlock",
          okLabel: "Arm TX now",
          bodyHtml: `<p>You must <strong>arm TX</strong> before retransmitting (315/433/868 bands, gain ≤20).</p>`,
          onOk: async () => {
            await setTxArmed(true);
            els.btnCloneTx.click();
          },
        });
        return;
      }
      const freq = clonePreset
        ? Number(clonePreset.center_mhz).toFixed(3) + " MHz"
        : "?";
      const tune =
        cloneCaptureMeta?.tx_freq_mhz != null
          ? Number(cloneCaptureMeta.tx_freq_mhz).toFixed(6) + " MHz"
          : freq;
      openConfirm({
        title: "Transmit capture?",
        subtitle: "HackRF TX — authorized lab only",
        okLabel: "Yes, transmit",
        bodyHtml: `
          <p>You are about to <strong>retransmit</strong> <span class="confirm-count">${escapeHtml(cloneCaptureId)}</span> on ${escapeHtml(tune)}.</p>
          <p class="hint">Uses best-press IQ + freq correction when available. Progress shows in the RF CLONE panel / TX overlay.</p>
          <p class="hint">Car keys with rolling codes usually will not unlock — this validates RF emission in lab.</p>`,
        onOk: () => runCloneTransmit(),
      });
    };
  }

  els.btnMonitor.onclick = async () => {
    const d = focusedKey ? devicesByKey[focusedKey] : null;
    if (!d) return;
    if (monitoring) {
      await api("/api/monitor/stop", { method: "POST" });
      monitoring = false;
      lastSample = null;
      syncStopButton();
      log("Monitor stopped.");
      renderFocus(d);
      return;
    }
    const res = await api("/api/monitor/start", {
      method: "POST",
      body: JSON.stringify({ device: d }),
    });
    if (res.ok === false) {
      log("Monitor failed: " + (res.error || ""));
      return;
    }
    monitoring = true;
    syncStopButton();
    log("Monitoring " + (d.key || ""));
    renderFocus(d);
  };

  els.btnDive.onclick = async () => {
    const d = focusedKey ? devicesByKey[focusedKey] : null;
    if (!d) return;
    await runFpvOrDive(d);
  };

  if (els.btnFpvDecode) {
    els.btnFpvDecode.onclick = async () => {
      const d = focusedKey ? devicesByKey[focusedKey] : null;
      if (!d) return;
      await runFpvOrDive(d);
    };
  }

  els.btnJson.onclick = () => {
    const d = focusedKey ? devicesByKey[focusedKey] : null;
    if (!d) return;
    // lightweight device card instead of raw dump
    const meta = d.metadata || {};
    const rows = [
      ["Name", d.name || d.device_type_name],
      ["Key", d.key],
      ["Loc", locText(d)],
      ["Radio", (d.radio || "").toUpperCase()],
      ["Signal", strengthText(d)],
      ["Severity", deviceSev(d)],
      ["Profile", meta.attack_profile],
      ["Hits", d.hit_count],
      ["First seen", d.first_seen],
      ["Last seen", d.last_seen],
    ].filter(([, v]) => v != null && v !== "");
    const html = `<div class="dive-report">
      <div class="dive-section"><h4>${ICONS.chip} Device</h4>
      <dl class="meta-table">${rows
        .map(([k, v]) => `<dt>${escapeHtml(k)}</dt><dd>${escapeHtml(String(v))}</dd>`)
        .join("")}</dl></div>
      ${svgHistoryChart(d.signal_history) || ""}
      ${d.risk ? `<div class="dive-section"><h4>${ICONS.shield} Risk</h4>${renderFindings(enrichRiskFromBle(d.risk, d.risk.gatt_snapshot))}</div>` : ""}
    </div>`;
    showModal("Device details", html, { html: true, subtitle: d.key || "", raw: d });
  };

  els.modalToggleRaw.onclick = () => {
    if (!modalRawPayload) return;
    modalShowingRaw = !modalShowingRaw;
    if (modalShowingRaw) {
      els.modalBody.classList.add("raw");
      els.modalBody.textContent = JSON.stringify(modalRawPayload, null, 2);
      els.modalToggleRaw.textContent = "Report view";
    } else if (modalRawPayload.dive_id || modalRawPayload.analysis) {
      showDiveReport(modalRawPayload);
    } else {
      // re-open device card
      focusedKey = modalRawPayload.key || focusedKey;
      els.btnJson.onclick();
    }
  };

  $("#modal-close").onclick = () => els.modal.classList.add("hidden");
  $(".modal-backdrop").onclick = () => els.modal.classList.add("hidden");

  async function setTxArmed(armed) {
    const res = await api("/api/tx/arm", {
      method: "POST",
      body: JSON.stringify({
        armed: !!armed,
        note: armed ? "UI arm for lab demo" : "UI disarm",
      }),
    });
    txArmed = !!(res.armed ?? armed);
    refreshTxArmUi();
    log(txArmed ? "TX ARMED — replay transmit enabled" : "TX disarmed");
  }

  function refreshTxArmUi() {
    if (!els.btnTxArm) return;
    els.btnTxArm.textContent = txArmed ? "🔓 TX ARMED" : "🔒 TX disarmed";
    els.btnTxArm.classList.toggle("btn-attack", txArmed);
    if (els.txArmHint) {
      els.txArmHint.textContent = txArmed
        ? "TX armed — Replay transmit allowed on 315/433/868 (gain ≤20)."
        : "Arm TX before Replay transmit (315/433/868 only).";
    }
  }

  if (els.btnTxArm) {
    els.btnTxArm.onclick = () => setTxArmed(!txArmed);
  }
  if (els.btnExportCsv) {
    els.btnExportCsv.onclick = () => {
      window.open("/api/export/devices.csv", "_blank");
      log("Export CSV…");
    };
  }
  if (els.btnExportJson) {
    els.btnExportJson.onclick = async () => {
      const data = await api("/api/export/devices.json");
      showModal("Export JSON", data, { subtitle: `${data.count || 0} device(s)`, raw: data });
      log(`Export JSON — ${data.count || 0} device(s)`);
    };
  }
  if (els.btnCaptures) {
    els.btnCaptures.onclick = async () => {
      const res = await api("/api/captures?limit=30");
      const rows = res.captures || [];
      const html = `<div class="dive-section"><h4>${ICONS.chip} Capture library</h4>
        <div class="findings-list">${
          rows
            .map(
              (c) => `<div class="finding">
            <span class="finding-sev risk-pill risk-medium">${escapeHtml(c.kind)}</span>
            <div>
              <div class="finding-title">${escapeHtml(c.id)}</div>
              <div class="finding-detail">${escapeHtml(c.mtime_iso || "")} · ${(
                (c.size_bytes || 0) / 1e6
              ).toFixed(2)} MB
              ${
                c.summary && c.summary.message
                  ? " · " + escapeHtml(String(c.summary.message))
                  : ""
              }</div>
            </div>
          </div>`
            )
            .join("") || '<div class="hint">No captures yet</div>'
        }</div></div>`;
      showModal("Captures", html, { html: true, raw: res });
    };
  }

  bindFilters();
  loadCatalog().then(async () => {
    try {
      const tx = await api("/api/tx/status");
      txArmed = !!tx.armed;
      refreshTxArmUi();
    } catch (_) {}
    await loadGpsTrail();
    pollStatus();
  });
  loadHealth();
  connectWs();
  setInterval(loadHealth, 5000);
  syncStopButton();
})();
