"""RF Hunter v2 TUI — wardriving panel with live signal bars (authorized lab use)."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

os.environ.setdefault(
    "RF_HUNTER_CAPTURES",
    str(ROOT.parent / "captures" / "rf-hunter-v2"),
)
os.environ.setdefault(
    "RF_HUNTER_CATALOG",
    str(ROOT / "backend" / "data" / "device_catalog.yaml"),
)

from textual import on, work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.message import Message
from textual.reactive import reactive
from textual.widgets import (
    Button,
    DataTable,
    Footer,
    Header,
    Input,
    Label,
    ProgressBar,
    RichLog,
    SelectionList,
    Static,
    TabbedContent,
    TabPane,
)
from textual.widgets.selection_list import Selection

from backend.app import catalog, deep_dive, monitor, scanner, tracker, vuln_scan
from backend.app.tracker import colored_bar, device_key, signal_level


def hackrf_status() -> tuple[bool, str]:
    if not shutil.which("hackrf_info"):
        return False, "hackrf_info missing"
    try:
        r = subprocess.run(["hackrf_info"], capture_output=True, timeout=5)
        ok = r.returncode == 0 and b"Found HackRF" in r.stdout
        if not ok:
            return False, "not found"
        serial = ""
        for line in r.stdout.decode(errors="replace").splitlines():
            if "Serial number:" in line:
                serial = line.split(":", 1)[1].strip()[-12:]
                break
        return True, serial or "OK"
    except Exception as e:
        return False, str(e)


def label_for_device(dt: dict) -> str:
    radio = dt.get("radio", "?").upper()
    bands = dt.get("bands") or []
    if bands and dt.get("radio") == "hackrf":
        b0 = bands[0]
        band = f"{b0.get('freq_min_mhz')}–{b0.get('freq_max_mhz')} MHz"
    elif dt.get("radio") == "ble":
        band = "BLE"
    else:
        band = "RF"
    return f"{dt['name']}  ·  {radio}  ·  {band}"


def parse_int(value: str, default: int, lo: int, hi: int) -> int:
    try:
        n = int(str(value).strip())
    except (TypeError, ValueError):
        return default
    return max(lo, min(hi, n))


def dtype_ids_for_tab(active_tab: str, types: list[dict], categories: list[dict]) -> list[str]:
    if active_tab in ("tab-all", "all", None, ""):
        return [t["id"] for t in types]
    cat_id = active_tab.removeprefix("tab-")
    known = {c["id"] for c in categories}
    if cat_id not in known:
        return [t["id"] for t in types]
    return [t["id"] for t in types if t.get("category") == cat_id]


def _strength_text(d: dict) -> str:
    if d.get("rssi_dbm") is not None:
        return f"{d['rssi_dbm']:.0f} dBm"
    if d.get("power_dbm") is not None:
        return f"{d['power_dbm']:.0f} dBm"
    if d.get("snr_db") is not None:
        return f"+{d['snr_db']:.1f} dB"
    return "—"


def _loc_text(d: dict) -> str:
    if d.get("freq_mhz"):
        return f"{d['freq_mhz']:.4f} MHz"
    if d.get("mac"):
        return str(d["mac"])
    return "—"


def _risk_markup(status: str) -> str:
    colors = {
        "vulnerable": "bold red",
        "critical": "bold red",
        "high": "red",
        "medium": "yellow",
        "suspected": "yellow",
        "low": "green",
        "unknown": "dim",
    }
    c = colors.get(status or "unknown", "dim")
    return f"[{c}]{(status or 'unknown')[:10]}[/]"


class ScanEvent(Message):
    def __init__(self, payload: dict) -> None:
        self.payload = payload
        super().__init__()


class StatusBar(Static):
    def __init__(self) -> None:
        super().__init__(id="status-bar")

    def update_status(
        self,
        hackrf_ok: bool,
        hackrf_detail: str,
        scan: str,
        mode: str,
        selected: int,
        tracked: int,
    ) -> None:
        h = (
            f"[bold green]● HackRF[/] [dim]{hackrf_detail}[/]"
            if hackrf_ok
            else f"[bold red]○ HackRF[/] [dim]{hackrf_detail}[/]"
        )
        color = {
            "idle": "dim",
            "running": "cyan",
            "completed": "green",
            "stopped": "yellow",
            "error": "red",
        }.get(scan, "dim")
        mode_c = "magenta" if mode == "wardrive" else "dim"
        self.update(
            f"  {h}   │   [{color}]{scan}[/] [{mode_c}]{mode}[/]   │   "
            f"[bold cyan]{selected}[/] types   │   "
            f"[bold green]{tracked}[/] devices   │   "
            f"[dim]wardrive v2[/]"
        )


class DetailPanel(Static):
    """Selected device metadata + big signal bar."""

    def show_device(self, d: dict | None, sample: dict | None = None) -> None:
        if not d:
            self.update("[dim]Select a device (Enter) — then m=monitor, d=deep dive[/]")
            return
        level = int(d.get("signal_level") or signal_level(d))
        bar = colored_bar(level, 20)
        meta = d.get("metadata") or {}
        name = d.get("name") or d.get("device_type_name") or "?"
        risk = d.get("risk_status") or "unknown"
        hist = d.get("signal_history") or []
        spark = ""
        if hist:
            # mini spark from last samples
            mx = max(hist) if hist else 1
            mn = min(hist) if hist else 0
            span = max(mx - mn, 1e-6)
            blocks = "▁▂▃▄▅▆▇█"
            spark = "".join(blocks[min(7, int((v - mn) / span * 7))] for v in hist[-16:])

        mon = ""
        if sample:
            db = sample.get("db")
            hint = sample.get("hint") or ""
            mbar = sample.get("bar") or ""
            mon = f"\n[bold cyan]MONITOR[/]  {db} dB  {mbar}  [yellow]{hint}[/]"

        lines = [
            f"[bold]{name}[/]  {_risk_markup(risk)}",
            f"{bar}  {_strength_text(d)}  hits:{d.get('hit_count', 1)}"
            + ("  [dim]stale[/]" if d.get("stale") else ""),
            f"[dim]{_loc_text(d)} · {(d.get('radio') or '?').upper()} · "
            f"{meta.get('attack_profile') or meta.get('classification') or '—'}[/]",
            f"[dim]key={d.get('key') or device_key(d)}  first={str(d.get('first_seen', ''))[-8:]}[/]",
        ]
        if spark:
            lines.append(f"[cyan]{spark}[/]")
        if meta.get("oui_hint"):
            lines.append(f"[dim]OUI: {meta['oui_hint']}[/]")
        risk_obj = d.get("risk") or {}
        if risk_obj.get("summary"):
            lines.append("[yellow]" + " · ".join(risk_obj["summary"][:2]) + "[/]")
        if mon:
            lines.append(mon)
        self.update("\n".join(lines))


class RFHunterApp(App):
    TITLE = "RF Hunter v2"
    SUB_TITLE = "wardrive · HackRF + BLE"

    CSS = """
    Screen {
        background: #0a0e14;
        color: #e6edf5;
    }

    #status-bar {
        dock: top;
        height: 1;
        background: #0f1520;
        color: #7d8da6;
        padding: 0 1;
    }

    #main { height: 1fr; }

    #left {
        width: 40;
        min-width: 34;
        border-right: solid #243044;
        background: #111820;
    }

    #left-title {
        text-style: bold;
        color: #3b9eff;
        padding: 1 1 0 1;
        height: 2;
    }

    #hint {
        color: #7d8da6;
        padding: 0 1 1 1;
        height: 1;
    }

    #config-row {
        height: 3;
        padding: 0 1;
        align: left middle;
    }

    #config-row Label {
        width: 7;
        color: #7d8da6;
        margin-right: 1;
    }

    #config-row Input {
        width: 8;
        margin-right: 1;
        background: #0d1219;
        color: #e6edf5;
        border: solid #243044;
    }

    #config-row Input:focus {
        border: solid #3b9eff;
    }

    #btn-row, #btn-row2 {
        height: 3;
        padding: 0 1;
    }

    #btn-row Button, #btn-row2 Button {
        width: 1fr;
        margin-right: 1;
    }

    Button.primary {
        background: #2563a8;
        color: #ffffff;
        text-style: bold;
    }

    Button.wardrive {
        background: #6b21a8;
        color: #ffffff;
        text-style: bold;
    }

    Button.danger {
        background: #8b2e2a;
        color: #ffffff;
    }

    Button.accent {
        background: #0f766e;
        color: #ffffff;
    }

    Button:disabled { opacity: 0.4; }

    #progress-wrap {
        height: 2;
        padding: 0 1 1 1;
    }

    #category-tabs { height: 1fr; }

    TabbedContent { height: 1fr; }
    TabPane { padding: 0; }

    SelectionList {
        background: #0d1219;
        color: #e6edf5;
        height: 1fr;
        padding: 0 1;
        border: none;
    }

    SelectionList > .selection-list--option {
        color: #e6edf5;
        padding: 0 1;
    }

    SelectionList > .selection-list--option--highlighted {
        background: #1a3050;
        color: #ffffff;
    }

    SelectionList:focus > .selection-list--option--highlighted {
        background: #2563a8;
    }

    #center { width: 1fr; }

    #detections-header {
        height: 1;
        padding: 0 1;
        color: #7d8da6;
        text-style: bold;
    }

    #detections {
        height: 1fr;
        border: solid #243044;
        margin: 0 1;
        background: #0d1219;
    }

    DataTable { height: 1fr; color: #e6edf5; }
    DataTable > .datatable--cursor { background: #1a3050; }
    DataTable > .datatable--header { text-style: bold; color: #3b9eff; }

    #detail {
        height: 8;
        border-top: solid #243044;
        background: #111820;
        padding: 0 1;
        color: #e6edf5;
    }

    #log-panel {
        height: 10;
        border-top: solid #243044;
        background: #0d1219;
    }

    #log-title {
        dock: top;
        height: 1;
        padding: 0 1;
        color: #3dd68c;
        text-style: bold;
        background: #111820;
    }

    #log {
        height: 1fr;
        padding: 0 1;
        color: #e6edf5;
    }

    Footer { background: #0f1520; }
    """

    BINDINGS = [
        Binding("q", "quit", "Quit", show=True),
        Binding("s", "start_scan", "Scan", show=True),
        Binding("w", "start_wardrive", "Wardrive", show=True),
        Binding("x", "stop_scan", "Stop all", show=True),
        Binding("m", "monitor_selected", "Monitor", show=True),
        Binding("d", "deep_dive_selected", "Dive", show=True),
        Binding("v", "vuln_scan_quick", "Vulns", show=True),
        Binding("a", "select_all", "All", show=True),
        Binding("n", "clear_selection", "None", show=True),
        Binding("c", "clear_results", "Clear", show=True),
        Binding("r", "refresh_hackrf", "HackRF", show=True),
        Binding("f", "cycle_sev_filter", "Filter", show=True),
        Binding("enter", "focus_row", "Select", show=False),
    ]

    scan_status: reactive[str] = reactive("idle")
    selected_count: reactive[int] = reactive(0)

    def __init__(self) -> None:
        super().__init__()
        self._categories = catalog.get_categories()
        self._types = catalog.get_device_types()
        self._selected: set[str] = set()
        self._row_keys: list[str] = []  # table row index → device key
        self._focused_key: str | None = None
        self._hackrf_ok = False
        self._hackrf_detail = "…"
        self._lists: dict[str, SelectionList] = {}
        self._applying_selection = False
        self._mode = "once"
        self._last_sample: dict | None = None
        self._monitoring = False
        self._sev_filter: str | None = None  # None | critical|high|medium|low|unknown

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield StatusBar()

        with Horizontal(id="main"):
            with Vertical(id="left"):
                yield Static("◈ WARDRIVE TYPES", id="left-title")
                yield Static("w=wardrive · x=stop · v=vulns · f=filter sev", id="hint")
                with Horizontal(id="config-row"):
                    yield Label("Dur(s)")
                    yield Input(value="20", id="duration", restrict=r"[0-9]*", max_length=4)
                    yield Label("Passes")
                    yield Input(value="30", id="passes", restrict=r"[0-9]*", max_length=4)
                with Horizontal(id="btn-row"):
                    yield Button("▶ WARDRIVE", id="btn-wardrive", classes="wardrive")
                    yield Button("■ STOP ALL", id="btn-stop", classes="danger")
                with Horizontal(id="btn-row2"):
                    yield Button("SCAN", id="btn-scan", classes="primary")
                    yield Button("VULNS", id="btn-vulns", classes="accent")
                    yield Button("MONITOR", id="btn-monitor", classes="accent")
                    yield Button("DIVE", id="btn-dive", classes="accent")
                with Vertical(id="progress-wrap"):
                    yield ProgressBar(total=100, show_eta=False, id="progress")

                with TabbedContent(id="category-tabs"):
                    with TabPane("All", id="tab-all"):
                        yield SelectionList(id="list-all")
                    for cat in self._categories:
                        with TabPane(cat["label"], id=f"tab-{cat['id']}"):
                            yield SelectionList(id=f"list-{cat['id']}")

            with Vertical(id="center"):
                yield Static("DEVICES  ·  0", id="detections-header")
                yield DataTable(id="detections", zebra_stripes=True, cursor_type="row")
                yield DetailPanel(id="detail")
                with Vertical(id="log-panel"):
                    yield Static("LIVE LOG", id="log-title")
                    yield RichLog(id="log", highlight=True, markup=True, wrap=True)

        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#detections", DataTable)
        table.add_columns("Signal", "dBm/SNR", "Loc", "Type", "Radio", "Risk", "Hits")

        self._build_selection_lists()
        self._wire_scanner()
        self.action_refresh_hackrf()
        self._sync_buttons()
        self._refresh_status_bar()
        self.query_one(DetailPanel).show_device(None)
        self._log(
            "[dim]RF Hunter v2 — [bold]w[/] wardrive, [bold]s[/] once, "
            "[bold]Enter[/] select, [bold]m[/] monitor, [bold]d[/] dive[/]"
        )

    def _build_selection_lists(self) -> None:
        self._lists.clear()

        all_list = self.query_one("#list-all", SelectionList)
        all_list.clear_options()
        for dt in self._types:
            all_list.add_option(Selection(label_for_device(dt), dt["id"], False))
        self._lists["all"] = all_list

        for cat in self._categories:
            lst = self.query_one(f"#list-{cat['id']}", SelectionList)
            lst.clear_options()
            for dt in self._types:
                if dt.get("category") != cat["id"]:
                    continue
                lst.add_option(Selection(label_for_device(dt), dt["id"], False))
            self._lists[cat["id"]] = lst

    def _wire_scanner(self) -> None:
        def on_event(ev: dict) -> None:
            self.post_message(ScanEvent(ev))

        scanner.session.subscribe(on_event)
        monitor.monitor.subscribe(on_event)
        vuln_scan.vuln_scan.subscribe(on_event)

    def _log(self, msg: str) -> None:
        self.query_one("#log", RichLog).write(msg)

    def _sync_buttons(self) -> None:
        running = self.scan_status == "running"
        vuln_running = vuln_scan.vuln_scan.is_running()
        self.query_one("#btn-scan", Button).disabled = running or vuln_running
        self.query_one("#btn-wardrive", Button).disabled = running or vuln_running
        # Stop all always clickable — clears scan/monitor/vuln
        self.query_one("#btn-stop", Button).disabled = False

    def _refresh_status_bar(self) -> None:
        n = len(tracker.tracker.snapshot())
        self.query_one(StatusBar).update_status(
            self._hackrf_ok,
            self._hackrf_detail,
            self.scan_status,
            self._mode if self.scan_status == "running" else scanner.session.mode,
            len(self._selected),
            n,
        )

    def watch_scan_status(self, _value: str) -> None:
        self._sync_buttons()
        self._refresh_status_bar()

    def watch_selected_count(self, _value: int) -> None:
        self._refresh_status_bar()

    def _active_list(self) -> SelectionList | None:
        tabs = self.query_one("#category-tabs", TabbedContent)
        active = tabs.active or "tab-all"
        key = "all" if active == "tab-all" else active.removeprefix("tab-")
        return self._lists.get(key)

    def _apply_selected_to_lists(self) -> None:
        self._applying_selection = True
        try:
            for lst in self._lists.values():
                known = {opt.value for opt in lst.options}
                for val in list(lst.selected):
                    try:
                        lst.deselect(val)
                    except Exception:
                        pass
                for tid in self._selected:
                    if tid in known:
                        lst.select(tid)
        finally:
            self._applying_selection = False

    def _sync_selected_from_lists(self) -> None:
        selected: set[str] = set()
        for lst in self._lists.values():
            known = {opt.value for opt in lst.options}
            for v in lst.selected:
                if v in known:
                    selected.add(str(v))
        self._selected = selected
        self.selected_count = len(self._selected)

    @on(SelectionList.SelectedChanged)
    def on_selection_changed(self, _event: SelectionList.SelectedChanged) -> None:
        if self._applying_selection:
            return
        self._sync_selected_from_lists()

    def action_refresh_hackrf(self) -> None:
        ok, detail = hackrf_status()
        self._hackrf_ok = ok
        self._hackrf_detail = detail
        self._refresh_status_bar()
        self._log(
            f"[green]HackRF OK[/] ({detail})" if ok else f"[red]HackRF N/A[/] ({detail})"
        )

    def action_select_all(self) -> None:
        tabs = self.query_one("#category-tabs", TabbedContent)
        targets = dtype_ids_for_tab(tabs.active or "tab-all", self._types, self._categories)
        for tid in targets:
            self._selected.add(tid)
        self._apply_selected_to_lists()
        self.selected_count = len(self._selected)
        self._log(f"[cyan]Selected {len(targets)} type(s)[/] → total {len(self._selected)}")

    def action_clear_selection(self) -> None:
        self._selected.clear()
        self._apply_selected_to_lists()
        self.selected_count = 0
        self._log("[dim]Selection cleared[/]")

    def action_clear_results(self) -> None:
        tracker.tracker.clear()
        self._row_keys.clear()
        self._focused_key = None
        table = self.query_one("#detections", DataTable)
        table.clear()
        self.query_one("#detections-header", Static).update("DEVICES  ·  0")
        self.query_one(DetailPanel).show_device(None)
        self._log("[dim]Tracker cleared[/]")
        self._refresh_status_bar()

    @on(Button.Pressed, "#btn-scan")
    def on_scan_pressed(self) -> None:
        self.action_start_scan()

    @on(Button.Pressed, "#btn-wardrive")
    def on_wardrive_pressed(self) -> None:
        self.action_start_wardrive()

    @on(Button.Pressed, "#btn-stop")
    def on_stop_pressed(self) -> None:
        self.action_stop_scan()

    @on(Button.Pressed, "#btn-monitor")
    def on_monitor_pressed(self) -> None:
        self.action_monitor_selected()

    @on(Button.Pressed, "#btn-dive")
    def on_dive_pressed(self) -> None:
        self.action_deep_dive_selected()

    @on(Button.Pressed, "#btn-vulns")
    def on_vulns_pressed(self) -> None:
        self.action_vuln_scan_quick()

    def _start(self, mode: str) -> None:
        if self.scan_status == "running":
            return

        self._sync_selected_from_lists()
        if not self._selected:
            self._log("[yellow]Nothing selected — press [bold]a[/] or Space on a type[/]")
            return

        duration = parse_int(self.query_one("#duration", Input).value, 20, 5, 600)
        passes = parse_int(self.query_one("#passes", Input).value, 30, 8, 500)
        self.query_one("#duration", Input).value = str(duration)
        self.query_one("#passes", Input).value = str(passes)

        if mode == "wardrive":
            # Keep prior detections — use Cleanup / clear_results for a fresh start
            kept = len(tracker.tracker.snapshot())
            if kept:
                self._log(f"[dim]Keeping {kept} prior device(s) — press [bold]c[/] to clear[/]")
        self._mode = mode
        self.scan_status = "running"
        self.query_one("#progress", ProgressBar).update(progress=0)
        ids = sorted(self._selected)
        label = "WARDRIVE" if mode == "wardrive" else "SCAN"
        self._log(
            f"[bold magenta]▶ {label}[/] — {len(ids)} type(s), {duration}s, {passes} passes"
        )
        try:
            sid = scanner.session.start(
                ids, duration, 32, 36, passes, mode=mode, clear_results=False
            )
            self._log(f"[dim]session {sid}[/]")
        except Exception as e:
            self.scan_status = "error"
            self._log(f"[red]Start failed: {e}[/]")

    def action_start_scan(self) -> None:
        self._start("once")

    def action_start_wardrive(self) -> None:
        self._start("wardrive")

    def action_stop_scan(self) -> None:
        scanner.session.stop()
        monitor.monitor.stop()
        vuln_scan.vuln_scan.stop()
        self._monitoring = False
        self._last_sample = None
        self._log("[yellow]■ Stop all (scan + monitor + vulns)[/]")

    def action_cycle_sev_filter(self) -> None:
        order = [None, "critical", "high", "medium", "low", "unknown"]
        try:
            i = order.index(self._sev_filter)
        except ValueError:
            i = 0
        self._sev_filter = order[(i + 1) % len(order)]
        label = self._sev_filter or "all"
        self._log(f"[cyan]Filter severity:[/] {label}")
        self._refresh_table()

    def action_vuln_scan_quick(self) -> None:
        if self.scan_status == "running":
            self._log("[yellow]Stop wardrive first (x)[/]")
            return
        devices = tracker.tracker.snapshot()
        if not devices:
            self._log("[yellow]No tracked devices — wardrive first[/]")
            return
        res = vuln_scan.vuln_scan.start(mode="quick")
        if not res.get("ok"):
            self._log(f"[red]Vuln scan failed: {res.get('error')}[/]")
            return
        self._log(f"[bold red]⚡ Vuln triage[/] on {res.get('total')} device(s)")

    def action_focus_row(self) -> None:
        table = self.query_one("#detections", DataTable)
        if not self._row_keys:
            return
        row = table.cursor_row
        if row is None or row < 0 or row >= len(self._row_keys):
            return
        self._focused_key = self._row_keys[row]
        d = tracker.tracker.get(self._focused_key)
        self.query_one(DetailPanel).show_device(d, self._last_sample if self._monitoring else None)
        self._log(f"[cyan]Focused[/] {self._focused_key}")

    @on(DataTable.RowSelected)
    def on_row_selected(self, event: DataTable.RowSelected) -> None:
        row = event.cursor_row
        if row is None or row < 0 or row >= len(self._row_keys):
            return
        self._focused_key = self._row_keys[row]
        d = tracker.tracker.get(self._focused_key)
        self.query_one(DetailPanel).show_device(d)

    def _focused_device(self) -> dict | None:
        if not self._focused_key:
            # try cursor
            table = self.query_one("#detections", DataTable)
            row = table.cursor_row
            if row is not None and 0 <= row < len(self._row_keys):
                self._focused_key = self._row_keys[row]
        if not self._focused_key:
            return None
        return tracker.tracker.get(self._focused_key)

    def action_monitor_selected(self) -> None:
        d = self._focused_device()
        if not d:
            self._log("[yellow]Select a device row first (Enter)[/]")
            return
        if self._monitoring and monitor.monitor.device_key == d.get("key"):
            monitor.monitor.stop()
            self._monitoring = False
            self._log("[yellow]Monitor stopped[/]")
            return
        monitor.monitor.start(d)
        self._monitoring = True
        self._log(f"[bold cyan]Monitoring[/] {d.get('key')}")
        self.query_one(DetailPanel).show_device(d)

    @work(thread=True)
    def action_deep_dive_selected(self) -> None:
        d = self._focused_device()
        if not d:
            self.call_from_thread(self._log, "[yellow]Select a device row first[/]")
            return
        self.call_from_thread(self._log, f"[bold]Deep dive[/] {d.get('key')}…")
        try:
            result = deep_dive.deep_dive(d)
            risk = result.get("risk") or {}
            status = risk.get("status", "?")
            summary = ", ".join(risk.get("summary") or [])[:120]
            self.call_from_thread(
                self._log,
                f"[bold green]Dive done[/] risk={status} {summary}",
            )
            updated = tracker.tracker.get(device_key(d))
            self.call_from_thread(self._refresh_table)
            if updated:
                self.call_from_thread(
                    self.query_one(DetailPanel).show_device, updated
                )
        except Exception as e:
            self.call_from_thread(self._log, f"[red]Dive failed: {e}[/]")

    def _refresh_table(self) -> None:
        devices = tracker.tracker.snapshot()
        if self._sev_filter:
            def match(d: dict) -> bool:
                sev = ((d.get("risk") or {}).get("severity") or d.get("risk_status") or "unknown").lower()
                if sev == "vulnerable":
                    sev = "critical"
                if sev == "suspected":
                    sev = "medium"
                if self._sev_filter == "unknown":
                    return not d.get("risk") and sev in ("unknown", "suspected", "")
                return sev == self._sev_filter
            devices = [d for d in devices if match(d)]

        table = self.query_one("#detections", DataTable)
        table.clear()
        self._row_keys = []
        for d in devices:
            key = d.get("key") or device_key(d)
            level = int(d.get("signal_level") or signal_level(d))
            bar = colored_bar(level, 10)
            if d.get("stale"):
                bar = f"[dim]{bar}[/]"
            dtype = d.get("device_type_name") or d.get("device_type_id") or "?"
            radio = (d.get("radio") or "?").upper()
            risk = d.get("risk_status") or "unknown"
            table.add_row(
                bar,
                _strength_text(d),
                _loc_text(d)[:22],
                str(dtype)[:18],
                radio,
                risk[:10],
                str(d.get("hit_count") or 1),
                key=key,
            )
            self._row_keys.append(key)
        filt = f" · filter:{self._sev_filter}" if self._sev_filter else ""
        self.query_one("#detections-header", Static).update(
            f"DEVICES  ·  {len(devices)}{filt}"
        )
        self._refresh_status_bar()
        if self._focused_key:
            d = tracker.tracker.get(self._focused_key)
            self.query_one(DetailPanel).show_device(
                d, self._last_sample if self._monitoring else None
            )

    @on(ScanEvent)
    def on_scan_event(self, event: ScanEvent) -> None:
        msg = event.payload
        mtype = msg.get("type")

        if mtype == "log":
            self._log(f"[dim]{msg.get('message', '')}[/]")
        elif mtype == "progress":
            self.query_one("#progress", ProgressBar).update(
                progress=float(msg.get("progress", 0))
            )
        elif mtype in ("device", "device_update", "tracker_snapshot", "vuln_finding", "vuln_scan_complete"):
            self._refresh_table()
            if mtype == "vuln_scan_complete":
                counts = msg.get("counts") or {}
                self._log(
                    "[bold green]Vulns done[/] "
                    + " ".join(f"{k}={counts.get(k, 0)}" for k in ("critical", "high", "medium", "low"))
                )
        elif mtype == "vuln_scan_start":
            self._log("[bold red]Vuln scan running…[/]")
        elif mtype == "monitor_sample":
            self._last_sample = msg
            if self._focused_key and msg.get("device_key") == self._focused_key:
                d = tracker.tracker.get(self._focused_key)
                self.query_one(DetailPanel).show_device(d, msg)
            # light refresh for signal column
            self._refresh_table()
        elif mtype == "monitor_stop":
            self._monitoring = False
            self._last_sample = None
        elif mtype == "complete":
            self.scan_status = msg.get("status") or "completed"
            self.query_one("#progress", ProgressBar).update(progress=100)
            n = len(tracker.tracker.snapshot())
            self._log(f"[bold green]✓ Done[/] — {n} device(s)")
            self._refresh_table()
        elif mtype == "error":
            self.scan_status = "error"
            self._log(f"[bold red]ERROR:[/] {msg.get('message')}")


def main() -> None:
    Path(os.environ["RF_HUNTER_CAPTURES"]).mkdir(parents=True, exist_ok=True)
    RFHunterApp().run()


if __name__ == "__main__":
    main()
