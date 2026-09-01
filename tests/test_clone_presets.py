"""RF CLONE presets + spectrum response shape."""

from backend.app.clone_presets import get_preset, list_presets, synthetic_device


def test_clone_presets_shape():
    presets = list_presets()
    assert len(presets) >= 6
    ids = {p["id"] for p in presets}
    assert "garage_433" in ids
    assert "garage_868" in ids
    assert "garage_low" in ids
    assert "car_433" in ids
    assert "remote_315" in ids
    assert "domotica_868" in ids
    for p in presets:
        assert p["center_mhz"]
        assert p["icon"]
        assert p["label"]


def test_hunt_empty_without_hw(monkeypatch):
    """hunt() should return structured response even if sweep yields nothing."""
    from backend.app import clone_presets
    import subprocess

    def fake_run(*_a, **_k):
        class R:
            stdout = ""
            returncode = 0

        return R()

    monkeypatch.setattr(clone_presets, "pkill_rf_tools", lambda: None)
    monkeypatch.setattr(clone_presets.subprocess, "run", fake_run)
    # exclusive context manager
    class Dummy:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    monkeypatch.setattr(clone_presets, "exclusive", lambda *_a, **_k: Dummy())
    res = clone_presets.hunt(hold_s=4.0)
    assert res["ok"] is True
    assert "candidates" in res


def test_synthetic_device_for_replay():
    p = get_preset("garage_433")
    assert p is not None
    d = synthetic_device(p)
    assert d["radio"] == "hackrf"
    assert abs(float(d["freq_mhz"]) - 433.92) < 0.01
    assert d["device_type_id"]


def test_spectrum_requires_target():
    from backend.app import clone_presets

    res = clone_presets.spectrum()
    assert res.get("ok") is False
