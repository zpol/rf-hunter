"""TX allowlist + fine-tune clamp."""

from backend.app import tx_safety


def test_allowlist_bands():
    assert tx_safety.in_allowlist(433.92)
    assert tx_safety.in_allowlist(868.35)
    assert tx_safety.in_allowlist(315.0)
    assert tx_safety.in_allowlist(330.0)
    assert tx_safety.in_allowlist(286.0)
    assert not tx_safety.in_allowlist(881.9)
    assert not tx_safety.in_allowlist(915.0)


def test_snap_gsm_clutter_to_868():
    assert tx_safety.nearest_allowlist_mhz(881.9) == 868.35
    assert tx_safety.nearest_allowlist_mhz(433.92) == 433.92


def test_safe_tx_freq_clamps_wild_offset():
    tx, off, note = tx_safety.safe_tx_freq(433.92, 15_000_000)  # 15 MHz bogus
    assert tx == 433.92
    assert off is None
    assert note

    tx2, off2, _ = tx_safety.safe_tx_freq(433.92, 40_000)
    assert abs(tx2 - 433.96) < 0.001
    assert off2 == 40_000
