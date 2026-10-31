"""Which optional applets does the build under test carry?

A build without `applet-piv` / `applet-openpgp` answers SELECT of that AID
with 6A82 (file not found).  The PIV and OpenPGP test modules skip then
(see `_skip_absent_applet` in conftest.py) instead of failing.
"""
from __future__ import annotations

APPLETS = {
    "piv": ("PIV", "00A404000BA000000308000010000100"),
    "openpgp": ("OpenPGP", "00A4040006D27600012401"),
}

_cache: dict[str, bool] = {}


def applet_absent(sw: int) -> bool:
    return sw == 0x6A82


def applet_present(key: str, send=None) -> bool:
    """True unless SELECT of the applet answers 6A82.  `send(apdu_hex) -> sw`
    defaults to a PC/SC session on the device under test; if the device
    cannot be reached the applet is assumed present (the tests report that)."""
    if key in _cache:
        return _cache[key]
    _, select = APPLETS[key]
    try:
        if send is None:
            from helpers.pcsc import session

            with session() as s:
                _, sw = s.send(select)
        else:
            sw = send(select)
    except Exception:
        return True
    present = not applet_absent(sw)
    if send is None:
        _cache[key] = present
    return present


def module_applet(module_name: str) -> str | None:
    for key in APPLETS:
        if module_name.startswith(f"test_{key}_"):
            return key
    return None
