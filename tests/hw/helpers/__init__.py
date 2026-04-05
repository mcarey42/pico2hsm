"""Shared helpers for pico2hsm hardware integration tests."""

from __future__ import annotations

import re


def sw_from_output(stdout: str, stderr: str = "") -> str | None:
    """Extract the SW (status word) from opensc-tool output.

    Priority order:
    1. opensc-tool stdout: "Received (SW1=0xNN, SW2=0xNN):" — the last such
       line is the SW of the last user APDU sent.
    2. OpenSC debug log (stderr): "sw1=NN sw2=NN" — only used as fallback
       because OpenSC's card-detection probes can inject spurious 6A82 entries
       into stderr before our APDUs are sent.
    3. Last 4-char hex string on its own line.

    Pass ``stdout`` and ``stderr`` separately so we can prefer stdout.
    For backward compatibility, if only ``stdout`` is provided the function
    still searches the single string (stdout) for both patterns.
    """
    # Primary: opensc-tool stdout "Received (SW1=0xNN, SW2=0xNN):"
    matches = re.findall(
        r"SW1=0x([0-9A-Fa-f]{2}),\s*SW2=0x([0-9A-Fa-f]{2})",
        stdout,
        re.IGNORECASE,
    )
    if matches:
        sw1, sw2 = matches[-1]
        return (sw1 + sw2).upper()

    # Secondary: same pattern in stderr (some OpenSC versions write it there)
    if stderr:
        matches = re.findall(
            r"SW1=0x([0-9A-Fa-f]{2}),\s*SW2=0x([0-9A-Fa-f]{2})",
            stderr,
            re.IGNORECASE,
        )
        if matches:
            sw1, sw2 = matches[-1]
            return (sw1 + sw2).upper()

    # Fallback: "sw1=NN sw2=NN" from OpenSC driver debug logs — LAST match only.
    # Note: OpenSC card-detection probes (coolkey, muscle) inject 6A82 here
    # before our APDUs are sent, so take the LAST match.
    combined = stdout + ("\n" + stderr if stderr else "")
    matches = re.findall(
        r"sw1=([0-9A-Fa-f]{2})[\s,]+sw2=([0-9A-Fa-f]{2})",
        combined,
    )
    if matches:
        sw1, sw2 = matches[-1]
        return (sw1 + sw2).upper()

    # Last resort: a line that is exactly 4 hex chars after stripping spaces
    lines = [ln.strip() for ln in combined.splitlines() if ln.strip()]
    for line in reversed(lines):
        clean = line.replace(" ", "")
        if len(clean) == 4 and all(c in "0123456789ABCDEFabcdef" for c in clean):
            return clean.upper()

    return None


def last_response_hex(stdout: str) -> str:
    """Extract the hex bytes of the last APDU response from opensc-tool stdout.

    opensc-tool prints responses like:
        Received (SW1=0x90, SW2=0x00):
        6F 1B 84 10 ...                 ← response data (may span multiple lines)
        ...                              ← until the next "Sending:" or EOF

    Returns the concatenated hex bytes (no spaces, no ASCII sidebar, no SW).
    Returns an empty string if no response was found.
    """
    # Find all "Received (...): \n <hex lines>" blocks
    # Split on "Sending:" to isolate individual exchanges
    # We want the last exchange's response body
    segments = re.split(r"Sending:", stdout)
    # The last segment is after the last "Sending:" — it contains the last response
    if not segments:
        return ""
    last_seg = segments[-1]

    # Find "Received (...):" and take everything after it
    m = re.search(
        r"Received\s*\(SW1=0x[0-9A-Fa-f]{2},\s*SW2=0x[0-9A-Fa-f]{2}\):\s*\n([\s\S]*)",
        last_seg,
        re.IGNORECASE,
    )
    if not m:
        return ""

    raw_lines = m.group(1).strip().splitlines()
    hex_chars = []
    for line in raw_lines:
        # opensc-tool adds an ASCII sidebar after 16 bytes: "XX XX ...  ...."
        # The sidebar starts after a double-space or at a non-hex character cluster
        # Strip the sidebar by taking only the leading hex tokens
        tokens = line.strip().split()
        for tok in tokens:
            # Token is a valid hex byte
            if len(tok) == 2 and all(c in "0123456789ABCDEFabcdef" for c in tok):
                hex_chars.append(tok)
            else:
                # Hit the ASCII sidebar or unexpected content — stop this line
                break
    return "".join(hex_chars).upper()
