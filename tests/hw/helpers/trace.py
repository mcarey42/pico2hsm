"""APDU trace parser for OpenSC debug output."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from helpers.cli import CLIResult


# Patterns for OpenSC debug level 9 output
#
# OpenSC 0.25 format (apdu.c:367):
#   sc_single_transmit: CLA:0, INS:A4, P1:4, P2:0, data(7) 0x...
_RE_TRANSMIT = re.compile(
    r"sc_single_transmit:\s+CLA:([0-9A-Fa-f]+),\s*INS:([0-9A-Fa-f]+),"
    r"\s*P1:([0-9A-Fa-f]+),\s*P2:([0-9A-Fa-f]+)",
    re.IGNORECASE,
)
# SW reported on the result line (from any driver):
#   coolkey_apdu_io: result r=0 apdu.resplen=NN sw1=90 sw2=00
#   sc_hsm_read_binary: Check SW error ... sw1=6a sw2=82
_RE_SW = re.compile(r"sw1=([0-9A-Fa-f]{2})[\s,]+sw2=([0-9A-Fa-f]{2})", re.IGNORECASE)

# Legacy format from older OpenSC versions (kept for compatibility)
_RE_SENDING = re.compile(
    r"Sending\s*(?:APDU)?[:\s]+([0-9A-Fa-f][0-9A-Fa-f ]+)",
    re.IGNORECASE,
)
_RE_RECEIVED = re.compile(
    r"Received\s*\(SW1=0x([0-9A-Fa-f]{2}),\s*SW2=0x([0-9A-Fa-f]{2})\)\s*:([0-9A-Fa-f ]*)",
    re.IGNORECASE,
)


@dataclass
class APDUExchange:
    sent_hex: str      # hex string of the command APDU bytes
    received_hex: str  # hex string of response data (without SW)
    sw: str            # status word, e.g. "9000"


def parse_apdu_trace(text: str) -> list[APDUExchange]:
    """Parse OpenSC debug output and return a list of APDU exchanges.

    Handles two formats:

    OpenSC 0.25+ (apdu.c sc_single_transmit lines):
        sc_single_transmit: CLA:0, INS:A4, P1:4, P2:0, data(7) 0x...
        ...
        sw1=6a sw2=82

    Legacy OpenSC (older versions):
        Sending: 00 A4 04 00 ...
        Received (SW1=0x90, SW2=0x00): 6F 1F ...
    """
    exchanges: list[APDUExchange] = []
    lines = text.splitlines()

    # --- OpenSC 0.25 format ---
    # Strategy: every sc_single_transmit CLA/INS/P1/P2 line is one APDU.
    # Look ahead up to _SW_LOOKAHEAD lines for a matching sw1=/sw2= result.
    # If a new command starts before SW is found, flush previous as SW=????.
    _SW_LOOKAHEAD = 20
    pending_sent: str | None = None
    pending_line_idx: int = -1

    for i, line in enumerate(lines):
        # Modern format: command line
        m_tx = _RE_TRANSMIT.search(line)
        if m_tx:
            # Flush any previous pending command that got no SW
            if pending_sent is not None:
                # Scan the lines between pending and now for a SW
                sw = _find_sw_in_window(lines, pending_line_idx + 1, i)
                exchanges.append(APDUExchange(
                    sent_hex=pending_sent,
                    received_hex="",
                    sw=sw,
                ))
            cla = int(m_tx.group(1), 16)
            ins = int(m_tx.group(2), 16)
            p1  = int(m_tx.group(3), 16)
            p2  = int(m_tx.group(4), 16)
            pending_sent = f"{cla:02X}{ins:02X}{p1:02X}{p2:02X}"
            pending_line_idx = i
            continue

        # Modern format: explicit SW line (closes current pending immediately)
        m_sw = _RE_SW.search(line)
        if m_sw and pending_sent is not None:
            if i - pending_line_idx <= _SW_LOOKAHEAD:
                sw1 = m_sw.group(1).upper()
                sw2 = m_sw.group(2).upper()
                exchanges.append(APDUExchange(
                    sent_hex=pending_sent,
                    received_hex="",
                    sw=sw1 + sw2,
                ))
                pending_sent = None
                pending_line_idx = -1
            continue

        # Legacy format: Sending line
        m_send = _RE_SENDING.search(line)
        if m_send:
            if pending_sent is not None:
                exchanges.append(APDUExchange(sent_hex=pending_sent, received_hex="", sw="????"))
            pending_sent = _normalise_hex(m_send.group(1))
            pending_line_idx = i
            continue

        # Legacy format: Received line
        m_recv = _RE_RECEIVED.search(line)
        if m_recv:
            sw1 = m_recv.group(1).upper()
            sw2 = m_recv.group(2).upper()
            data_hex = _normalise_hex(m_recv.group(3)) if m_recv.group(3).strip() else ""
            exchanges.append(APDUExchange(
                sent_hex=pending_sent or "",
                received_hex=data_hex,
                sw=sw1 + sw2,
            ))
            pending_sent = None
            pending_line_idx = -1

    # Flush final pending command
    if pending_sent is not None:
        sw = _find_sw_in_window(lines, pending_line_idx + 1, len(lines))
        exchanges.append(APDUExchange(sent_hex=pending_sent, received_hex="", sw=sw))

    return exchanges


def _find_sw_in_window(lines: list[str], start: int, end: int) -> str:
    """Scan lines[start:end] for the first sw1=/sw2= pattern; return SW or '????'."""
    for line in lines[start:end]:
        m = _RE_SW.search(line)
        if m:
            return m.group(1).upper() + m.group(2).upper()
    return "????"


def format_trace_summary(exchanges: list[APDUExchange]) -> str:
    """Return a human-readable table of APDU exchanges."""
    if not exchanges:
        return "(no APDU exchanges captured)\n"

    col_w = 60
    lines: list[str] = [
        f"{'#':<4} {'SENT (CLA INS P1 P2 ...)':<{col_w}} {'SW':<6} RESPONSE DATA",
        "-" * (col_w * 2 + 16),
    ]
    for i, ex in enumerate(exchanges, 1):
        sent = ex.sent_hex[:col_w] or "(empty)"
        resp = ex.received_hex[:col_w] or "(empty)"
        lines.append(f"{i:<4} {sent:<{col_w}} {ex.sw:<6} {resp}")

    return "\n".join(lines) + "\n"


def save_json_trace(
    path: Path,
    test_name: str,
    result: "CLIResult",
    exchanges: list[APDUExchange],
) -> None:
    """Write a JSON file with test metadata and parsed APDU exchanges."""
    payload = {
        "test_name": test_name,
        "cmd": result.cmd,
        "returncode": result.returncode,
        "elapsed_ms": result.elapsed_ms,
        "timestamp": datetime.now(tz=timezone.utc).isoformat(),
        "apdu_count": len(exchanges),
        "exchanges": [
            {
                "sent_hex": ex.sent_hex,
                "received_hex": ex.received_hex,
                "sw": ex.sw,
            }
            for ex in exchanges
        ],
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _normalise_hex(raw: str) -> str:
    """Strip spaces and normalise hex string to uppercase pairs."""
    stripped = raw.replace(" ", "").replace("\t", "").upper()
    return stripped
