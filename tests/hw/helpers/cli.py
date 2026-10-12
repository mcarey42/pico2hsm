"""Subprocess wrapper for running PCSC/pkcs11 CLI tools with APDU trace capture."""

from __future__ import annotations

import os
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


@dataclass
class CLIResult:
    cmd: list[str]
    returncode: int
    stdout: str        # stdout decoded as UTF-8 (text commands)
    stdout_bytes: bytes  # stdout as raw bytes (for binary output like DER keys)
    stderr: str
    elapsed_ms: float
    trace_file: Optional[Path] = None


class CLIRunner:
    """Run CLI tools (sc-hsm-tool, pkcs11-tool, openssl) with APDU tracing."""

    def __init__(self, config: dict, run_dir: Path) -> None:
        self.config = config
        self.run_dir = run_dir
        self.run_dir.mkdir(parents=True, exist_ok=True)

    def run(
        self,
        args: list[str],
        *,
        env_extra: Optional[dict] = None,
        save_as: Optional[str] = None,
        stdin_data: Optional[bytes] = None,
        timeout: int = 300,
    ) -> CLIResult:
        """Run a command, capturing stdout/stderr separately with APDU tracing enabled.

        Args:
            timeout: Subprocess wall-clock timeout in seconds (default 300).
                     RSA-2048 sign/decrypt on a debug Cortex-M33 build can take
                     up to ~180 s.  Use a larger value for RSA-4096 keygen
                     (which can take 15–60 min on opt-level=1 hardware).
        """
        env = os.environ.copy()
        # Always enable OpenSC APDU tracing to stderr
        env["OPENSC_DEBUG"] = "9"
        env["OPENSC_LOG_STDERR"] = "1"
        env["OPENSC_LOG_FILE"] = ""  # empty = use stderr
        if env_extra:
            env.update(env_extra)

        t_start = time.perf_counter()
        try:
            proc = subprocess.run(
                args,
                input=stdin_data,
                capture_output=True,
                env=env,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            elapsed_ms = (time.perf_counter() - t_start) * 1000.0
            msg = f"[TIMEOUT after {timeout}s] {' '.join(args)}"
            return CLIResult(
                cmd=args,
                returncode=-1,
                stdout="",
                stdout_bytes=b"",
                stderr=msg,
                elapsed_ms=elapsed_ms,
            )
        elapsed_ms = (time.perf_counter() - t_start) * 1000.0

        stdout_bytes = proc.stdout
        stdout = stdout_bytes.decode("utf-8", errors="replace")
        stderr = proc.stderr.decode("utf-8", errors="replace")

        trace_file: Optional[Path] = None
        if save_as is not None:
            trace_file = self.run_dir / f"{save_as}.txt"
            _write_trace_file(
                trace_file,
                cmd=args,
                returncode=proc.returncode,
                elapsed_ms=elapsed_ms,
                stdout=stdout,
                stderr=stderr,
            )

        return CLIResult(
            cmd=args,
            returncode=proc.returncode,
            stdout=stdout,
            stdout_bytes=stdout_bytes,
            stderr=stderr,
            elapsed_ms=elapsed_ms,
            trace_file=trace_file,
        )

    def sc_hsm_tool(self, *args: str, save_as: Optional[str] = None, timeout: int = 300) -> CLIResult:
        """Run sc-hsm-tool with the given arguments."""
        return self.run(["sc-hsm-tool"] + list(args), save_as=save_as, timeout=timeout)

    def pkcs11_tool(self, *args: str, save_as: Optional[str] = None, timeout: int = 300) -> CLIResult:
        """Run pkcs11-tool with --module prepended."""
        cmd = ["pkcs11-tool", "--module", self.config["module"]] + list(args)
        return self.run(cmd, save_as=save_as, timeout=timeout)

    def openssl(self, *args: str, save_as: Optional[str] = None, timeout: int = 300) -> CLIResult:
        """Run openssl with the given arguments."""
        return self.run(["openssl"] + list(args), save_as=save_as, timeout=timeout)

    def openssl_stdin(
        self,
        args: list[str],
        stdin_data: bytes,
        save_as: Optional[str] = None,
        timeout: int = 300,
    ) -> CLIResult:
        """Run openssl with stdin input."""
        return self.run(
            ["openssl"] + args,
            stdin_data=stdin_data,
            save_as=save_as,
            timeout=timeout,
        )

    def send_apdu(
        self,
        *apdus: str,
        reader: Optional[int] = None,
        save_as: Optional[str] = None,
    ) -> CLIResult:
        """Send one or more raw APDUs via opensc-tool and return the result.

        APDUs are passed as hex strings (e.g. ``"80543C0000"``).
        opensc-tool prints each response as hex to stdout; SW bytes are on
        the ``Received (SW1=0x.., SW2=0x..)`` line.

        Args:
            apdus: Hex APDU strings to send in sequence.
            reader: PCSC reader index (default: the device under test,
                OPENSC_DEFAULT_READER, else 0).  Pass it only for tests
                that address a specific device of several.
            save_as: If set, save the trace to this filename in run_dir.
        """
        if reader is None:
            reader = int(os.environ.get("OPENSC_DEFAULT_READER", "0"))
        cmd = ["opensc-tool", "-c", "default", f"-r{reader}"]
        for apdu in apdus:
            cmd += ["-s", apdu]
        return self.run(cmd, save_as=save_as,
                        env_extra={"OPENSC_DEFAULT_READER": str(reader)})


def _write_trace_file(
    path: Path,
    cmd: list[str],
    returncode: int,
    elapsed_ms: float,
    stdout: str,
    stderr: str,
) -> None:
    """Write a human-readable trace file for a single CLI invocation."""
    ts = datetime.now(tz=timezone.utc).isoformat()
    cmd_str = " ".join(cmd)
    lines = [
        "=" * 80,
        f"TIMESTAMP : {ts}",
        f"COMMAND   : {cmd_str}",
        f"RETURNCODE: {returncode}",
        f"ELAPSED   : {elapsed_ms:.1f} ms",
        "=" * 80,
        "",
        "STDOUT:",
        "-" * 40,
        stdout,
        "",
        "STDERR (APDU TRACE):",
        "-" * 40,
        stderr,
        "",
    ]
    path.write_text("\n".join(lines), encoding="utf-8")
