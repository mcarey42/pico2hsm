#!/usr/bin/env python3
"""pico2hsm cluster daemon and management CLI.

Usage:
  hsm_daemon.py start [--pid-file=PATH] [--config=FILE] [--quorum=N]
  hsm_daemon.py stop [--pid-file=PATH]
  hsm_daemon.py status [--config=FILE]
  hsm_daemon.py sync <device-name> [--config=FILE]
  hsm_daemon.py verify-sync [--config=FILE]
  hsm_daemon.py export-state [--config=FILE]
  hsm_daemon.py enroll-peer <name> <address> [--cert=FILE] [--config=FILE]
"""

import argparse
import json
import logging
import os
import signal
import sys
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("hsm-daemon")

DEFAULT_PID_FILE = "/run/pico2hsm/daemon.pid"
DEFAULT_CONFIG = os.path.expanduser("~/.pico2hsm/config.json")


def cmd_start(args) -> int:
    """Start the daemon (forks to background if --pid-file given)."""
    from pico2hsm.config import PeerConfig
    from pico2hsm.daemon import DkekDaemon

    config = _load_config(args.config)
    daemon = DkekDaemon(config, quorum_required=args.quorum)

    if args.pid_file:
        # Fork to background
        try:
            pid = os.fork()
            if pid > 0:
                print(f"Daemon started (PID {pid})")
                return 0
        except AttributeError:
            # Windows -- no fork, run in foreground
            pass

    try:
        daemon.run(pid_file=args.pid_file)
    except KeyboardInterrupt:
        pass
    return 0


def cmd_stop(args) -> int:
    """Send SIGTERM to daemon PID."""
    pid_file = args.pid_file or DEFAULT_PID_FILE
    try:
        with open(pid_file) as f:
            pid = int(f.read().strip())
        os.kill(pid, signal.SIGTERM)
        print(f"Sent SIGTERM to PID {pid}")
        return 0
    except FileNotFoundError:
        print(f"PID file not found: {pid_file}")
        return 1
    except ProcessLookupError:
        print(f"Process {pid} not found (already stopped?)")
        return 0
    except Exception as e:
        print(f"Error stopping daemon: {e}")
        return 1


def cmd_status(args) -> int:
    """Print cluster status from StatePersistence."""
    from pico2hsm.state import StatePersistence

    config = _load_config(args.config)
    persistence = StatePersistence(config.state_dir)
    state = persistence.load()

    if not state.devices:
        print("No devices enrolled.")
        return 0

    print(f"Enrolled devices: {len(state.devices)}")
    for fp, dev in state.devices.items():
        print(f"  {dev.name}: gen={dev.last_generation}, "
              f"sync={dev.last_sync_result}, seen={dev.last_seen[:19]}")
    return 0


def cmd_sync(args) -> int:
    """Trigger manual sync for a named device."""
    print(f"Manual sync for '{args.device_name}' -- connect devices and use local sync")
    print("(Full network sync requires running daemon)")
    return 0


def cmd_verify_sync(args) -> int:
    """Fetch state hashes from all connected devices and compare."""
    try:
        from pico2hsm.device import Pico2HSM
        from pico2hsm.protocol import build_extras
        devices = Pico2HSM.list_devices() if hasattr(Pico2HSM, 'list_devices') else []
    except Exception:
        devices = []

    if not devices:
        print("No devices connected.")
        return 1

    roots = {}
    for i, dev in enumerate(devices):
        try:
            apdu = build_extras(0x36)
            data, sw = dev.transmit(apdu)
            if sw == 0x9000 and len(data) >= 40:
                root = data[8:40].hex()
                roots[f"device-{i}"] = root
                print(f"  device-{i}: root={root[:16]}...")
            else:
                print(f"  device-{i}: FAILED (SW={sw:04X})")
        except Exception as e:
            print(f"  device-{i}: ERROR: {e}")

    if len(set(roots.values())) <= 1 and roots:
        print("All devices in sync")
        return 0
    else:
        print("Devices OUT OF SYNC")
        return 2


def cmd_export_state(args) -> int:
    """Dump state.json to stdout."""
    from pico2hsm.state import StatePersistence

    config = _load_config(args.config)
    persistence = StatePersistence(config.state_dir)
    state = persistence.load()
    print(json.dumps(state.to_dict(), indent=2))
    return 0


def cmd_enroll_peer(args) -> int:
    """Add a peer to the config."""
    print(f"Enrolling peer '{args.name}' at {args.address}")
    # Load config, add peer entry, save
    config_path = Path(args.config or DEFAULT_CONFIG)
    if config_path.exists():
        with open(config_path) as f:
            data = json.load(f)
    else:
        data = {"peers": []}

    peer = {"name": args.name, "address": args.address, "role": "secondary"}
    if args.cert:
        peer["cert_path"] = args.cert

    # Remove existing entry with same name
    data.setdefault("peers", [])
    data["peers"] = [p for p in data["peers"] if p.get("name") != args.name]
    data["peers"].append(peer)

    config_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with open(config_path, "w") as f:
        json.dump(data, f, indent=2)
    print(f"Enrolled peer '{args.name}' in {config_path}")
    return 0


def _load_config(config_path=None):
    from pico2hsm.config import PeerConfig
    path = config_path or DEFAULT_CONFIG
    if os.path.exists(path):
        return PeerConfig.load(path)
    # Return a minimal config with no peers
    return PeerConfig(peers=[])


def main() -> int:
    parser = argparse.ArgumentParser(description="pico2hsm cluster daemon")
    parser.add_argument("--config", default=None, help="Config file path")

    sub = parser.add_subparsers(dest="command")

    p_start = sub.add_parser("start")
    p_start.add_argument("--pid-file", default=None)
    p_start.add_argument("--quorum", type=int, default=1)

    p_stop = sub.add_parser("stop")
    p_stop.add_argument("--pid-file", default=DEFAULT_PID_FILE)

    sub.add_parser("status")

    p_sync = sub.add_parser("sync")
    p_sync.add_argument("device_name")

    sub.add_parser("verify-sync")
    sub.add_parser("export-state")

    p_enroll = sub.add_parser("enroll-peer")
    p_enroll.add_argument("name")
    p_enroll.add_argument("address")
    p_enroll.add_argument("--cert", default=None)

    args = parser.parse_args()

    commands = {
        "start": cmd_start,
        "stop": cmd_stop,
        "status": cmd_status,
        "sync": cmd_sync,
        "verify-sync": cmd_verify_sync,
        "export-state": cmd_export_state,
        "enroll-peer": cmd_enroll_peer,
    }

    if args.command not in commands:
        parser.print_help()
        return 1

    return commands[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
