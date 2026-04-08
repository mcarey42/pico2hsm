# pico2hsm Python Cluster Daemon -- Operations and Reference Guide

## 1. Overview

The pico2hsm cluster daemon (`hsm_daemon.py`) is a long-running Python process that keeps multiple pico2hsm HSM devices synchronized. It automates three operations:

- **USB auto-sync**: When a secondary HSM is plugged in, the daemon detects it and synchronizes DKEK material and keys from the primary.
- **TCP peer sync**: Remote pico2hsm daemons connect over TCP (optionally with TLS) to exchange key manifests, DKEK-wrapped key blobs, and state hashes.
- **Periodic health check**: Every 60 seconds, the daemon queries all connected devices for their state root hash and logs whether the cluster is in sync.

**When to use the daemon vs. manual sync.** Use the daemon when you want unattended, automatic synchronization between two HSMs -- plug a device in and it catches up. For one-off operations (initial provisioning, testing, debugging), use the CLI subcommands (`hsm_daemon.py verify-sync`, `hsm_daemon.py export-state`) or the `pico2hsm` Python library directly.

**Relationship to firmware.** The daemon is a coordinator -- it mediates all communication between HSMs. Devices never communicate directly. The daemon issues firmware APDUs (`EXTRAS` subcommands 0x30-0x3C) to read device identity keys, initiate DKEK exchanges, fetch key manifests, and compare state hashes. The DKEK exchange uses a P-256 ECDH relay protocol where the host never sees plaintext DKEK material.

**Current scope.** V1 targets N=1 (standalone) and N=2 (primary + one hot standby) topologies. Quorum-gated multi-node (N>=3) is designed for but not yet shipped.

---

## 2. Architecture

### 2.1 Thread Model

The daemon runs four concurrent threads plus the main thread:

```
main thread
  |
  +-- TCP listener thread        (name: tcp-listener)
  |     Accepts inbound TCP connections from remote peer daemons.
  |     Spawns a handler thread per connection.
  |
  +-- USB monitor thread         (name: usb-monitor)
  |     Detects USB device connect events.
  |     Uses pyudev if available; falls back to polling every 5 seconds.
  |
  +-- Health check thread        (name: health-check)
  |     Every 60 seconds, queries all connected devices for state hashes
  |     and logs sync status.
  |
  +-- main loop
        Sleeps in 1-second intervals. Exits on SIGTERM or SIGINT.
```

All threads are daemon threads -- they terminate when the main thread exits. The main thread handles signal registration (SIGTERM, SIGINT) and PID file lifecycle.

### 2.2 Key Classes and Data Flow

```
hsm_daemon.py           CLI entry point; argparse dispatch
    |
    v
DkekDaemon              Top-level daemon class (daemon.py)
    |-- PeerConfig       Configuration (config.py)
    |-- StatePersistence  Disk-backed state (state.py)
    |-- SyncManager       Sync orchestration (sync.py)
    |     |-- DkekExchange     DKEK relay protocol (dkek.py)
    |     |-- DeviceEnrollment Device identity (enrollment.py)
    |     +-- key_transfer     Key export/import (key_transfer.py)
    +-- Pico2HSM          USB/PCSC device connection (device.py)
```

**Sync data flow (USB auto-sync):**

1. USB monitor detects a new device.
2. `_on_usb_connect_event()` checks `sync_on_connect` config flag.
3. Lists all connected `Pico2HSM` devices.
4. Finds the primary device (from config), identifies secondaries.
5. Calls `SyncManager.sync_local(primary, secondary)`.
6. `SyncManager` reads generation counters from both devices.
7. If secondary is behind, calls `DkekExchange.exchange_local_usb()` to relay the DKEK.
8. Updates `StatePersistence` with the result.

**Sync data flow (TCP peer sync):**

1. Remote daemon connects to the TCP listener.
2. `_handle_tcp_connection()` enters a message loop.
3. Remote sends `MANIFEST_REQ` -- local responds with `MANIFEST_RESP` from the primary HSM.
4. Remote sends `STATE_HASH_REQ` -- local responds with `STATE_HASH_RESP`.
5. Remote requests specific keys via `KEY_BLOB` messages.
6. Exchange ends with `SYNC_COMPLETE` carrying each side's state root for verification.

### 2.3 State Persistence

`StatePersistence` stores cluster state in `~/.pico2hsm/state.json` (configurable via `state_dir`). The state tracks:

- Enrolled device fingerprints and names
- Last known generation counter per device
- Last sync result ("success", "failed", "skipped")
- Last seen timestamp (ISO 8601)

The state file is written atomically (write to a temp file, then `os.replace()`) with permissions `0o600` in a directory with permissions `0o700`.

---

## 3. Installation

### 3.1 Python Dependencies

The daemon requires Python 3.10+ and the following packages (from `requirements.txt`):

| Package | Purpose |
|---|---|
| `pyscard>=2.0.7` | PCSC smartcard access (talks to pcscd) |
| `cryptography>=41.0.0` | TLS certificate generation, public key parsing |
| `pyyaml>=6.0` | Configuration file parsing |
| `pyudev>=0.24` | Efficient USB device monitoring (optional but recommended) |
| `click>=8.1.0` | CLI utilities |
| `tqdm>=4.66.0` | Progress bars for long operations |
| `base58>=2.1.1` | Key encoding |

### 3.2 Install

From the repository root:

```sh
pip install -e tools/python/
```

This installs the `pico2hsm` package and makes `hsm-tool` available as a console script.

For daemon operation, ensure `pcscd` is running:

```sh
sudo systemctl start pcscd
sudo systemctl enable pcscd
```

### 3.3 Optional: pyudev for Efficient USB Monitoring

Without `pyudev`, the daemon falls back to polling `Pico2HSM.list_device_paths()` every 5 seconds. With `pyudev`, it uses kernel netlink events for instant detection:

```sh
pip install pyudev
```

On systems without udev (macOS, some containers), the polling fallback is used automatically.

---

## 4. Configuration

The daemon reads a YAML configuration file. Default location: `~/.pico2hsm/config.json` (despite the `.json` extension, the loader uses `yaml.safe_load`, so both YAML and JSON are accepted).

### 4.1 PeerConfig Fields

| Field | Type | Default | Description |
|---|---|---|---|
| `listen_address` | string | `"0.0.0.0"` | IP address to bind the TCP listener |
| `listen_port` | int | `7890` | TCP port for peer connections. Set to `0` or omit to disable TCP listener |
| `state_dir` | string | `"~/.pico2hsm"` | Directory for `state.json` and TLS identity files |
| `log_level` | string | `"INFO"` | Python logging level (`DEBUG`, `INFO`, `WARNING`, `ERROR`) |
| `sync_on_connect` | bool | `true` | Auto-sync secondary devices when USB connect is detected |
| `tls_enabled` | bool | `true` | Use TLS for TCP transport |
| `identity_cert` | string | null | Path to this daemon's TLS certificate (auto-generated if absent) |
| `identity_key` | string | null | Path to this daemon's TLS private key (auto-generated if absent) |
| `cluster_id` | string | `"default-cluster"` | Cluster identifier for enrollment |
| `peers` | list | `[]` | List of peer entries (see below) |

### 4.2 Peer Entry Fields

Each entry in the `peers` list:

| Field | Type | Required | Description |
|---|---|---|---|
| `name` | string | yes | Unique human-readable name for this peer |
| `role` | string | no (default: `"secondary"`) | One of `"primary"`, `"secondary"`, or `"quorum-member"` |
| `public_key_file` | string | yes (or `public_key`) | Path to PEM file containing the peer's P-256 public key |
| `public_key` | string | yes (or `public_key_file`) | Base64-encoded DER public key (inline alternative) |
| `address` | string | no | `"host:port"` for TCP sync. Omit for USB-only peers |
| `cert_path` | string | no | Path to the peer's TLS certificate for mTLS verification |

Validation rules:
- Exactly one peer may have `role: primary`. Zero is allowed (USB-only, no primary designation).
- No duplicate peer names.
- Public keys must be 65-byte uncompressed P-256 points.

### 4.3 Example: Single-Node (Standalone)

```yaml
# ~/.pico2hsm/config.yaml
# No peers, no TCP listener -- just USB monitoring and health checks.
listen_port: 0
state_dir: "~/.pico2hsm"
sync_on_connect: false
```

### 4.4 Example: Two-Node Mirrored Setup

**Node A** (primary, at 192.168.1.10):

```yaml
# /etc/pico2hsm/config.yaml on Node A
listen_address: "0.0.0.0"
listen_port: 7890
state_dir: "/var/lib/pico2hsm"
log_level: "INFO"
sync_on_connect: true
tls_enabled: true
cluster_id: "prod-cluster"

peers:
  - name: "hsm-primary"
    role: "primary"
    public_key_file: "/etc/pico2hsm/keys/hsm-primary.pub.pem"

  - name: "hsm-secondary"
    role: "secondary"
    public_key_file: "/etc/pico2hsm/keys/hsm-secondary.pub.pem"
    address: "192.168.1.11:7890"
    cert_path: "/etc/pico2hsm/certs/node-b.crt"
```

**Node B** (secondary, at 192.168.1.11):

```yaml
# /etc/pico2hsm/config.yaml on Node B
listen_address: "0.0.0.0"
listen_port: 7890
state_dir: "/var/lib/pico2hsm"
log_level: "INFO"
sync_on_connect: true
tls_enabled: true
cluster_id: "prod-cluster"

peers:
  - name: "hsm-primary"
    role: "primary"
    public_key_file: "/etc/pico2hsm/keys/hsm-primary.pub.pem"
    address: "192.168.1.10:7890"
    cert_path: "/etc/pico2hsm/certs/node-a.crt"

  - name: "hsm-secondary"
    role: "secondary"
    public_key_file: "/etc/pico2hsm/keys/hsm-secondary.pub.pem"
```

### 4.5 Obtaining Device Public Keys

To enroll a device, extract its P-256 identity key:

```python
from pico2hsm import Pico2HSM
from pico2hsm.enrollment import DeviceEnrollment

with Pico2HSM() as hsm:
    hsm.connect()
    hsm.select_applet()
    info = DeviceEnrollment.get_device_info(hsm)
    DeviceEnrollment.save_pubkey_pem(info.pubkey, "/etc/pico2hsm/keys/hsm-primary.pub.pem")
    print(f"Fingerprint: {info.fingerprint}")
```

Or use the CLI:

```sh
hsm_daemon.py enroll-peer hsm-secondary 192.168.1.11:7890 --cert /path/to/cert.pem
```

---

## 5. Running the Daemon

### 5.1 Starting

**Foreground (for debugging):**

```sh
python tools/python/hsm_daemon.py start --config /etc/pico2hsm/config.yaml
```

**Background with PID file:**

```sh
python tools/python/hsm_daemon.py start \
    --config /etc/pico2hsm/config.yaml \
    --pid-file /run/pico2hsm/daemon.pid \
    --quorum 1
```

When `--pid-file` is given, the process forks to the background. The parent prints the child PID and exits.

Options:

| Flag | Default | Description |
|---|---|---|
| `--config FILE` | `~/.pico2hsm/config.json` | Path to YAML/JSON config file |
| `--pid-file PATH` | (none -- foreground) | Write PID here and fork to background |
| `--quorum N` | `1` | Number of devices that must confirm the current generation before syncing a lagging device. `1` means sync immediately |

### 5.2 Stopping

```sh
python tools/python/hsm_daemon.py stop --pid-file /run/pico2hsm/daemon.pid
```

This reads the PID file and sends `SIGTERM`. The daemon cleans up the PID file on exit.

### 5.3 Signal Handling

| Signal | Behavior |
|---|---|
| `SIGTERM` | Clean shutdown: sets `_running = False`, removes PID file, exits |
| `SIGINT` | Same as SIGTERM (Ctrl-C in foreground mode) |

Signal handlers are only registered when running on the main thread. If the daemon is started from a non-main thread (e.g., in tests), signals are not intercepted.

### 5.4 Other CLI Subcommands

```sh
# Print enrolled devices and their sync status
hsm_daemon.py status --config /etc/pico2hsm/config.yaml

# Check if all connected devices have matching state roots
hsm_daemon.py verify-sync --config /etc/pico2hsm/config.yaml

# Dump the full state.json to stdout
hsm_daemon.py export-state --config /etc/pico2hsm/config.yaml

# Enroll a remote peer
hsm_daemon.py enroll-peer node-b 192.168.1.11:7890 --cert /path/to/cert.pem
```

### 5.5 Logging

Logging uses Python's `logging` module. Format:

```
2026-04-08 14:22:01,234 INFO pico2hsm.daemon: pico2hsm DKEK daemon running (quorum=1)
```

Set the log level in the config file (`log_level: "DEBUG"`) or via the `LOGGING` environment before starting. Key log lines to watch:

| Log line | Meaning |
|---|---|
| `TCP listener started on 0.0.0.0:7890` | TCP listener is accepting connections |
| `USB monitor started` | USB device monitoring is active |
| `Health check: cluster IN SYNC (a1b2c3d4)` | All connected devices share the same state root |
| `Health check: cluster OUT OF SYNC: {...}` | Devices have divergent state roots |
| `Auto-sync: attempting primary -> secondary` | USB connect triggered an automatic sync |
| `Auto-sync complete: Sync successful` | Auto-sync succeeded |
| `TCP connection from ('192.168.1.11', 45678)` | Remote peer connected |
| `Quorum not met: 1/3 devices confirmed` | Sync deferred because not enough devices have the current generation |
| `Received signal 15 -- shutting down` | Clean shutdown initiated |

---

## 6. systemd Integration

### 6.1 Unit File

Create `/etc/systemd/system/pico2hsm-daemon.service`:

```ini
[Unit]
Description=pico2hsm Cluster Sync Daemon
Documentation=https://github.com/pico2hsm/pico2hsm
After=network.target pcscd.service
Requires=pcscd.service

[Service]
Type=forking
User=pico2hsm
Group=pico2hsm

ExecStartPre=/usr/bin/mkdir -p /run/pico2hsm
ExecStartPre=/usr/bin/chown pico2hsm:pico2hsm /run/pico2hsm

ExecStart=/usr/bin/python3 /opt/pico2hsm/tools/python/hsm_daemon.py start \
    --config /etc/pico2hsm/config.yaml \
    --pid-file /run/pico2hsm/daemon.pid \
    --quorum 1

ExecStop=/usr/bin/python3 /opt/pico2hsm/tools/python/hsm_daemon.py stop \
    --pid-file /run/pico2hsm/daemon.pid

PIDFile=/run/pico2hsm/daemon.pid

Restart=on-failure
RestartSec=10

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/pico2hsm /run/pico2hsm
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

### 6.2 Setup

```sh
# Create service user
sudo useradd -r -s /usr/sbin/nologin -d /var/lib/pico2hsm pico2hsm

# Create directories
sudo mkdir -p /var/lib/pico2hsm /etc/pico2hsm/keys /etc/pico2hsm/certs
sudo chown -R pico2hsm:pico2hsm /var/lib/pico2hsm

# Grant USB/smartcard access (add to plugdev or create udev rule)
sudo usermod -aG plugdev pico2hsm

# Install and enable
sudo systemctl daemon-reload
sudo systemctl enable pico2hsm-daemon
sudo systemctl start pico2hsm-daemon

# Check status
sudo systemctl status pico2hsm-daemon
sudo journalctl -u pico2hsm-daemon -f
```

### 6.3 Notes

- The daemon forks when `--pid-file` is given, so `Type=forking` is correct.
- `Requires=pcscd.service` ensures pcscd is started first. Without pcscd, the daemon cannot communicate with any HSM.
- The `ReadWritePaths` directive restricts filesystem writes to the state directory and PID directory.
- For `Type=simple` (no fork), remove `--pid-file` and `PIDFile=`, and change `Type=forking` to `Type=simple`.

---

## 7. Sync Modes

### 7.1 USB Auto-Sync

**Trigger:** A USB device add event is detected (via pyudev or polling fallback).

**What happens:**

1. The daemon waits 2 seconds for USB enumeration to complete.
2. It lists all connected `Pico2HSM` devices.
3. If `sync_on_connect` is `true` and a primary is configured, it attempts to sync the primary to each configured secondary.
4. Sync uses `SyncManager.sync_local()`, which:
   - Reads generation counters from both devices via `EXTRAS GET_GENERATION` (P1=0x34).
   - If the secondary is already at or ahead of the primary's generation, sync is skipped.
   - If quorum is required (`--quorum N` with N > 1), checks that N other devices have confirmed the primary's generation before proceeding.
   - Calls `DkekExchange.exchange_local_usb()` to relay the DKEK via the 4-step P-256 ECDH protocol.
   - Updates `state.json` with the result.

**Disable:** Set `sync_on_connect: false` in the config file.

**Polling fallback behavior:** Without pyudev, the daemon checks for new device paths every 5 seconds. This means there may be up to a 7-second delay (5s poll + 2s enumeration wait) before sync begins.

### 7.2 TCP Peer Sync

**Protocol:** TCP with optional TLS, using the `P2H1` binary framing format.

**Frame format:**

```
[4 bytes: magic "P2H1"] [1 byte: msg_type] [4 bytes: BE payload length] [payload]
```

Maximum payload size: 65536 bytes (enforced on receive to prevent allocation attacks).

**Message types:**

| Code | Name | Direction | Payload |
|---|---|---|---|
| `0x01` | `NOISE` | bidirectional | DKEK exchange protocol data |
| `0x05` | `DEV_PUBKEY` | bidirectional | 65-byte uncompressed P-256 public key |
| `0x06` | `EPHEM_PUB` | bidirectional | 65-byte ephemeral public key |
| `0x07` | `ENC_DKEK` | source -> target | 60 bytes: nonce(12) + ciphertext(32) + tag(16) |
| `0x10` | `MANIFEST_REQ` | requester -> server | empty |
| `0x11` | `MANIFEST_RESP` | server -> requester | Serialized key manifest |
| `0x12` | `KEY_BLOB` | bidirectional | key_ref(1) + DKEK-wrapped key blob |
| `0x13` | `SYNC_COMPLETE` | bidirectional | state_root(32) |
| `0x14` | `STATE_HASH_REQ` | requester -> server | empty |
| `0x15` | `STATE_HASH_RESP` | server -> requester | generation(8) + state_root(32) + signature(64) = 104 bytes |
| `0x20` | `TOMBSTONE` | primary -> secondary | Tombstone record |
| `0x21` | `PROMOTE_PRIMARY` | operator | device_id(16) + operator_sig(64) |
| `0xFF` | `ACK` | bidirectional | empty or context-dependent |

**TCP connection lifecycle:**

1. Remote peer connects (TLS handshake if `tls_enabled`).
2. Connection handler loops, processing messages until `ACK`, `SYNC_COMPLETE`, an unknown message type, or timeout (30 seconds idle).
3. The handler serves data from the locally connected primary HSM.

**TLS:** When `tls_enabled` is `true`, the server wraps the socket with TLS using its daemon identity certificate. If no identity cert/key is configured, an ephemeral self-signed RSA-2048 certificate is generated. The current implementation uses `CERT_NONE` on both sides (anonymous TLS, protecting against passive eavesdroppers). Full mTLS with certificate pinning is planned.

### 7.3 Periodic Health Check

**Interval:** Every 60 seconds (implemented as 60 x 1-second sleeps for clean shutdown responsiveness).

**What it checks:**

1. Lists all connected `Pico2HSM` devices.
2. If two or more devices are connected, sends `EXTRAS GET_STATE_HASH` (P1=0x36) to each.
3. Parses the response: 8 bytes generation + 32 bytes state root + 64 bytes signature = 104 bytes total.
4. Compares state roots across all devices.

**Log output:**

- `Health check: cluster IN SYNC (a1b2c3d4)` -- all devices share the same state root (first 8 hex chars shown).
- `Health check: cluster OUT OF SYNC: {'device-0': 'a1b2...', 'device-1': 'c3d4...'}` -- state roots differ.
- If fewer than 2 devices are connected, no health check output is logged.

---

## 8. Cluster Topology

### 8.1 Primary vs. Secondary

- **Primary**: The authoritative source of DKEK material and keys. Exactly zero or one peer in the config has `role: primary`.
- **Secondary**: Receives DKEK and key state from the primary. Can have any number of secondaries.
- **Quorum-member**: Participates in quorum counting but is neither primary nor secondary. Reserved for future N>=3 topologies.

The primary/secondary distinction is purely a sync direction indicator. Both devices are fully functional HSMs that can independently sign, decrypt, and wrap keys. The daemon simply uses the primary as the source of truth for sync operations.

### 8.2 Two-Device Mirrored Setup

This is the recommended V1 deployment:

1. **Provision both devices.** Initialize each HSM with the same SO-PIN and user PIN.

2. **Extract identity keys.** Connect each device and save its P-256 public key to a PEM file.

3. **Configure both nodes.** Each node's config lists both peers with their public keys. The primary peer entry has `role: primary`.

4. **Start daemons.** Start the daemon on both hosts. When the secondary connects (USB or TCP), sync begins automatically.

5. **Verify sync.** Run `hsm_daemon.py verify-sync` to confirm both devices report the same state root.

**Failover:** If the primary fails, the secondary continues to operate independently (it holds the same DKEK and all keys). Promoting a secondary to primary is currently a manual config change -- update the peer roles in the config file and restart the daemon.

### 8.3 Quorum Semantics

The `--quorum N` flag controls how many devices must have confirmed the primary's current generation before the daemon will sync a lagging device. This prevents syncing stale state if the primary has regressed (e.g., after a re-initialization).

- `--quorum 1` (default): Sync immediately. No quorum check.
- `--quorum 2`: At least 2 devices (excluding the target) must be at the primary's generation before sync proceeds.

If quorum is not met, sync is deferred with a log warning: `Quorum not met: 1/3 devices confirmed generation 10 (excluding secondary). Sync deferred until quorum is reached.`

Quorum is evaluated against the `state.json` device records, not live device queries. This means a device that was seen at the correct generation in a previous run counts toward quorum.

---

## 9. Troubleshooting

### Daemon fails to start

**Symptom:** `DeviceNotFoundError: No PCSC readers found`

**Cause:** pcscd is not running or the HSM is not plugged in.

**Fix:**
```sh
sudo systemctl start pcscd
opensc-tool --list-readers    # verify the device is visible
```

**Symptom:** `OSError: [Errno 98] Address already in use`

**Cause:** Another process (or a previous daemon instance) is already listening on the configured port.

**Fix:**
```sh
# Find what is using the port
ss -tlnp | grep 7890
# Stop the old daemon
python tools/python/hsm_daemon.py stop --pid-file /run/pico2hsm/daemon.pid
# Or kill the process directly
kill $(cat /run/pico2hsm/daemon.pid)
```

**Symptom:** `ConfigError: Failed to read config`

**Cause:** Config file is missing, not valid YAML, or has schema errors.

**Fix:** Verify the config path exists and is valid YAML. Common mistakes:
- Missing `public_key_file` or `public_key` on a peer entry.
- More than one peer with `role: primary`.
- Invalid role value (must be `primary`, `secondary`, or `quorum-member`).

### Sync fails

**Symptom:** `Auto-sync failed: ...` or `SyncError: Sync failed: ...`

**Possible causes and diagnosis:**

1. **State root mismatch after sync.** The log will show `Verification: state roots MISMATCH after sync`. This means the key transfer completed but the devices ended up in different states. Possible causes: concurrent key operations during sync, or a firmware bug.

2. **DKEK exchange failed.** Look for `DKEKError` in the logs. Common causes:
   - Device returned unexpected pubkey length (device not initialized or wrong applet selected).
   - Enrollment check failed (`EnrollmentError: Device with pubkey ... is not enrolled`).

3. **Quorum not met.** `Quorum not met: 1/3 devices confirmed generation 10`. Wait for more devices to come online, or reduce the quorum requirement.

4. **Generation counters.** If the secondary's generation is already >= the primary's, sync is skipped (this is normal: `Already in sync`).

### USB monitor not working

**Symptom:** Plugging in a device does not trigger auto-sync.

**Diagnosis:**
```sh
# Check if pyudev is installed
python -c "import pyudev; print('pyudev available')"
```

If pyudev is not installed, the daemon uses polling (5-second intervals). Look for the log line:

```
pyudev not available; falling back to USB polling
```

**Fix:**
```sh
pip install pyudev
```

Also verify `sync_on_connect: true` in the config.

### TCP connection refused

**Symptom:** Remote peer cannot connect to the daemon's TCP listener.

**Diagnosis:**

1. Verify the listener is running:
   ```sh
   ss -tlnp | grep 7890
   ```

2. Check firewall rules:
   ```sh
   sudo iptables -L -n | grep 7890
   # or
   sudo ufw status
   ```

3. Verify `listen_port` is set in the config (default: 7890, set to 0 to disable).

4. If connecting across a NAT, ensure port forwarding is configured. V1 supports direct TCP and outbound-connects-to-reachable-host models only.

---

## 10. Security Notes

### 10.1 DKEK Protection in Transit

The DKEK never passes through the host in plaintext. The exchange uses the P-256 ECDH relay protocol:

1. Each HSM generates an ephemeral P-256 keypair.
2. The host relays public keys between the two HSMs.
3. Each HSM independently computes a shared session key via ECDH + HKDF-SHA256.
4. The source encrypts the DKEK with AES-256-GCM using the session key.
5. The host forwards the ciphertext; the target decrypts on-device.

The host sees only ciphertexts and public keys. Even a fully compromised host cannot extract the DKEK.

**Limitation:** The V1 protocol does not include mutual HSM authentication or replay protection. These are specified in `CLUSTER_PLAN_V2.md` and will be implemented before production deployment.

### 10.2 TCP Transport Encryption

When `tls_enabled` is `true`, TCP connections are wrapped with TLS. The current implementation uses anonymous TLS (`CERT_NONE` on both sides), which protects against passive eavesdropping but not active man-in-the-middle attacks.

The planned upgrade path (from `CLUSTER_PLAN_V2.md`):
- Each daemon generates a persistent X.509 identity certificate at first run.
- Peer daemons enroll each other's certificate fingerprint during cluster formation.
- mTLS with certificate pinning replaces anonymous TLS.
- The HSM signs the TLS certificate fingerprint (`SIGN_ENROLLMENT` APDU), binding the TLS identity to a physical device.

### 10.3 TLS Identity Management

The `tls.py` module manages daemon TLS identities:

- On first run, generates an RSA-2048 self-signed certificate with CN=`pico2hsm-daemon`, valid for 10 years.
- Private key is stored with permissions `0o600`; certificate with `0o644`.
- Files are stored in the `state_dir` as `daemon.crt` and `daemon.key`.
- Key file permissions are checked on startup; a warning is logged if they are too permissive.

### 10.4 State File Security

- `state.json` is stored in a directory with permissions `0o700`.
- The file itself is written with permissions `0o600`.
- Writes use atomic replacement (`tempfile.mkstemp` + `os.replace`) to prevent corruption from crashes or concurrent writes.
- Schema validation is applied when loading: unknown fields are ignored with a warning, and type mismatches cause individual device entries to be skipped.

### 10.5 PID File

The PID file (default: `/run/pico2hsm/daemon.pid`) is written at startup and removed at shutdown. It contains the daemon process ID as a decimal string. The `stop` command reads this file and sends `SIGTERM`.

### 10.6 Running as Non-Root

The daemon does not require root. It needs:

- Read/write access to the PCSC daemon socket (typically requires membership in the `plugdev` or `pcscd` group).
- Read/write access to the state directory.
- Permission to bind the configured TCP port (ports >= 1024 do not require root).

The systemd unit file above uses a dedicated `pico2hsm` user with minimal filesystem access via `ProtectSystem=strict` and `ReadWritePaths`.

### 10.7 Known Limitations

- **Anonymous TLS.** Active network attackers can MITM TCP connections. Mitigated by DKEK-level encryption (attacker cannot extract key material even with a MITM), but state hash comparison could be spoofed.
- **No HSM mutual authentication.** The relay protocol in V1 does not verify that the ephemeral keys came from enrolled devices. Planned for V2.
- **No replay protection.** A captured DKEK exchange session could theoretically be replayed. Planned for V2.
- **Daemon trust.** The daemon is trusted to correctly route messages and report state. A compromised daemon could suppress sync events or lie about state hashes. HSM-signed attestations (V2) address this.
