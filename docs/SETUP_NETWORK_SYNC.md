# Network Sync Setup (Two Hosts)

> **Superseded by [CLUSTER_PLAN_V3.md](CLUSTER_PLAN_V3.md).** This guide
> describes 1.x two-host sync through the Python daemon.
> Domains, enrollment against any member, and multi-way sync replace
> this model. The production daemon will be `pico2hsm-syncd`, in the
> companion pico2hsm-tool repository; the Python daemon is kept only as a
> reference and test harness. Daemon and peer-enrollment steps below may not
> match current firmware. Keys from 1.x do not carry over to 2.0.

A complete guide for synchronizing pico2hsm devices across two separate
hosts over a network. This covers firewall configuration, TLS identity
setup, daemon configuration, and verification procedures.

For local (same-host) mirrored setup, see
[SETUP_LOCAL_CLUSTER.md](SETUP_LOCAL_CLUSTER.md).
For single-device setup, see
[SINGLE_DEVICE_SETUP.md](SINGLE_DEVICE_SETUP.md).
For daemon internals and reference, see
[PYTHON_DAEMON.md](PYTHON_DAEMON.md).

---

## 1. Architecture Overview

```
+--------------------------+          +--------------------------+
|   Host A (Primary)       |          |   Host B (Secondary)     |
|                          |          |                          |
|  +------------------+    |   TCP    |    +------------------+  |
|  | pico2hsm-daemon  |<---+--/TLS---+--->| pico2hsm-daemon  |  |
|  +--------+---------+    |  :7890   |    +--------+---------+  |
|           | USB          |          |             | USB         |
|  +--------v---------+    |          |    +--------v---------+  |
|  |  pico2hsm HSM    |    |          |    |  pico2hsm HSM    |  |
|  +------------------+    |          |    +------------------+  |
+--------------------------+          +--------------------------+
```

Each host runs an instance of `hsm_daemon.py` connected to a local
pico2hsm device over USB. The daemons communicate over TCP port 7890
(configurable) using the `P2H1` binary framing protocol, optionally
wrapped in TLS.

**Sync flow:** When a remote peer connects, the daemon serving the
primary HSM responds to manifest requests, state hash queries, and
key blob export requests. The secondary-side daemon compares its local
state root against the primary's, identifies missing keys via manifest
diff, and requests DKEK-wrapped key blobs for any keys it lacks. Key
material never passes through either host in plaintext -- the DKEK
wrapping ensures only a device initialized with the same DKEK share can
unwrap the blobs. A periodic health check (every 60 seconds) queries
both local devices and logs whether the cluster is in sync.

---

## 2. Prerequisites

Before starting, ensure:

- **Network connectivity.** Host A and Host B can reach each other on
  TCP port 7890 (or your chosen port). See section 3 for firewall rules.
- **Matching DKEK shares.** Both HSMs must be initialized with the same
  DKEK share. If this has not been done, follow the initialization
  procedure in
  [SETUP_LOCAL_CLUSTER.md](SETUP_LOCAL_CLUSTER.md) (steps 1-3)
  first. This is the most common cause of sync failures.
- **pico2hsm daemon installed on both hosts.** From the repository root:

  ```sh
  pip install -e tools/python/
  ```

  Verify the install:

  ```sh
  python3 tools/python/hsm_daemon.py --help
  ```

- **pcscd running on both hosts.** The daemon communicates with the HSM
  via PC/SC:

  ```sh
  sudo systemctl start pcscd
  sudo systemctl enable pcscd
  opensc-tool --list-readers   # verify the device appears
  ```

- **openssl available on both hosts** (for verifying TLS fingerprints):

  ```sh
  openssl version
  ```

- **Python 3.10+** with `pyscard`, `cryptography`, and `pyyaml`
  installed (pulled in by `pip install -e tools/python/`).

**Connectivity test:**

```sh
# From Host B, verify Host A is reachable on port 7890
nc -zv 192.168.1.10 7890

# Alternative using curl
curl -v telnet://192.168.1.10:7890
```

If the port is not yet open (daemon not started), this will fail with
"Connection refused" -- that is expected. The test confirms the network
path is clear once the daemon is running.

---

## 3. Network and Firewall Requirements

The daemon listens on TCP port 7890 by default (configurable via
`listen_port` in the config file). Both directions must be permitted:
either host may initiate connections depending on your topology.

**Minimum requirements:**

- TCP port 7890 open between Host A and Host B
- Bidirectional: both daemons accept inbound connections
- Recommended: use a dedicated private network interface (VLAN, VPN
  tunnel, or dedicated management network) rather than exposing port
  7890 on a public interface

### UFW (Ubuntu/Debian)

```sh
# On Host A, allow inbound from Host B only
sudo ufw allow from 192.168.1.11 to any port 7890 proto tcp

# On Host B, allow inbound from Host A only
sudo ufw allow from 192.168.1.10 to any port 7890 proto tcp

# Verify
sudo ufw status
```

### iptables

```sh
# On Host A
sudo iptables -A INPUT -p tcp --dport 7890 -s 192.168.1.11 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 7890 -j DROP

# On Host B
sudo iptables -A INPUT -p tcp --dport 7890 -s 192.168.1.10 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 7890 -j DROP

# Persist across reboots (Debian/Ubuntu)
sudo apt install iptables-persistent
sudo netfilter-persistent save
```

### nftables

```sh
# On Host A
sudo nft add rule inet filter input tcp dport 7890 ip saddr 192.168.1.11 accept
sudo nft add rule inet filter input tcp dport 7890 drop
```

### Cloud security groups (AWS / GCP / Azure)

Create a security group rule allowing TCP 7890 inbound from the peer
host's IP or security group. In AWS, this is an inbound rule on both
instances' security groups. In GCP, create a firewall rule scoped to
the relevant network tags. In Azure, add an inbound NSG rule.

> **Note:** Even with TLS enabled, restrict the port to known peer IPs.
> Defense in depth -- do not rely solely on TLS for access control.

---

## 4. TLS Setup

The daemon uses identity-based TLS: each daemon generates a self-signed
RSA-2048 certificate on first start. Peers authenticate by certificate
fingerprint, not by a shared CA. This is a trust-on-first-use (TOFU)
model similar to SSH host keys.

### 4.1 Generate identity certificates

Start each daemon once to trigger certificate generation. The daemon
will create `daemon.crt` and `daemon.key` in the state directory.

**On Host A:**

```sh
# Create the state directory
sudo mkdir -p /var/lib/pico2hsm
sudo chown pico2hsm:pico2hsm /var/lib/pico2hsm

# Start the daemon briefly to generate the identity cert
python3 tools/python/hsm_daemon.py start \
  --config /etc/pico2hsm/daemon.yaml
# Press Ctrl-C after you see "TCP listener started" in the log
```

The daemon writes:

- `/var/lib/pico2hsm/daemon.crt` (permissions 0644)
- `/var/lib/pico2hsm/daemon.key` (permissions 0600)

**On Host B:**

```sh
sudo mkdir -p /var/lib/pico2hsm
sudo chown pico2hsm:pico2hsm /var/lib/pico2hsm

python3 tools/python/hsm_daemon.py start \
  --config /etc/pico2hsm/daemon.yaml
# Ctrl-C after cert is generated
```

### 4.2 Extract fingerprints

```sh
# On Host A
openssl x509 -in /var/lib/pico2hsm/daemon.crt -fingerprint -sha256 -noout
# Output: sha256 Fingerprint=AB:CD:12:34:...
```

```sh
# On Host B
openssl x509 -in /var/lib/pico2hsm/daemon.crt -fingerprint -sha256 -noout
# Output: sha256 Fingerprint=EF:56:78:90:...
```

### 4.3 Exchange fingerprints out-of-band

> **Security:** Exchange fingerprints through a trusted channel --
> SSH session from a trusted host, encrypted messaging, or read them
> aloud over a phone call. Do not send fingerprints over the same
> network path that will carry the sync traffic. An attacker who can
> tamper with both the fingerprint exchange and the network traffic
> can mount a man-in-the-middle attack.

Record the fingerprints. You will add Host B's fingerprint to Host A's
config and vice versa.

### 4.4 Exchange certificates for mTLS

For full mutual TLS verification, copy each host's certificate to the
other host:

```sh
# Copy Host A's cert to Host B
scp /var/lib/pico2hsm/daemon.crt hostB:/etc/pico2hsm/certs/host-a.crt

# Copy Host B's cert to Host A
scp /var/lib/pico2hsm/daemon.crt hostA:/etc/pico2hsm/certs/host-b.crt
```

Verify the copied certificate matches the fingerprint you recorded:

```sh
# On Host A, verify Host B's cert
openssl x509 -in /etc/pico2hsm/certs/host-b.crt -fingerprint -sha256 -noout
# Must match the fingerprint from step 4.2
```

---

## 5. Configuration -- Host A (Primary)

Create `/etc/pico2hsm/daemon.yaml` on Host A:

```yaml
# Host A -- Primary node
# Listens for incoming connections AND connects to secondary.

listen_address: "0.0.0.0"       # Accept connections from Host B
listen_port: 7890

state_dir: "/var/lib/pico2hsm"
log_level: "INFO"

sync_on_connect: true            # Sync when secondary connects via USB
tls_enabled: true                # Required for network sync

# Cluster identifier (must match on both hosts)
cluster_id: "prod-cluster"

peers:
  - name: "hsm-primary"
    role: "primary"
    # P-256 identity key extracted from the primary HSM device.
    # See section 8 for how to obtain this.
    public_key_file: "/etc/pico2hsm/keys/hsm-primary.pub.pem"

  - name: "hsm-secondary"
    role: "secondary"
    public_key_file: "/etc/pico2hsm/keys/hsm-secondary.pub.pem"
    address: "192.168.1.11:7890"    # Host B's IP or hostname
    # TLS certificate from Host B (copied in step 4.4)
    cert_path: "/etc/pico2hsm/certs/host-b.crt"
```

> **Note:** The `peers` list describes the HSM devices, not the hosts.
> The `address` field on a peer entry tells this daemon where to reach
> the remote daemon that has that device connected. The primary peer
> entry typically has no `address` (it is local to this host).

---

## 6. Configuration -- Host B (Secondary)

Create `/etc/pico2hsm/daemon.yaml` on Host B:

```yaml
# Host B -- Secondary node

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
    address: "192.168.1.10:7890"    # Host A's IP or hostname
    cert_path: "/etc/pico2hsm/certs/host-a.crt"

  - name: "hsm-secondary"
    role: "secondary"
    public_key_file: "/etc/pico2hsm/keys/hsm-secondary.pub.pem"
    # No address -- this device is local to this host
```

**Configuration validation rules:**

- Exactly one peer may have `role: primary`
- No duplicate peer names
- Every peer must have either `public_key_file` or `public_key`
  (base64-encoded DER)
- Public keys must be 65-byte uncompressed P-256 points

---

## 7. Starting the Daemons

Start Host A first, verify it is listening, then start Host B.

### 7.1 Start Host A

```sh
# Start the daemon
sudo systemctl start pico2hsm-daemon.service

# Verify it is running
sudo systemctl status pico2hsm-daemon.service

# Confirm the TCP listener is active
ss -tlnp | grep 7890
# Expected output:
# LISTEN  0  5  0.0.0.0:7890  0.0.0.0:*  users:(("python3",pid=12345,fd=6))
```

### 7.2 Start Host B

```sh
sudo systemctl start pico2hsm-daemon.service

# Watch the logs on both hosts
journalctl -u pico2hsm-daemon -f
```

### 7.3 Expected log output on successful connection

**Host A (primary):**

```
2026-04-08 10:00:01,234 INFO pico2hsm.daemon: TCP listener started on 0.0.0.0:7890
2026-04-08 10:00:01,235 INFO pico2hsm.daemon: USB monitor started
2026-04-08 10:00:01,236 INFO pico2hsm.daemon: Health check started
2026-04-08 10:00:01,237 INFO pico2hsm.daemon: pico2hsm DKEK daemon running (quorum=1)
2026-04-08 10:00:15,100 INFO pico2hsm.daemon: TCP connection from ('192.168.1.11', 48372)
2026-04-08 10:00:15,250 INFO pico2hsm.daemon: TCP sync complete from ('192.168.1.11', 48372): roots_match=True
```

**Host B (secondary):**

```
2026-04-08 10:00:10,500 INFO pico2hsm.daemon: TCP listener started on 0.0.0.0:7890
2026-04-08 10:00:10,501 INFO pico2hsm.daemon: USB monitor started
2026-04-08 10:00:10,502 INFO pico2hsm.daemon: pico2hsm DKEK daemon running (quorum=1)
```

If `sync_on_connect` is true on both sides and you are also running
local USB monitoring, you may see additional auto-sync log lines.

### 7.4 Without systemd (foreground mode)

If you have not set up the systemd unit file, run in the foreground:

```sh
# Host A (in a terminal or tmux session)
python3 /opt/pico2hsm/tools/python/hsm_daemon.py start \
  --config /etc/pico2hsm/daemon.yaml

# Host B (in a terminal or tmux session)
python3 /opt/pico2hsm/tools/python/hsm_daemon.py start \
  --config /etc/pico2hsm/daemon.yaml
```

See [PYTHON_DAEMON.md](PYTHON_DAEMON.md) section 6 for the full
systemd unit file and setup instructions.

---

## 8. Enrollment (First-Time Peer Registration)

Before sync can work, each daemon must know the P-256 identity public
key of both HSM devices. This is a one-time setup step.

### 8.1 Extract device public keys

Connect each HSM and extract its identity key:

```python
from pico2hsm import Pico2HSM
from pico2hsm.enrollment import DeviceEnrollment

with Pico2HSM() as hsm:
    hsm.connect()
    hsm.select_applet()
    info = DeviceEnrollment.get_device_info(hsm)
    DeviceEnrollment.save_pubkey_pem(
        info.pubkey,
        "/etc/pico2hsm/keys/hsm-primary.pub.pem"
    )
    print(f"Fingerprint: {info.fingerprint}")
```

Repeat on Host B for the secondary device, saving to
`/etc/pico2hsm/keys/hsm-secondary.pub.pem`.

### 8.2 Distribute public keys

Copy the public key files to both hosts:

```sh
# From Host A, send both keys to Host B
scp /etc/pico2hsm/keys/hsm-primary.pub.pem \
    hostB:/etc/pico2hsm/keys/hsm-primary.pub.pem

# From Host B, send secondary key to Host A
scp /etc/pico2hsm/keys/hsm-secondary.pub.pem \
    hostA:/etc/pico2hsm/keys/hsm-secondary.pub.pem
```

Both hosts must have both key files. The config on each host references
the same two public key files.

### 8.3 Using the CLI enrollment command

Alternatively, use the built-in enrollment command to register a remote
peer:

```sh
# On Host A, enroll Host B as a peer
python3 tools/python/hsm_daemon.py enroll-peer \
  "hsm-secondary" "192.168.1.11:7890" \
  --cert /etc/pico2hsm/certs/host-b.crt \
  --config /etc/pico2hsm/daemon.yaml
```

This adds a peer entry to the config file with the given name, address,
and certificate path. You still need to provide the device public key
file manually (edit the config to add `public_key_file`).

### 8.4 Verify enrollment

```sh
python3 tools/python/hsm_daemon.py status \
  --config /etc/pico2hsm/daemon.yaml
```

Expected output:

```
Enrolled devices: 2
  hsm-primary: gen=5, sync=success, seen=2026-04-08T10:00
  hsm-secondary: gen=5, sync=success, seen=2026-04-08T10:00
```

---

## 9. Verifying Network Sync

### 9.1 Check daemon status

```sh
# On either host
python3 tools/python/hsm_daemon.py status \
  --config /etc/pico2hsm/daemon.yaml
```

Both devices should show the same generation counter and `sync=success`.

### 9.2 Generate a key on Host A, verify it appears on Host B

```sh
# Host A -- generate a test key
pkcs11-tool --login --pin 648219 --keypairgen --key-type EC:prime256v1 \
  --id 03 --label "network-sync-test"
```

Watch Host B's logs for the sync event:

```sh
# On Host B
journalctl -u pico2hsm-daemon -f
```

You should see log lines indicating a manifest diff and key transfer.
Then verify the key appeared on the secondary:

```sh
# On Host B
pkcs11-tool --login --pin 648219 --list-objects
# Should include: label: network-sync-test
```

### 9.3 Compare state hashes directly

Query each device's state hash using the firmware's vendor APDU:

```sh
# On Host A (select SC-HSM applet, then GET_STATE_HASH)
opensc-tool -s "00A404000BE82B0601040181C31F020100" -s "80543A0000"

# On Host B
opensc-tool -s "00A404000BE82B0601040181C31F020100" -s "80543A0000"
```

Each response is 104 bytes:

| Offset | Length | Field |
|--------|--------|-------|
| 0 | 8 bytes | Generation counter (big-endian u64) |
| 8 | 32 bytes | State root (SHA-256 over all key slot hashes) |
| 40 | 64 bytes | Device signature (ECDSA over generation + root) |

Compare the 32 bytes at offset 8-39. If they match, both devices hold
identical key material. The generation counter (bytes 0-7) may differ
slightly -- this is normal and indicates how many state-changing
operations each device has processed.

### 9.4 Run the built-in verify-sync command

```sh
# On either host (requires both devices connected, or one device per host)
python3 tools/python/hsm_daemon.py verify-sync \
  --config /etc/pico2hsm/daemon.yaml
```

Expected output when in sync:

```
  device-0: root=a1b2c3d4e5f6...
  device-1: root=a1b2c3d4e5f6...
All devices in sync
```

Expected output when out of sync:

```
  device-0: root=a1b2c3d4e5f6...
  device-1: root=99887766aabb...
Devices OUT OF SYNC
```

---

## 10. Monitoring

### 10.1 systemd journal

```sh
# Recent logs
journalctl -u pico2hsm-daemon --since "1 hour ago"

# Follow live
journalctl -u pico2hsm-daemon -f

# Errors only
journalctl -u pico2hsm-daemon -p err
```

### 10.2 Key log lines to watch

| Log pattern | Meaning |
|---|---|
| `TCP listener started on 0.0.0.0:7890` | Daemon is accepting TCP connections |
| `TCP connection from ('x.x.x.x', port)` | Remote peer connected |
| `Health check: cluster IN SYNC (xxxxxxxx)` | All local devices share the same state root |
| `Health check: cluster OUT OF SYNC` | Devices have divergent state roots -- action needed |
| `Auto-sync: attempting primary -> secondary` | USB connect triggered automatic sync |
| `Auto-sync complete: Sync successful` | Auto-sync succeeded |
| `TCP sync complete from ... roots_match=True` | TCP sync verified successfully |
| `Quorum not met` | Sync deferred (only relevant with `--quorum` > 1) |
| `Received signal 15 -- shutting down` | Clean daemon shutdown |

### 10.3 Alerting

The daemon logs structured output to the systemd journal. To alert on
sync failures, monitor the journal for the `OUT OF SYNC` pattern:

```sh
# Simple cron-based check (add to crontab)
journalctl -u pico2hsm-daemon --since "5 minutes ago" \
  | grep -q "OUT OF SYNC" && \
  echo "pico2hsm cluster OUT OF SYNC" | mail -s "HSM Alert" admin@example.com
```

For Prometheus-based monitoring, parse the journal output or expose a
health endpoint via a sidecar script that calls `hsm_daemon.py status`
and exports the result as a metric.

---

## 11. Operating over a VPN

For sites connected via WireGuard, OpenVPN, or IPsec:

- Use the VPN interface IP in the `address:` field of the peer config.
  For example, with WireGuard where Host A is `10.8.0.1` and Host B is
  `10.8.0.2`:

  ```yaml
  # Host A config -- peer entry for secondary
  - name: "hsm-secondary"
    address: "10.8.0.2:7890"
  ```

- Restrict the listener to the VPN interface to avoid exposing the port
  on the public interface:

  ```yaml
  listen_address: "10.8.0.1"     # VPN IP only, not 0.0.0.0
  ```

- TLS is still recommended even over a VPN. The VPN protects the
  transport layer, but TLS provides defense in depth: if the VPN is
  compromised, TLS still protects daemon-to-daemon communication.

- Ensure the VPN is established before the daemon starts. In systemd:

  ```ini
  [Unit]
  After=network.target pcscd.service wg-quick@wg0.service
  Requires=pcscd.service
  Wants=wg-quick@wg0.service
  ```

---

## 12. Latency and Reliability Considerations

- **High-latency links.** Sync works over links with hundreds of
  milliseconds of latency. The TCP idle timeout is 30 seconds (set in
  the connection handler via `conn.settimeout(30.0)`).

- **Brief disconnections.** The daemon handles transient network
  failures gracefully. If a TCP connection drops, the remote peer will
  reconnect on its next sync cycle. The health check thread continues
  monitoring local devices independently of the TCP connection state.

- **Reconnection.** The daemon does not maintain persistent outbound
  connections. Sync is triggered by inbound connections (TCP listener)
  and USB connect events. For continuous monitoring, the 60-second
  health check provides a regular heartbeat.

- **Large key sets.** Manifest exchange and key blob transfer are
  sequential. With many keys (50+), the initial sync may take several
  minutes over a slow link. Subsequent syncs only transfer missing keys.

- **Maximum frame size.** Individual TCP messages are capped at 64 KB
  (`MAX_FRAME_SIZE = 65536`). This is enforced on receive to prevent
  memory exhaustion from malformed or malicious frames.

- **Recommended deployment.** Place both hosts on a reliable link --
  data centre interconnect, dedicated VLAN, or site-to-site VPN.
  Residential internet connections introduce unpredictable latency and
  packet loss that may cause spurious sync timeouts.

- **Geographic distribution.** For sites in different regions, use
  split-DNS or static IP addresses to ensure stable peer resolution.
  The daemon resolves hostnames at connection time, not at startup.

---

## 13. Troubleshooting

| Symptom | Likely cause | Diagnostic | Fix |
|---|---|---|---|
| `Connection refused` on port 7890 | Daemon not running on peer, or firewall blocking | `nc -zv host 7890` and `ss -tlnp \| grep 7890` on the peer | Start daemon; open firewall (section 3) |
| `TLS handshake failed` | Certificate fingerprint mismatch or expired cert | Compare fingerprints: `openssl x509 -in daemon.crt -fingerprint -sha256 -noout` on both sides | Re-exchange certificates (section 4.4) |
| `OSError: Address already in use` | Previous daemon instance still running | `ss -tlnp \| grep 7890` to find the PID | `hsm_daemon.py stop` or `kill <pid>` |
| `ConfigError: Peer has no public key` | Missing `public_key_file` or `public_key` in config | Check config YAML syntax | Add the device public key (section 8) |
| `ConfigError: N primary peers; exactly one is required` | Multiple peers marked as primary | Review config on both hosts | Exactly one peer should have `role: primary` |
| `Health check: cluster OUT OF SYNC` | Key added on one device but not yet synced | Wait 60 seconds for the next health check cycle | Usually self-resolves; run `verify-sync` to confirm |
| Peer shows as DISCONNECTED in status | Network partition or daemon down on peer | `ping <peer-ip>`, `traceroute <peer-ip>` | Check network path; restart remote daemon |
| Keys not syncing despite connection | DKEK mismatch (different share on each device) | Compare state hashes (section 9.3); if roots differ even with same keys, DKEK differs | Re-initialize both devices with the same DKEK share ([SETUP_LOCAL_CLUSTER.md](SETUP_LOCAL_CLUSTER.md)) |
| `DKEKError: Unexpected pubkey length` | Device not initialized or wrong applet selected | `opensc-tool --list-readers` to verify device is present | Initialize the device; check USB connection |
| `EnrollmentError: Device not enrolled` | Device identity key not in config | Run enrollment (section 8) | Add device public key to config |
| Sync slow with many keys | Large manifest exchange | Check key count: `pkcs11-tool --login --pin 648219 --list-objects \| grep -c "Private Key"` | Normal for large key sets; initial sync is sequential |
| `pyudev not available; falling back to USB polling` | pyudev not installed | `python -c "import pyudev"` | `pip install pyudev` (optional; polling fallback works) |

---

## 14. Security Hardening Checklist

Before putting the cluster into production, verify each item:

- [ ] TLS enabled (`tls_enabled: true` in config on both hosts)
- [ ] Certificate fingerprints verified out-of-band (section 4.3)
- [ ] Peer TLS certificates exchanged and referenced in config
  (`cert_path` on each peer entry)
- [ ] Daemon running as non-root `pico2hsm` user
  (`sudo useradd -r -s /usr/sbin/nologin pico2hsm`)
- [ ] Port 7890 firewalled to peer IP only (section 3)
- [ ] DKEK share file (`cluster-dkek-share.pbe`) stored offline and
  encrypted -- not on either host's filesystem
- [ ] systemd `ProtectSystem=strict` active in the unit file
- [ ] `ReadWritePaths` restricted to `/var/lib/pico2hsm` and
  `/run/pico2hsm`
- [ ] `NoNewPrivileges=true` in the unit file
- [ ] Private key permissions are `0600`:
  `stat -c %a /var/lib/pico2hsm/daemon.key` should show `600`
- [ ] Audit log enabled and monitored:
  `journalctl -u pico2hsm-daemon`
- [ ] USB device access restricted to the `pico2hsm` user
  (udev rule or `plugdev` group membership)

> **Warning:** The V1 TCP transport uses anonymous TLS by default
> (`CERT_NONE` on both sides). This protects against passive
> eavesdropping but not active man-in-the-middle attacks. For
> production deployments, always configure `cert_path` on peer entries
> to enable mTLS verification. Full mutual authentication with
> HSM-signed attestations is planned for V2
> (see [CLUSTER_PLAN_V2.md](CLUSTER_PLAN_V2.md)).

---

## Quick Reference

```sh
# Start daemon (foreground)
python3 tools/python/hsm_daemon.py start --config /etc/pico2hsm/daemon.yaml

# Start daemon (background with PID file)
python3 tools/python/hsm_daemon.py start \
  --config /etc/pico2hsm/daemon.yaml \
  --pid-file /run/pico2hsm/daemon.pid

# Stop daemon
python3 tools/python/hsm_daemon.py stop --pid-file /run/pico2hsm/daemon.pid

# Check cluster status
python3 tools/python/hsm_daemon.py status --config /etc/pico2hsm/daemon.yaml

# Verify sync
python3 tools/python/hsm_daemon.py verify-sync --config /etc/pico2hsm/daemon.yaml

# Export full state
python3 tools/python/hsm_daemon.py export-state --config /etc/pico2hsm/daemon.yaml

# Enroll a remote peer
python3 tools/python/hsm_daemon.py enroll-peer \
  "peer-name" "192.168.1.11:7890" \
  --cert /path/to/cert.pem \
  --config /etc/pico2hsm/daemon.yaml
```
