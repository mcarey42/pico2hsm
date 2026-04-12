# Local Two-Device Cluster Setup

This guide walks you through setting up two pico2hsm devices as a synchronised pair on a single Linux host. When complete, both devices will hold identical cryptographic keys, the daemon will automatically sync new keys when the second device is connected, and any PKCS#11 application can use either device interchangeably. If one device fails, the other continues operating with the same keys -- no manual recovery is needed unless both fail simultaneously.

---

## Prerequisites checklist

Verify each item before proceeding. Every command below should succeed.

- [ ] **Two pico2hsm devices, both flashed and connected via USB**
  ```sh
  lsusb | grep -i "CCID\|HSM\|SmartCard"
  # Should show two entries
  ```

- [ ] **Linux host (Ubuntu 22.04+ or Debian 12+)**
  ```sh
  cat /etc/os-release | head -2
  ```
  > **Note:** macOS works for the manual steps, but the systemd service integration in Step 6 is Linux-specific. On macOS, use `launchd` or run the daemon in the foreground.

- [ ] **pcscd running**
  ```sh
  sudo systemctl status pcscd
  # Should show "active (running)"
  # If not: sudo systemctl enable --now pcscd
  ```

- [ ] **OpenSC installed**
  ```sh
  opensc-tool --version
  # Should print: OpenSC 0.23.0 or later
  ```

- [ ] **Python 3.10+**
  ```sh
  python3 --version
  # Should print: Python 3.10.x or later
  ```

- [ ] **Both readers visible**
  ```sh
  opensc-tool --list-readers
  # Expected output:
  # Nr.  Card  Features  Name
  # 0    Yes             pico2hsm SC-HSM (0001) 00 00
  # 1    Yes             pico2hsm SC-HSM (0001) 01 00
  ```

- [ ] **pico2hsm Python package installed**
  ```sh
  pip show pico2hsm 2>/dev/null || echo "Not installed"
  # If not installed:
  pip install -e tools/python/
  ```

---

## Concept: what DKEK synchronisation means

The DKEK (Device Key Encryption Key) is the master key that encrypts all private keys stored on a pico2hsm device. Each device derives its DKEK from one or more "shares" that you import during initialisation. When two devices are initialised with the same DKEK share, they derive the same DKEK. This means a key wrapped (exported) from one device can be unwrapped (imported) on the other -- the encrypted blob is portable between any devices that share the same DKEK.

The sync daemon automates this wrap/unwrap process. It watches for USB device connect events, compares the key manifests on both devices, and transfers any keys that exist on the primary but not the secondary. After initial setup, generating a new key on the primary and plugging in the secondary is enough -- the daemon detects the new key and copies it over automatically. The DKEK exchange itself uses a P-256 ECDH relay protocol where plaintext key material never passes through the host.

---

## Step 1: Initialize both devices

Both devices must be initialised with `--dkek-shares 1` so they can accept a shared DKEK. The SO-PIN (Security Officer PIN) is a 16-character hex string used for administrative operations. The user PIN is what you type daily for signing and decryption.

```sh
# Verify both readers are present
opensc-tool --list-readers
# Expected:
# Nr.  Card  Features  Name
# 0    Yes             pico2hsm SC-HSM (0001) 00 00
# 1    Yes             pico2hsm SC-HSM (0001) 01 00
```

```sh
# Initialize reader 0 (primary)
sc-hsm-tool -r 0 --initialize \
  --label "HSM-Primary" \
  --so-pin 3537363231383830 \
  --pin 648219 \
  --dkek-shares 1

# Expected output:
# Using reader with a]card: pico2hsm SC-HSM (0001) 00 00
# Initialized token with label 'HSM-Primary'
```

```sh
# Initialize reader 1 (secondary)
sc-hsm-tool -r 1 --initialize \
  --label "HSM-Secondary" \
  --so-pin 3537363231383830 \
  --pin 648219 \
  --dkek-shares 1

# Expected output:
# Using reader with a card: pico2hsm SC-HSM (0001) 01 00
# Initialized token with label 'HSM-Secondary'
```

> **Warning:** Both devices **must** use `--dkek-shares 1`. If one device is initialised with a different share count, the DKEK derivation will differ and key transfer between the devices will fail. Initialisation erases all keys on the device.

> **Note:** Using different user PINs on each device is perfectly fine. The DKEK and all keys are independent of the PIN value. The SO-PIN should match if you want consistent administrative access.

---

## Step 2: Create and import the DKEK share

One DKEK share file must be imported into both devices. This is the single most important file in your cluster -- it is the recovery key for all keys on both devices.

```sh
# Create the directory
sudo mkdir -p /etc/pico2hsm
sudo chown $USER:$USER /etc/pico2hsm

# Create the share (PBE-encrypted file)
sc-hsm-tool --create-dkek-share /etc/pico2hsm/dkek-share-1.pbe \
  --password "USE-A-STRONG-PASSPHRASE-HERE"

# Expected output:
# DKEK share created and saved to /etc/pico2hsm/dkek-share-1.pbe
```

```sh
# Import into primary
sc-hsm-tool -r 0 --import-dkek-share /etc/pico2hsm/dkek-share-1.pbe \
  --password "USE-A-STRONG-PASSPHRASE-HERE"

# Expected output:
# Using reader with a card: pico2hsm SC-HSM (0001) 00 00
# DKEK share imported
# DKEK shares outstanding: 0
# DKEK key check value: A1B2C3D4E5F6A1B2
```

```sh
# Import into secondary
sc-hsm-tool -r 1 --import-dkek-share /etc/pico2hsm/dkek-share-1.pbe \
  --password "USE-A-STRONG-PASSPHRASE-HERE"

# Expected output:
# Using reader with a card: pico2hsm SC-HSM (0001) 01 00
# DKEK share imported
# DKEK shares outstanding: 0
# DKEK key check value: A1B2C3D4E5F6A1B2
```

The DKEK key check value (KCV) must be identical on both devices. If it differs, one of the imports used a different share file or passphrase -- go back to the beginning of this step.

> **Warning:** Back up the DKEK share file **now**, before proceeding. If both devices fail and you do not have this file, all keys are permanently lost.

```sh
cp /etc/pico2hsm/dkek-share-1.pbe ~/dkek-share-1.pbe.backup
# Move this backup to offline storage (USB drive, safe, etc.)
```

---

## Step 3: Generate your first key

Generate a P-256 signing key on the primary device. This key will be synced to the secondary in the next step.

```sh
pkcs11-tool --login --pin 648219 \
  --keypairgen --key-type EC:prime256v1 \
  --id 01 --label "signing-key-1"

# Expected output:
# Using slot 0 with a present token (0x0)
# Key pair generated:
# Private Key Object; EC
#   label:      signing-key-1
#   ID:         01
#   Usage:      sign
#   Access:     sensitive, always sensitive, never extractable
# Public Key Object; EC  EC_POINT 256 bits
#   label:      signing-key-1
#   ID:         01
#   Usage:      verify
```

---

## Step 4: Manually sync to secondary (first time)

The first sync is done manually using sc-hsm-tool's wrap/unwrap commands. The wrapped blob is encrypted under the DKEK -- the raw private key never appears on the host.

```sh
# Wrap (export) the key from primary
sc-hsm-tool -r 0 --wrap-key /tmp/key-01.bin \
  --key-reference 1 --pin 648219

# Expected output:
# Key 1 wrapped to /tmp/key-01.bin
```

```sh
# Unwrap (import) to secondary
sc-hsm-tool -r 1 --unwrap-key /tmp/key-01.bin \
  --key-reference 1 --pin 648219

# Expected output:
# Key 1 unwrapped
```

```sh
# Clean up the wrapped key file (it is no longer needed on disk)
rm /tmp/key-01.bin
```

Repeat the wrap/unwrap for each key reference if you generated multiple keys. You can list all keys on the primary to see what needs syncing:

```sh
pkcs11-tool --login --pin 648219 --list-objects --type privkey
```

---

## Step 5: Install and configure the daemon

The daemon monitors USB device connections and automatically syncs new keys from the primary to the secondary.

### Install Python dependencies

```sh
pip install -e tools/python/
```

This installs the `pico2hsm` package and all required dependencies (`pyscard`, `cryptography`, `pyyaml`, `pyudev`, etc.).

### Extract device identity keys

Each device has a P-256 static identity key. The daemon uses these to verify it is talking to enrolled devices during the DKEK exchange.

```python
# Run this in a Python shell or save as a script:
from pico2hsm.device import Pico2HSM
from pico2hsm.enrollment import DeviceEnrollment

# Extract primary's public key
primary = Pico2HSM()
primary.connect(reader_index=0)
primary.select_applet()
info = DeviceEnrollment.get_device_info(primary)
DeviceEnrollment.save_pubkey_pem(info.pubkey, "/etc/pico2hsm/keys/primary.pub.pem")
print(f"Primary fingerprint: {info.fingerprint}")

# Extract secondary's public key
secondary = Pico2HSM()
secondary.connect(reader_index=1)
secondary.select_applet()
info = DeviceEnrollment.get_device_info(secondary)
DeviceEnrollment.save_pubkey_pem(info.pubkey, "/etc/pico2hsm/keys/secondary.pub.pem")
print(f"Secondary fingerprint: {info.fingerprint}")
```

```sh
# Create the keys directory
sudo mkdir -p /etc/pico2hsm/keys
```

### Create the configuration file

```sh
sudo mkdir -p /etc/pico2hsm
```

Create `/etc/pico2hsm/daemon.yaml` with the following content:

```yaml
# /etc/pico2hsm/daemon.yaml -- Local two-device cluster
#
# listen_address: Bind address for the TCP listener. Use 127.0.0.1 for
#   local-only operation (no remote peers).
listen_address: "127.0.0.1"

# listen_port: TCP port for peer daemon connections. Set to 0 to disable
#   the TCP listener entirely (USB-only sync).
listen_port: 7890

# state_dir: Where the daemon stores state.json (sync history, device
#   records). Must be writable by the daemon user.
state_dir: "/var/lib/pico2hsm"

# sync_on_connect: When true, the daemon automatically syncs the primary
#   to each secondary whenever a USB device connect event is detected.
sync_on_connect: true

# tls_enabled: Use TLS for TCP transport. For local-only operation this
#   can be false. Enable for any network-facing deployment.
tls_enabled: false

# log_level: Python logging level. Use DEBUG for initial setup, INFO for
#   normal operation.
log_level: "INFO"

# peers: Each entry identifies a device in the cluster.
#   - name: Human-readable label (must be unique).
#   - role: "primary" (source of truth) or "secondary" (receives sync).
#   - public_key_file: Path to the device's P-256 identity key (PEM).
#     Extracted in the step above.
peers:
  - name: "primary"
    role: "primary"
    public_key_file: "/etc/pico2hsm/keys/primary.pub.pem"

  - name: "secondary"
    role: "secondary"
    public_key_file: "/etc/pico2hsm/keys/secondary.pub.pem"
```

---

## Step 6: Start the daemon as a systemd service

### Create a service user

```sh
sudo useradd -r -s /usr/sbin/nologin -d /var/lib/pico2hsm pico2hsm
sudo mkdir -p /var/lib/pico2hsm /run/pico2hsm
sudo chown -R pico2hsm:pico2hsm /var/lib/pico2hsm
# Grant smartcard reader access
sudo usermod -aG plugdev pico2hsm
```

### Install the systemd unit

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
    --config /etc/pico2hsm/daemon.yaml \
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

> **Note:** Adjust the `ExecStart` path if you installed pico2hsm somewhere other than `/opt/pico2hsm`. If you cloned the repo to `~/pico2hsm`, use the full path to `hsm_daemon.py` there.

### Enable and start

```sh
sudo systemctl daemon-reload
sudo systemctl enable pico2hsm-daemon.service
sudo systemctl start pico2hsm-daemon.service
```

### Verify the daemon is running

```sh
sudo systemctl status pico2hsm-daemon.service
# Expected:
#   Active: active (running)
#   Main PID: 12345

sudo journalctl -u pico2hsm-daemon -n 20 --no-pager
# Expected healthy log output:
# 2026-04-08 10:00:01,234 INFO pico2hsm.daemon: TCP listener started on 127.0.0.1:7890
# 2026-04-08 10:00:01,235 INFO pico2hsm.daemon: USB monitor started
# 2026-04-08 10:00:01,235 INFO pico2hsm.daemon: Health check started
# 2026-04-08 10:00:01,236 INFO pico2hsm.daemon: pico2hsm DKEK daemon running (quorum=1)
# 2026-04-08 10:01:01,500 INFO pico2hsm.daemon: Health check: cluster IN SYNC (a1b2c3d4)
```

To follow logs in real time:

```sh
sudo journalctl -u pico2hsm-daemon -f
```

---

## Step 7: Verify the setup is working

Run through each of these checks to confirm both devices are synchronised and operational.

### a) Both devices report the same state root

The state root is a SHA-256 hash computed over all 254 key slot hashes. Identical state roots mean identical key material.

```sh
# Select the SC-HSM applet and query state hash on each device
opensc-tool -r 0 -s "00A404000BE82B0601040181C31F020100" -s "80543A0000"
opensc-tool -r 1 -s "00A404000BE82B0601040181C31F020100" -s "80543A0000"
# Compare the 32 bytes at offset 8 in each response (bytes 8-39).
# They should be identical.
```

Or use the daemon CLI:

```sh
python3 tools/python/hsm_daemon.py verify-sync \
  --config /etc/pico2hsm/daemon.yaml

# Expected output:
#   device-0: root=a1b2c3d4...
#   device-1: root=a1b2c3d4...
# All devices in sync
```

### b) Both devices list the same keys

```sh
pkcs11-tool --list-objects --type privkey
# Should show signing-key-1 (ID 01) on whichever reader pkcs11-tool picks.

# Explicitly check each reader:
pkcs11-tool --list-objects --type privkey --slot-index 0
pkcs11-tool --list-objects --type privkey --slot-index 1
# Both should list the same key(s).
```

### c) Sign on primary, verify on secondary

This proves both devices hold the same private key and can interoperate.

```sh
# Create a test message
echo "test message" > /tmp/msg.txt

# Sign on primary (reader 0)
pkcs11-tool --login --pin 648219 \
  --sign --mechanism ECDSA-SHA256 --id 01 \
  --input-file /tmp/msg.txt --output-file /tmp/sig.bin \
  --slot-index 0

# Export the public key from secondary (reader 1)
pkcs11-tool --login --pin 648219 \
  --read-object --type pubkey --id 01 --output-file /tmp/pubkey.der \
  --slot-index 1

# Verify the signature using the secondary's public key
openssl dgst -sha256 -verify /tmp/pubkey.der -signature /tmp/sig.bin /tmp/msg.txt
# Should print: Verified OK
```

### d) Auto-sync test

Confirm the daemon automatically syncs new keys.

```sh
# Generate a second key on primary
pkcs11-tool --login --pin 648219 \
  --keypairgen --key-type EC:prime256v1 \
  --id 02 --label "signing-key-2" \
  --slot-index 0
```

Watch the daemon logs in another terminal:

```sh
sudo journalctl -u pico2hsm-daemon -f
# You should see:
# Auto-sync: attempting primary -> secondary
# Auto-sync complete: Sync successful
```

Then verify the new key appears on the secondary:

```sh
pkcs11-tool --list-objects --type privkey --slot-index 1
# Should now list both signing-key-1 and signing-key-2
```

---

## Operating the cluster

### Adding a new key

Generate on the primary. If the daemon is running and both devices are connected, the key is automatically synced to the secondary.

```sh
pkcs11-tool --login --pin 648219 \
  --keypairgen --key-type EC:secp384r1 \
  --id 03 --label "p384-key" \
  --slot-index 0
# Daemon auto-syncs to secondary within seconds
```

### Manual sync

If the daemon is not running, or you prefer to sync manually:

```sh
python3 tools/python/hsm_daemon.py sync secondary \
  --config /etc/pico2hsm/daemon.yaml
```

### Check sync status

```sh
python3 tools/python/hsm_daemon.py verify-sync \
  --config /etc/pico2hsm/daemon.yaml
```

### View cluster health

```sh
python3 tools/python/hsm_daemon.py status \
  --config /etc/pico2hsm/daemon.yaml

# Expected output:
# Enrolled devices: 2
#   primary: gen=3, sync=success, seen=2026-04-08T10:15:00
#   secondary: gen=3, sync=success, seen=2026-04-08T10:15:02
```

### Export full state (for debugging)

```sh
python3 tools/python/hsm_daemon.py export-state \
  --config /etc/pico2hsm/daemon.yaml
```

### Replace a failed device

If one device fails, the surviving device continues to operate independently. To restore redundancy with a replacement device:

1. Flash firmware onto the replacement device (see [QUICKSTART.md](../QUICKSTART.md)).

2. Initialise it with the same DKEK share configuration:
   ```sh
   sc-hsm-tool -r 1 --initialize \
     --label "HSM-Secondary-v2" \
     --so-pin 3537363231383830 \
     --pin 648219 \
     --dkek-shares 1
   ```

3. Import the DKEK share from your backup:
   ```sh
   sc-hsm-tool -r 1 --import-dkek-share /etc/pico2hsm/dkek-share-1.pbe \
     --password "USE-A-STRONG-PASSPHRASE-HERE"
   ```

4. Sync all keys from the surviving primary:
   ```sh
   # For each key on the primary (list them first):
   pkcs11-tool --login --pin 648219 --list-objects --type privkey --slot-index 0

   # Wrap and unwrap each key:
   sc-hsm-tool -r 0 --wrap-key /tmp/key-01.bin --key-reference 1 --pin 648219
   sc-hsm-tool -r 1 --unwrap-key /tmp/key-01.bin --key-reference 1 --pin 648219
   # Repeat for each key reference
   ```

5. Verify state roots match:
   ```sh
   python3 tools/python/hsm_daemon.py verify-sync \
     --config /etc/pico2hsm/daemon.yaml
   ```

6. Update the daemon config if the replacement device has a different identity key, then restart the daemon:
   ```sh
   sudo systemctl restart pico2hsm-daemon.service
   ```

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Daemon does not start | pcscd not running | `sudo systemctl start pcscd` |
| "No devices found" | USB not enumerated | Check `lsusb \| grep -i pico` and try a different USB port |
| "ConfigError: Failed to read config" | Invalid YAML or missing public key file | Verify config syntax and that all `public_key_file` paths exist |
| Sync fails with "state mismatch" | DKEK mismatch between devices | Re-initialise both devices and import the same DKEK share |
| Auto-sync not triggering | pyudev not installed | `pip install pyudev` (without it, polling runs every 5 seconds) |
| State roots differ after sync | Key generation in flight during sync | Wait 5 seconds and run `verify-sync` again |
| "Address already in use" on port 7890 | Previous daemon instance still running | `python3 tools/python/hsm_daemon.py stop --pid-file /run/pico2hsm/daemon.pid` |
| "EnrollmentError: Device not enrolled" | Device identity key not in config | Re-extract the device public key and update config |
| DKEK KCV differs between devices | Wrong share file or passphrase used | Re-initialise the mismatched device and re-import the correct share |
| `pkcs11-tool` shows no slots | pcscd not running or device not plugged in | `sudo systemctl restart pcscd && opensc-tool --list-readers` |
