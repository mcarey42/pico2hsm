# pico2hsm Cluster Verification Guide

This guide provides step-by-step procedures for verifying that a pico2hsm
two-device cluster is correctly configured and operational. Each check shows
the exact command to run and what to expect in both passing and failing cases.

All commands assume a Linux host (Ubuntu 22.04+) with two pico2hsm devices
connected via USB. Reader indices default to 0 and 1; adjust if your setup
differs (run `opensc-tool --list-readers` to confirm).

For automated verification, use `verify.sh` in the repository root.

---

## 1. Pre-flight checks

Run these before starting the daemon or performing any cluster operations.

### 1.1 USB devices present

```sh
lsusb | grep -i "1209:27c0\|pico"
```

**PASS** -- two entries appear:

```
Bus 001 Device 012: ID 1209:27c0 Generic pico2hsm SC-HSM
Bus 001 Device 013: ID 1209:27c0 Generic pico2hsm SC-HSM
```

**FAIL** -- fewer than two entries. Check USB cables, try different ports, or
run `dmesg | tail -20` to see if the kernel detected the devices.

### 1.2 pcscd running

```sh
systemctl is-active pcscd
```

**PASS:**

```
active
```

**FAIL:**

```
inactive
```

Fix: `sudo systemctl start pcscd && sudo systemctl enable pcscd`

### 1.3 Readers enumerated

```sh
opensc-tool --list-readers
```

**PASS** -- two readers with "Yes" in the Card column:

```
Nr.  Card  Features  Name
0    Yes             pico2hsm SC-HSM (0001) 00 00
1    Yes             pico2hsm SC-HSM (0001) 01 00
```

**FAIL** -- fewer than two rows, or "No" in the Card column. This means pcscd
sees the reader but no card is present. Re-seat the USB cable or restart pcscd.

### 1.4 Firmware responds (SELECT AID)

Send a SELECT command to the SC-HSM applet on each reader:

```sh
# Reader 0
opensc-tool -r 0 -s "00A404000BE82B0601040181C31F020100"

# Reader 1
opensc-tool -r 1 -s "00A404000BE82B0601040181C31F020100"
```

**PASS** -- the response includes `SW1=0x90, SW2=0x00` and an FCI template
containing the AID (`E8 2B 06 01 04 01 81 C3 1F 02 01`) and a version tag
(`9F6E`):

```
Received (SW1=0x90, SW2=0x00):
6F 19 84 0B E8 2B 06 01 04 01 81 C3 1F 02 01 A5 ...
```

**FAIL** -- `SW1=0x6A, SW2=0x82` (file not found) means the firmware does not
have the SC-HSM applet. Reflash the device with the correct firmware build.

### 1.5 Both devices initialized

```sh
pkcs11-tool --list-slots
```

**PASS** -- each slot shows a token label and "token initialized":

```
Slot 0 (0x0): pico2hsm SC-HSM (0001) 00 00
  token label        : pico2hsm
  token flags:       ... token initialized ...
Slot 1 (0x1): pico2hsm SC-HSM (0001) 01 00
  token label        : pico2hsm
  token flags:       ... token initialized ...
```

**FAIL (uninitialized)** -- the token flags show "uninitialized" or the slot
is listed as empty. Initialize the device with:

```sh
sc-hsm-tool -r 0 --initialize --label pico2hsm \
  --so-pin 3537363231383830 --pin 648219 --dkek-shares 1
```

---

## 2. DKEK verification

Both devices must share the same DKEK (Device Key Encryption Key) for key
synchronization to work. The DKEK is loaded by importing DKEK shares.

### 2.1 Check DKEK share status

```sh
sc-hsm-tool -r 0 --info
sc-hsm-tool -r 1 --info
```

**PASS** -- "DKEK shares" line shows 0 outstanding shares:

```
SmartCard-HSM has key management enabled with 1 DKEK share(s)
DKEK share 1 : imported
```

**FAIL** -- outstanding shares remain:

```
DKEK shares outstanding: 1
```

This means the DKEK share has not been imported yet. Import the share:

```sh
sc-hsm-tool -r 0 --import-dkek-share /path/to/share.pbe --password YOUR_PASSPHRASE
```

### 2.2 Verify DKEK KCV (Key Check Value)

When you import a DKEK share, `sc-hsm-tool` prints the KCV. If both devices
were initialized with the same share file (or received DKEK via the cluster
exchange protocol), their KCVs must match.

If you did not capture the KCV at import time, you can verify indirectly by
checking that both devices produce the same state hash after having the same
keys (see section 3).

---

## 3. State hash verification

The state hash is a SHA-256 digest over all key slots on a device. Two devices
with the same keys produce the same state root. The firmware command
`GET_STATE_HASH` (EXTRAS P1=0x3A) returns 104 bytes:

| Offset | Length | Field |
|--------|--------|-------|
| 0 | 8 | Generation counter (big-endian u64) |
| 8 | 32 | State root (SHA-256) |
| 40 | 64 | ECDSA-P256 signature over SHA-256(generation \|\| state_root) |

### 3.1 Extract and compare state roots

```sh
# Get state hash from device 0
ROOT0=$(opensc-tool -r 0 \
  -s "00A404000BE82B0601040181C31F020100" \
  -s "80543A0000" 2>/dev/null \
  | tail -20 \
  | grep -oE '[0-9A-Fa-f]{2}( [0-9A-Fa-f]{2}){15}' \
  | tr -d ' \n')
# Extract bytes 8-39 (state root = chars 16-79 in hex string)
ROOT0=${ROOT0:16:64}
echo "Root0: $ROOT0"

# Same for device 1
ROOT1=$(opensc-tool -r 1 \
  -s "00A404000BE82B0601040181C31F020100" \
  -s "80543A0000" 2>/dev/null \
  | tail -20 \
  | grep -oE '[0-9A-Fa-f]{2}( [0-9A-Fa-f]{2}){15}' \
  | tr -d ' \n')
ROOT1=${ROOT1:16:64}
echo "Root1: $ROOT1"

if [ -n "$ROOT0" ] && [ "$ROOT0" = "$ROOT1" ]; then
  echo "PASS: Devices are IN SYNC"
else
  echo "FAIL: Devices are OUT OF SYNC"
fi
```

**PASS:**

```
Root0: a1b2c3d4e5f6...  (64 hex chars)
Root1: a1b2c3d4e5f6...  (identical)
PASS: Devices are IN SYNC
```

**FAIL:**

```
Root0: a1b2c3d4e5f6...
Root1: 9f8e7d6c5b4a...  (different)
FAIL: Devices are OUT OF SYNC
```

If the roots differ, the devices hold different key sets. Trigger a sync via
the daemon or re-initialize and re-exchange the DKEK.

### 3.2 Using the Python daemon CLI

If the Python daemon tooling is installed:

```sh
python3 tools/python/hsm_daemon.py verify-sync
```

**PASS:**

```
  device-0: root=a1b2c3d4e5f6...
  device-1: root=a1b2c3d4e5f6...
All devices in sync
```

**FAIL:**

```
  device-0: root=a1b2c3d4e5f6...
  device-1: root=9f8e7d6c5b4a...
Devices OUT OF SYNC
```

---

## 4. Key operation verification

This section confirms that keys are usable across both devices. It requires
both devices to be initialized, have the same DKEK, and have at least one
shared key.

### 4.1 Sign on device 0, verify with public key from device 1

This proves both devices hold the same private key for a given slot (here,
slot 01). Adjust the slot ID and reader names as needed.

```sh
# Step 1: Export public key from device 1
pkcs11-tool --login --pin 648219 \
  --read-object --type pubkey --id 01 \
  --output-file /tmp/pubkey-from-secondary.der
openssl ec -inform DER -pubin \
  -in /tmp/pubkey-from-secondary.der \
  -out /tmp/pubkey.pem

# Step 2: Sign a message with device 0
echo "pico2hsm verification test $(date)" > /tmp/verify-msg.txt
OPENSC_DEFAULT_READER=0 pkcs11-tool --login --pin 648219 \
  --sign --mechanism ECDSA-SHA256 --id 01 \
  --input-file /tmp/verify-msg.txt \
  --output-file /tmp/sig.raw

# Step 3: Convert raw ECDSA signature (r||s) to DER format
python3 -c "
import sys
raw = open('/tmp/sig.raw','rb').read()
r = int.from_bytes(raw[:len(raw)//2], 'big')
s = int.from_bytes(raw[len(raw)//2:], 'big')
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
open('/tmp/sig.der','wb').write(encode_dss_signature(r, s))
"

# Step 4: Verify with secondary's public key
openssl dgst -sha256 -verify /tmp/pubkey.pem \
  -signature /tmp/sig.der /tmp/verify-msg.txt
```

**PASS:**

```
Verified OK
```

**FAIL:**

```
Verification Failure
```

If verification fails, the devices do not hold the same private key for that
slot. Check that DKEK exchange completed successfully and that key sync has
run.

---

## 5. Daemon health verification

These checks apply when the pico2hsm daemon is running as a systemd service.

### 5.1 Daemon is running

```sh
systemctl is-active pico2hsm-daemon
```

**PASS:** `active`
**FAIL:** `inactive` or `failed`

If failed, check the journal: `journalctl -u pico2hsm-daemon --since "10 min ago"`

### 5.2 No errors in the last hour

```sh
journalctl -u pico2hsm-daemon --since "1 hour ago" --no-pager | grep -c ERROR
```

**PASS:** `0`
**FAIL:** Any non-zero count. Inspect the errors:

```sh
journalctl -u pico2hsm-daemon --since "1 hour ago" --no-pager | grep ERROR
```

### 5.3 Last sync time

```sh
journalctl -u pico2hsm-daemon --no-pager | grep -i "sync complete\|sync successful\|IN SYNC" | tail -1
```

**PASS** -- a recent timestamp appears. Example:

```
Apr 08 14:22:01 host pico2hsm[1234]: Health check: cluster IN SYNC (a1b2c3d4)
```

**FAIL** -- no output, or the timestamp is stale. The daemon may not be
running, or no sync has been attempted.

### 5.4 Cluster sync via daemon CLI

```sh
python3 tools/python/hsm_daemon.py verify-sync --config /etc/pico2hsm/daemon.yaml
```

See section 3.2 for expected output.

---

## 6. Auto-sync verification

This procedure confirms that the daemon automatically syncs a new key from the
primary to the secondary.

### 6.1 Generate a test key on the primary

```sh
OPENSC_DEFAULT_READER=0 pkcs11-tool --login --pin 648219 \
  --keypairgen --key-type EC:prime256v1 \
  --id FF --label "verify-autosync-test"
```

Expected output:

```
Key pair generated:
Private Key Object; EC
  label:      verify-autosync-test
  ID:         ff
...
```

### 6.2 Watch daemon logs for sync event

```sh
timeout 60 journalctl -u pico2hsm-daemon -f | grep -m1 "sync"
```

Expected -- within 60 seconds, a line like:

```
Apr 08 14:23:05 host pico2hsm[1234]: Auto-sync complete: Sync successful
```

If nothing appears within 60 seconds, check that `sync_on_connect: true` is
set in the config file and that the daemon is running.

### 6.3 Confirm key appears on secondary

```sh
OPENSC_DEFAULT_READER=1 pkcs11-tool --login --pin 648219 \
  --list-objects | grep "verify-autosync-test"
```

**PASS:**

```
Private Key Object; EC
  label:      verify-autosync-test
  ID:         ff
```

**FAIL** -- no output. The key was not synced to the secondary.

### 6.4 Clean up test key

```sh
OPENSC_DEFAULT_READER=0 pkcs11-tool --login --pin 648219 \
  --delete-object --type privkey --id FF
OPENSC_DEFAULT_READER=1 pkcs11-tool --login --pin 648219 \
  --delete-object --type privkey --id FF
```

---

## 7. Quick reference: automated verification

The `verify.sh` script in the repository root runs all pre-flight, DKEK,
state hash, and key list checks automatically:

```sh
# Basic verification (no daemon checks)
./verify.sh --skip-daemon

# Full verification including daemon health
./verify.sh

# Custom reader indices and PIN
./verify.sh --reader0 0 --reader1 1 --pin 648219

# Full mode including sign/verify test
./verify.sh --full --skip-daemon
```

Exit code 0 means all checks passed. Exit code 1 means one or more checks
failed. The script prints a colored summary at the end.
