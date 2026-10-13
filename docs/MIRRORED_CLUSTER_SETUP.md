# Mirrored Cluster Setup (Two Devices)

> **Superseded by [CLUSTER_PLAN_V3.md](CLUSTER_PLAN_V3.md).** This guide
> describes the 1.x two-device "mirrored pair".
> "Mirrored" here means two devices that hold the same keys. It has nothing
> to do with mirrored (RAID) flash, which pico2hsm does not use.
> Domains, enrollment against any member, and multi-way sync replace
> this model. The production daemon will be `pico2hsm-syncd`, in the
> companion pico2hsm-tool repository; the Python daemon is kept only as a
> reference and test harness. Daemon and peer-enrollment steps below may not
> match current firmware. Keys from 1.x do not carry over to 2.0.
>
> The manual steps (DKEK share, `sc-hsm-tool --wrap-key` / `--unwrap-key`)
> use standard SmartCard-HSM formats and still work.

A complete guide for running two pico2hsm devices as an active-active
mirrored pair. Both devices hold identical keys and can serve any
cryptographic operation independently.

For single-device setup, see
[SINGLE_DEVICE_SETUP.md](SINGLE_DEVICE_SETUP.md).
For building and flashing firmware, see [QUICKSTART.md](../QUICKSTART.md).

---

## What this gives you

- **Redundancy**: If one device fails, the other has identical keys and
  continues operating without interruption.
- **Load sharing**: Clients can use either device for signing or decryption.
- **Zero-downtime backup**: Keys are always live on both devices. No offline
  backup ceremony is needed (though offline backups are still recommended).

---

## Hardware needed

- 2 pico2hsm devices, both flashed with the same firmware version
- Both devices connected to the same host via USB (or one per host with
  network connectivity for the sync daemon)

---

## Step 1 -- Identify your devices

Plug in both devices and list the available readers:

```sh
opensc-tool --list-readers
```

You should see two readers. Note their indices (0 and 1). The `-r` flag
in the commands below selects which reader to target.

```
# Readers known about:
Nr.  Card  Features  Name
0    Yes             pico2hsm (0)
1    Yes             pico2hsm (1)
```

---

## Step 2 -- Initialize BOTH devices with the same DKEK configuration

Both devices must be initialized with `--dkek-shares 1` so they can accept
the same DKEK share. The SO-PIN should match across devices. User PINs can
differ.

```sh
# Device 0
sc-hsm-tool -r 0 --initialize \
  --label "HSM-Primary" \
  --so-pin 3537363231383830 \
  --pin 648219 \
  --dkek-shares 1

# Device 1
sc-hsm-tool -r 1 --initialize \
  --label "HSM-Secondary" \
  --so-pin 3537363231383830 \
  --pin 648219 \
  --dkek-shares 1
```

**Critical:** Both devices must use `--dkek-shares 1`. If one device is
initialized with a different share count, the DKEK derivation will differ
and key transfer between the devices will fail silently (the unwrap
operation will return an error).

---

## Step 3 -- Create ONE DKEK share and import it into BOTH devices

The DKEK is derived from the share(s) imported into the device. For both
devices to derive the same DKEK, they must receive the same share.

```sh
# Create the shared DKEK share (do this once)
sc-hsm-tool --create-dkek-share cluster-dkek-share.pbe \
  --password "cluster-passphrase"

# Import into device 0
sc-hsm-tool -r 0 --import-dkek-share cluster-dkek-share.pbe \
  --password "cluster-passphrase"

# Import into device 1
sc-hsm-tool -r 1 --import-dkek-share cluster-dkek-share.pbe \
  --password "cluster-passphrase"
```

After this step, both devices have the same DKEK in volatile RAM. Keys
wrapped (exported) from one device can be unwrapped (imported) on the other.

Store `cluster-dkek-share.pbe` securely offline. If both devices fail
simultaneously, this file is required to restore keys to replacement
hardware.

---

## Step 4 -- Generate keys on the primary

Generate keys on device 0 (the primary). These will be synced to device 1
in the next step.

```sh
pkcs11-tool --login --pin 648219 -r 0 \
  --keypairgen --key-type EC:prime256v1 \
  --id 01 --label "shared-signing-key"
```

Generate as many keys as needed. All will be synced to the secondary.

---

## Step 5 -- Sync keys to the secondary

For each key on the primary, export it as a DKEK-wrapped blob and import
it into the secondary. The wrapped blob is encrypted -- the raw private key
never appears on the host.

```sh
# Export key 1 from device 0
sc-hsm-tool -r 0 --wrap-key wrapped-key-01.bin \
  --key-reference 1 --pin 648219

# Import key 1 into device 1
sc-hsm-tool -r 1 --unwrap-key wrapped-key-01.bin \
  --key-reference 1 --pin 648219
```

Repeat for each key reference. You can list all keys on the primary to see
what needs syncing:

```sh
pkcs11-tool --login --pin 648219 -r 0 --list-objects --type privkey
```

---

## Step 6 -- Verify both devices are in sync

Both devices implement a `GET_STATE_HASH` vendor APDU that returns a
generation counter and a SHA-256 state root computed over all 254 key slots.
If both devices hold identical keys, their state roots will match.

```sh
# State hash from device 0
opensc-tool -r 0 -s "80543A00"

# State hash from device 1
opensc-tool -r 1 -s "80543A00"
```

Each response contains:

| Offset | Length | Field |
|---|---|---|
| 0 | 8 bytes | Generation counter (big-endian u64) |
| 8 | 32 bytes | State root (SHA-256 over all key slot hashes) |
| 40 | 64 bytes | Device signature (RFC 6979 ECDSA over generation and root) |

Compare the 32 bytes at offset 8-39 in each response. If they match, the
devices hold identical key material.

You can also use the Python daemon CLI:

```sh
python3 tools/python/hsm_daemon.py verify-sync
```

This fetches the state hash from all connected devices and reports whether
they are in sync.

---

## Ongoing sync -- adding new keys

Whenever you generate or import a new key on one device, sync it to the
other using the same wrap/unwrap procedure:

```sh
# Generate on primary
pkcs11-tool --login --pin 648219 -r 0 \
  --keypairgen --key-type EC:secp384r1 \
  --id 02 --label "new-key"

# Sync to secondary
sc-hsm-tool -r 0 --wrap-key wrapped-key-02.bin \
  --key-reference 2 --pin 648219
sc-hsm-tool -r 1 --unwrap-key wrapped-key-02.bin \
  --key-reference 2 --pin 648219
```

Always verify sync after adding keys:

```sh
opensc-tool -r 0 -s "80543A00"
opensc-tool -r 1 -s "80543A00"
```

---

## Automated sync with the Python daemon

The Python daemon automates key synchronization between devices. It monitors
USB device connections and triggers sync when a secondary device appears.

### Configuration

Create `~/.pico2hsm/daemon.yaml`:

```yaml
listen_port: 7890
sync_on_connect: true
state_dir: "~/.pico2hsm"
log_level: INFO

peers:
  - name: primary
    role: primary
    public_key_file: "~/.pico2hsm/primary.pub"
    address: "localhost:7890"

  - name: secondary
    role: secondary
    public_key_file: "~/.pico2hsm/secondary.pub"
    address: "localhost:7891"
```

The `public_key_file` for each peer is the device's static public key
(P-256 uncompressed point, PEM-encoded). Extract it from a connected
device using the daemon's enrollment command.

### Starting the daemon

```sh
python3 tools/python/hsm_daemon.py start \
  --config ~/.pico2hsm/daemon.yaml
```

The daemon:
- Detects when a pico2hsm device connects via USB
- Compares its state root against the primary
- If divergent, triggers a full key sync (manifest diff, wrap/unwrap)
- Logs all sync operations to stderr

### Checking cluster status

```sh
python3 tools/python/hsm_daemon.py status \
  --config ~/.pico2hsm/daemon.yaml
```

### Stopping the daemon

```sh
python3 tools/python/hsm_daemon.py stop
```

---

## Failure and recovery scenarios

### One device fails

The surviving device has all keys. Operations continue using the remaining
device. To restore redundancy:

1. Flash firmware onto a replacement device
2. Initialize it with `--dkek-shares 1`
3. Import the DKEK share from the `.pbe` file
4. Wrap each key from the surviving device and unwrap onto the replacement
5. Verify state roots match

### Replacing a failed device (step by step)

```sh
# Initialize replacement (reader 1 after swapping hardware)
sc-hsm-tool -r 1 --initialize \
  --label "HSM-Secondary-v2" \
  --so-pin 3537363231383830 \
  --pin 648219 \
  --dkek-shares 1

# Import the original DKEK share
sc-hsm-tool -r 1 --import-dkek-share cluster-dkek-share.pbe \
  --password "cluster-passphrase"

# Sync all keys from the surviving primary
sc-hsm-tool -r 0 --wrap-key wrapped-key-01.bin \
  --key-reference 1 --pin 648219
sc-hsm-tool -r 1 --unwrap-key wrapped-key-01.bin \
  --key-reference 1 --pin 648219

# Repeat for each key, then verify
opensc-tool -r 0 -s "80543A00"
opensc-tool -r 1 -s "80543A00"
```

### Both devices fail simultaneously

This is the catastrophic scenario. Recovery requires:

1. The `cluster-dkek-share.pbe` file and its passphrase
2. The wrapped key backup files (`wrapped-key-*.bin`)

Without both of these, keys are permanently lost. This is why offline
backups are recommended even in a mirrored configuration.

Recovery procedure:

```sh
# Initialize a new device
sc-hsm-tool --initialize \
  --label "HSM-Recovered" \
  --so-pin 3537363231383830 \
  --pin 648219 \
  --dkek-shares 1

# Import the DKEK share
sc-hsm-tool --import-dkek-share cluster-dkek-share.pbe \
  --password "cluster-passphrase"

# Restore each key from the wrapped backups
sc-hsm-tool --unwrap-key wrapped-key-01.bin \
  --key-reference 1 --pin 648219
sc-hsm-tool --unwrap-key wrapped-key-02.bin \
  --key-reference 2 --pin 648219
# ... repeat for all keys
```

Then set up a second device as described in this guide to restore redundancy.

---

## Security considerations

- **DKEK share file**: This is the master secret for key recovery. Store it
  offline. Anyone with this file and the passphrase can decrypt wrapped key
  backups.
- **Wrapped key files**: These are encrypted under the DKEK. They are safe
  to store on disk, but losing them means losing the ability to restore
  individual keys without a live device.
- **Same DKEK on both devices**: This is required for key transfer to work.
  The DKEK exists only in device volatile RAM -- it is re-derived from the
  share on each power cycle (after the share is re-imported). If you change
  the DKEK on one device (by re-initializing), it must be re-synchronized.
- **PIN independence**: Each device can have a different user PIN. The DKEK
  and the keys are independent of the PIN value. This means you can change
  the PIN on one device without affecting the other.
