# Example 01: OpenSC smoke test

## What this demonstrates

This is the fastest possible "it works" check. In well under a second, it
verifies that:

- pcscd sees the pico2hsm device as a CCID smartcard reader;
- the device returns a valid ATR (Answer To Reset) — the first bytes a
  smartcard reports when powered on;
- the SC-HSM applet responds with its serial number.

If this example passes, your host toolchain, USB stack, pcscd, and pico2hsm
firmware are all wired together correctly. If it fails, every subsequent
example will also fail — start here when debugging.

## Prerequisites

- Flashed pico2hsm device on USB (see [QUICKSTART](../../QUICKSTART.md)).
- `opensc-tool` installed:
  - Debian / Ubuntu: `sudo apt install opensc`
  - macOS: `brew install opensc`
- `pcscd` running (Linux). On macOS this is automatic.
- Firmware feature: **none** — SC-HSM is always compiled in.

## Steps

1. List the readers pcscd can see:
   ```sh
   opensc-tool --list-readers
   ```
   Expected output contains a line similar to:
   ```
   0 Nitrokey Nitrokey 3 [CCID/ICCD Interface] (0000...) 00 00
   ```
   (Exact vendor string depends on your firmware's USB descriptor — the key
   marker is "CCID" and the trailing `00 00` indicating a card is present.)

2. Read the ATR:
   ```sh
   opensc-tool --atr
   ```
   Expected output (24 bytes, the pico2hsm SC-HSM ATR):
   ```
   3b:fe:18:00:00:81:31:fe:45:80:31:81:54:48:53:4d:31:73:80:21:40:81:07:fa
   ```
   The string `48 53 4d 31` is ASCII for `HSM1`; `80 31 81 54` is the historical
   bytes block that OpenSC matches against to bind the `sc-hsm` driver.

3. Read the device serial:
   ```sh
   opensc-tool --serial
   ```
   Expected output is an 8-byte hex string unique to your device, e.g.:
   ```
   DECC:0100:XXXX:XXXX
   ```

4. Run all of the above via the provided script:
   ```sh
   ./run.sh
   ```

## Expected result

`./run.sh` exits 0 and prints the reader, ATR, and serial with a final
`[ok] pico2hsm smoke test passed` line.

## Troubleshooting

**"No smart card readers found"**

pcscd isn't running or can't see the device.

```sh
# Linux:
sudo systemctl start pcscd
lsusb | grep -i "20a0\|1050"   # look for pico2hsm or similar CCID device VID

# macOS: replug the device; CryptoTokenKit re-enumerates automatically.
```

**"Unresponsive card: Communication error"**

Usually a USB enumeration race — the device was plugged in less than ~2 s
before pcscd polled it. Wait two seconds and retry:

```sh
sleep 2 && opensc-tool --atr
```

If the error persists, check `dmesg | tail -30` on Linux for CCID endpoint
errors. A common cause is a charge-only USB cable (no data lines) — swap
for a known-good data cable.

**ATR does not match expected**

Another smartcard reader (YubiKey, Nitrokey, etc.) is plugged in alongside
pico2hsm and came up as reader 0. List all readers and target the pico2hsm
one by index:

```sh
opensc-tool --list-readers
OPENSC_DEFAULT_READER=1 opensc-tool --atr
```

## Cleanup

None — this example is read-only. It does not touch flash or any persistent
device state.
