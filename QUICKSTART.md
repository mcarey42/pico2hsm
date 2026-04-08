# pico2hsm Quick Start Guide

This guide walks you through building and flashing pico2hsm firmware for the
first time. No prior experience with embedded development or security hardware
is assumed. Follow the steps in order.

---

## What you will end up with

After completing this guide you will have:
- pico2hsm firmware installed on your device
- A signing key that proves firmware came from you (explained below)
- Your device ready to act as a USB hardware security module

---

## What you need

### Hardware

One of the following supported boards:

| Board | Where to get it | Notes |
|-------|----------------|-------|
| Waveshare RP2350-One 4MB | waveshare.com | Smallest, USB-A dongle form factor |
| Waveshare RP2350-One 16MB | waveshare.com | Same board, more storage for keys |
| Raspberry Pi Pico 2 | raspberrypi.com | Cheapest option; needs a USB cable |
| Waveshare RP2350-Geek | waveshare.com | Has a small LCD screen |

You do **not** need a debug probe to follow this guide. You will flash the
firmware by holding a button and plugging in USB (called BOOTSEL mode).

### A computer running Linux or macOS

Windows works too but the commands below are written for Linux/macOS. If you
are on Windows, use WSL2 (Windows Subsystem for Linux).

---

## Step 1: Install the tools

Open a terminal and run these commands one at a time. Each should complete
without errors before you move to the next.

### 1a. Install Rust

Rust is the programming language the firmware is written in. If you already
have Rust installed, skip this step.

```sh
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Follow the on-screen prompts and choose option 1 (default install). When
it finishes, close and reopen your terminal, then verify:

```sh
rustc --version
# Should print something like: rustc 1.78.0 (...)
```

### 1b. Add the embedded ARM target

The firmware runs on an ARM chip. This adds support for that chip type to Rust:

```sh
rustup target add thumbv8m.main-none-eabihf
```

### 1c. Install picotool

`picotool` is a Raspberry Pi tool that handles UF2 files and firmware signing.

```sh
# Debian / Ubuntu
sudo apt install picotool

# macOS (requires Homebrew — https://brew.sh if you don't have it)
brew install picotool

# Verify
picotool version
# Should print: picotool v2.x.x
```

If your package manager doesn't have it, download it from:
https://github.com/raspberrypi/picotool/releases

### 1d. Optional: install the flashing tool

If you want to flash via USB cable with a debug probe (faster iteration), also
install `probe-rs`. If you plan to only use the BOOTSEL drag-and-drop method,
you can skip this for now.

```sh
cargo install probe-rs-tools
```

---

## Step 2: Get the code

```sh
git clone https://github.com/mcarey42/pico2hsm
cd pico2hsm
```

---

## Step 3: Create your signing key

This is the most important step. Read it fully before running any commands.

### What is a signing key and why does it matter?

Think of a signing key like a wax seal on a letter. When you seal a letter, anyone who receives it can verify it came from you and hasn't been tampered with. Your firmware signing key works the same way: every firmware file you build gets "sealed" with it, and the device checks that seal before running the firmware.

There are two parts:

- **Private key** (`ec_firmware_signing_key.pem`) — This is like your personal seal stamp. Keep it secret. If someone else gets it, they could build firmware that your device trusts. If you lose it, you will not be able to install firmware updates on any device you lock down with it.

- **Public key** (`ec_firmware_signing_key.pub`) — This is like the impression your seal leaves on wax. It's safe to share. The device stores a fingerprint of this key in its permanent memory (OTP) to know whose firmware to trust.

### Generate the key

Run this script from the project root:

```sh
./generate_firmware_signing_keys.sh
```

You should see output ending with something like:

```
SHA-256 fingerprint of public key (record this):
  a3f8...c920

===============================================================================
  WARNING: The private key (ec_firmware_signing_key.pem) is EXTREMELY SENSITIVE.
  ...
===============================================================================
```

**Write down or copy that fingerprint somewhere safe.** You will need it when provisioning devices.

### Save the key somewhere safe

This is critical. The key file lives in the project directory for now, but you
should also keep a backup copy somewhere secure. Good options:

- **USB drive stored offline** — Copy both `.pem` and `.pub` files to a USB
  drive, eject it, and put it somewhere physical (a drawer, a safe, etc.)
- **Password manager** — Many password managers (Bitwarden, 1Password) let you
  attach files to an entry. Store both key files there.
- **Encrypted external drive** — If you use an encrypted backup drive, include
  the key files in that backup.

> What NOT to do:
> - Don't commit these files to git (they are in `.gitignore` — the project
>   will refuse to build if they are accidentally added)
> - Don't email them to yourself or store them in cloud storage unencrypted
> - Don't lose them — there is no recovery if your device is locked and the
>   key is gone

---

## Step 4: Build the firmware

The build script does everything automatically. Just run:

```sh
./build-all.sh
```

What it does:
1. Checks that all tools are installed
2. Detects your signing key and signs every firmware file it builds
3. Builds firmware for all supported board variants
4. Creates UF2 files for each board (ready for drag-and-drop flashing)
5. Saves signed firmware and OTP configuration files to the `dist/` folder

A full build takes about 5–10 minutes. When it finishes you should see a summary like:

```
══ Build summary ══
Raspberry Pi Pico 2 4MB         OK     flash=476KB  ram=381KB
Waveshare RP2350-One  4MB       OK     flash=476KB  ram=381KB
Waveshare RP2350-One 16MB       OK     flash=476KB  ram=381KB
...
```

### What is in the `dist/` folder?

After the build, `dist/` contains one set of files per board:

```
dist/
  pico2hsm-pico2_4m.uf2              ← Flash this file to a Pico 2
  pico2hsm-rp2350_one_4m.uf2         ← Flash this file to an RP2350-One 4MB
  pico2hsm-rp2350_one_16m.uf2        ← Flash this file to an RP2350-One 16MB
  ...
  pico2hsm-pico2_4m-signed.elf       ← Signed firmware binary (for probe-rs)
  pico2hsm-pico2_4m-otp.json         ← OTP settings for locking the device
  ...
```

The UF2 files are what you will copy to the device. The OTP JSON files record
what needs to be burned into the device's permanent memory to enable secure
boot — you will use these later when you are ready to lock devices for
production.

---

## Step 5: Flash your device

There are two ways to flash. Pick the one that matches your setup.

### Method A: BOOTSEL drag-and-drop (no extra hardware needed)

This is the easiest method. You just need a USB cable.

1. **Hold the BOOTSEL button** on your board (it is labelled BOOTSEL)
2. **While holding BOOTSEL, plug in the USB cable** to your computer
3. The board appears as a USB drive called `RPI-RP2` (on Linux it mounts under `/media/`)
4. **Copy the right UF2 file** for your board:

```sh
# For Raspberry Pi Pico 2:
cp dist/pico2hsm-pico2_4m.uf2 /media/$USER/RPI-RP2/

# For Waveshare RP2350-One 4MB:
cp dist/pico2hsm-rp2350_one_4m.uf2 /media/$USER/RPI-RP2/

# For Waveshare RP2350-One 16MB:
cp dist/pico2hsm-rp2350_one_16m.uf2 /media/$USER/RPI-RP2/
```

On macOS, the drive appears in Finder as `RPI-RP2`. You can drag and drop the file.

5. The board automatically reboots and runs the firmware. The USB drive
   disappears — that's normal and means it worked.

### Method B: Probe-rs (requires a debug probe)

If you have a debug probe (Raspberry Pi Debug Probe, or any CMSIS-DAP adapter)
connected via SWD:

```sh
./build-all.sh --flash pico2_4m
```

Replace `pico2_4m` with your board's feature name. This builds, flashes, and
shows you the boot log. Press Ctrl+C when you have seen enough output.

---

## Step 6: Verify it worked

Plug the device into a USB port (without holding BOOTSEL this time). On Linux,
run:

```sh
lsusb | grep -i "CCID\|HSM\|SmartCard"
```

You should see the device listed. It presents itself as a USB CCID smart card
reader. To do a quick functional check with OpenSC:

```sh
# Install OpenSC if you don't have it
sudo apt install opensc    # Linux
brew install opensc        # macOS

# List connected cards
pkcs11-tool --list-slots
```

You should see something like:

```
Available slots:
Slot 0 (0x0): Feitian ...
  token label  : SmartCard-HSM (UserPIN)
  token manufacturer: ...
```

If you see a slot listed, the firmware is running correctly.

---

## Step 7: Initialize the device and generate a key

Now that the firmware is running, initialize the device as a SmartCard-HSM
and generate your first key. This is a quick smoke test — see
[docs/SINGLE_DEVICE_SETUP.md](docs/SINGLE_DEVICE_SETUP.md) for a full
walkthrough with key backup.

```sh
# Initialize with a test PIN (change these for real use)
sc-hsm-tool --initialize \
  --label "MyHSM" \
  --so-pin 3537363231383830 \
  --pin 648219 \
  --dkek-shares 0

# Generate an EC P-256 key pair
pkcs11-tool --login --pin 648219 \
  --keypairgen --key-type EC:prime256v1 \
  --id 01 --label "test-key"

# Sign a test message
echo "hello pico2hsm" > /tmp/msg.txt
pkcs11-tool --login --pin 648219 --sign \
  --mechanism ECDSA-SHA256 --id 01 \
  --input-file /tmp/msg.txt --output-file /tmp/sig.bin

# If the sign command returns without error, the device is fully operational
```

The `--dkek-shares 0` option above means no DKEK is configured, which is fine
for a quick test. For production use with key backup and recovery, set
`--dkek-shares 1` and follow the full guide.

---

## What's next

### Set up the device for daily use

Follow [docs/SINGLE_DEVICE_SETUP.md](docs/SINGLE_DEVICE_SETUP.md) to
initialize the device with DKEK key backup, generate production keys, and
configure key recovery.

### Set up a mirrored pair for redundancy

Follow [docs/SETUP_LOCAL_CLUSTER.md](docs/SETUP_LOCAL_CLUSTER.md) to
run two pico2hsm devices with identical keys — if one device fails, the other
has everything.

### Connect with an application

pico2hsm works with any PKCS#11-aware application:

- **SSH keys**: Use `pkcs11-tool` to generate a key, then configure OpenSSH
- **GPG / email signing**: Use `gpg --card-edit` (the device acts as an OpenPGP card)
- **PIV / smart card login**: The device supports the PIV standard used by YubiKey

See [BUILDING.md](BUILDING.md) for full build options, and the `docs/` folder
for APDU reference documentation for each applet.

### Locking your device for production

Once you are happy the device works, you can lock it down so only firmware
signed with your key will run. This is a permanent, irreversible operation.

The steps (covered in `docs/SECURE_PROVISIONING_PLAN.md`) are:
1. Use the provisioning APDUs (INS=0xF1 SET_PRODUCTION_MODE) to put the device in production mode
2. Use the `picotool otp load` command with the OTP JSON file from `dist/` to burn the key fingerprint into the device
3. The device will then verify your firmware signature on every boot

> **Important**: Only do this on a device you intend to deploy. You cannot
> undo it. If you want to keep experimenting, use a separate development device.

---

## Troubleshooting

### "picotool not found"

Install picotool as described in Step 1c. On Ubuntu 22.04 you may need to
add a PPA or install from source — see https://github.com/raspberrypi/picotool.

### The drive doesn't appear when I hold BOOTSEL

Try holding BOOTSEL before connecting USB, not after. On some boards the timing
is strict. Also make sure you are using a data USB cable, not a charge-only cable.

### Build fails with "error[E0463]: can't find crate"

Your Rust installation may be out of date. Run:

```sh
rustup update
```

### "picotool seal failed"

Your signing key may be in the wrong format. Delete both key files and run
`./generate_firmware_signing_keys.sh` again to generate a fresh pair.

### The device appears as a drive every time I plug it in

The firmware did not flash successfully. Try the BOOTSEL method again, making
sure you hold the button until the drive appears, then copy the file.

### pkcs11-tool shows no slots

The pcscd daemon may not be running:

```sh
sudo systemctl start pcscd
pkcs11-tool --list-slots
```

If it still shows nothing, check `dmesg | tail -20` after plugging in the device
to see if the USB device is being recognised at the kernel level.
