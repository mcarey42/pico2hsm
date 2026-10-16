# pico2hsm — Production Provisioning Guide (2.0)

How to turn a development board into a production HSM. The finished board has:

- your own signing keys in OTP;
- a per-device storage secret;
- secure boot;
- the store closed to BOOTSEL.

`tools/provision-device.py` automates the per-device work. It runs one stage at a time, checks every precondition, and reads back every write. It also boots the board between stages.

Stages 0–8 were verified end to end on an RP2350-One (silicon A2) on 2026-10-15, followed by the full hardware test suite under secure boot. The stage results are in §10.

> **Every OTP write is permanent.** There is no undo, no reset and no
> factory restore. Read §1 before you generate a key or touch a board.

---

## 1. Your keys, your risk

pico2hsm ships **no keys**. You generate and keep the keys that every device you provision will trust, forever. The project cannot recover them, revoke them, or help you if they are lost or leaked.

**What the keys are.** Two secp256k1 private keys, one per OTP boot-key slot. The RP2350 bootrom accepts no other curve.

| File | Slot | Use |
|---|---|---|
| `ec_firmware_signing_key-bootkey0.pem` | BOOTKEY0 | Signs every firmware build and partition table. |
| `ec_firmware_signing_key-bootkey1.pem` | BOOTKEY1 | Offline backup. Signs nothing until key 0 must be retired. |

Provisioning does three things to the key slots:

- burns the SHA-256 of each public key into the device;
- marks both slots valid;
- **permanently invalidates slots 2 and 3**, so no one, you included, can add a key later.

**If you lose both private keys:** no new firmware will ever boot on any device you provisioned. The devices keep working with the firmware they have, but they can never be updated.

**If a private key leaks:** whoever holds it can build firmware your devices will boot.

- While debug is still enabled (stage 9 not done), this is no worse than the open debug port already is.
- Once debug is disabled, the key is the whole security of the device.

Respond at once:

1. **If key 0 leaked:**
   - Sign new firmware with key 1, install it on every device, and confirm it boots.
   - Then set `BOOT_FLAGS1.KEY_INVALID` bit 0 on each device. This revokes slot 0.
   - Key 1 is now your only key, so guard it as if it were both.
2. **If key 1 (or both) leaked:** there is no slot left to move to. Retire those devices.

**If you only suspect a leak,** treat the key as leaked.

**How to keep them:**

- Generate the keys on an offline machine.
- Store each key encrypted (hardware token, LUKS volume or sealed vault), in two places, and keep key 1 apart from key 0.
- Record each key's **fingerprint**, the value burned into OTP:
  `openssl pkey -in <key>.pem -pubout -outform DER | tail -c 64 | sha256sum`
- The repo ignores `*.pem`. Never commit, paste or email a key.
- Build machines need key 0 only. Key 1 stays in offline storage until it is needed.

**The per-device storage secret (IKM).** Stage 2 writes 64 random bytes into OTP page 4. The device derives from them the key that seals its keystore.

- The tool generates the IKM in memory, writes it, verifies it and wipes the host copy, so **no one holds a copy**.
- This is by design: a copy could decrypt that device's flash if it ever left the device.
- The consequence: if a device dies, its keys are gone unless you exported them first, as a DKEK backup or to a domain peer (see [SINGLE_DEVICE_SETUP.md](SINGLE_DEVICE_SETUP.md) and [CLUSTER_PLAN_V3.md](CLUSTER_PLAN_V3.md)).
- Set up backups before you rely on a device.

**What provisioning does not protect against.** Tell whoever relies on the device:

- **Debug left enabled** (we stop before stage 9 on test boards): anyone with SWD access can read RAM, including the derived storage key.
- **Silicon A2 and A3:**
  - Erratum RP2350-E24 lets a skilled attacker with the board in hand bypass signature checks by glitching and swapping the flash chip.
  - A2 also has the BOOTSEL glitch errata (E20, E21).
  - Buy A4 silicon for production units.
- **Flash replay:** the store, its anchor and the counters all live in external flash.
  - Someone could image the flash chip with a clip and write the image back later.
  - That rolls the store back: a deleted key returns, or retry counters reset.
  - The contents stay encrypted; only rollback is possible.
- **Decapsulation:** chaff (stage 2) makes imaging the OTP harder, not impossible.

---

## 2. What you need

- **`picotool` with USB support**, on PATH. It talks to boards in BOOTSEL.
- **A `picotool` built with mbedtls**, for signing (`seal`, `partition create --sign`).
  - These are often two different builds.
  - Point the build scripts and the provisioning tool at the right one with `PICOTOOL=` and `--picotool`.
- **`openssl`, `python3` and `pyscard`** (`pip install pyscard`) for the provisioning tool, plus a running `pcscd`.
- **The board on USB.**
  - Debug builds can reboot themselves into BOOTSEL.
  - Release builds need the BOOT button; the tool says when.

The procedure is the same on every board:

| Board | Feature flag | Flash | Firmware slots |
|---|---|---|---|
| Raspberry Pi Pico 2 | `pico2_4m` | 4 MB | one, 1.83 MB |
| Waveshare RP2350-One | `rp2350_one_4m` | 4 MB | one, 1.83 MB |
| RP2350-One with a 16 MB chip | `rp2350_one_16m` | 16 MB | A/B, 4 MB each |
| Waveshare RP2350-Geek | `rp2350_geek_16m`, `rp2350_geek_sdcard` | 16 MB | A/B, 4 MB each |
| Waveshare RP2350-LCD-1.47-B | `waveshare_rp2350_lcd_16m`, `waveshare_rp2350_lcd_sdcard` | 16 MB | A/B, 4 MB each |

---

## 3. One time: the keys

```sh
./generate_firmware_signing_keys.sh 0     # BOOTKEY0: signs builds
./generate_firmware_signing_keys.sh 1     # BOOTKEY1: offline backup
tools/otp-bootkeys.sh                     # -> dist/otp/stage1-bootkeys.json, stage3-key-slots.json
```

`otp-bootkeys.sh` does four things:

- refuses anything but 256-bit secp256k1 keys;
- prints both fingerprints;
- prints the exact OTP rows each key will occupy;
- writes the two OTP files that the provisioning tool loads.

Neither file can enable secure boot. That is a separate, explicit stage.

---

## 4. Per release: signed firmware and the signed table

```sh
# Release firmware for every board, signed with key 0 (picotool seal):
PICOTOOL=/path/to/signing/picotool ./build-all.sh
#   -> dist/pico2hsm-<feature>-signed.elf, dist/pico2hsm-<feature>.uf2

# The board's production partition table, signed with key 0:
/path/to/signing/picotool partition create boards/pt_4m_prod.json pt-prod-signed.uf2 \
    --sign ec_firmware_signing_key-bootkey0.pem        # 16 MB boards: pt_16m_prod.json
```

`picotool seal` also writes `*-seal-otp-ENABLES-SECURE-BOOT.json`. **Never load that file.** Besides the key hash, it sets `crit1.secure_boot_enable`.

The production tables (`boards/pt_*_prod.json`) close the store regions to BOOTSEL: the binding, the counter log, the RSA pool and the keystore. They also make the flash outside the firmware slots read-only to BOOTSEL. From BOOTSEL, then:

- the store can't be read;
- the table can't be erased or replaced;
- signed firmware can still be installed.

See [FLASH_LAYOUT_2_0.md](FLASH_LAYOUT_2_0.md), including §5.5. That section explains why the space must stay *readable* on A2 silicon.

---

## 5. Per device: `tools/provision-device.py`

Run each stage on its own, or use `through N` to run stages 0 to N in order.

- Options go **before** the subcommand.
- Without `--burn`, a stage that would write OTP stops and says so.
- Every stage can be re-run: a completed stage reports "already done" and writes nothing.

```sh
P="tools/provision-device.py --serial <CHIPID>"
$P status                                   # read-only report of every relevant row
$P stage 0                                  # preflight
$P --burn stage 1                           # boot-key hashes
$P --burn stage 2                           # storage IKM + chaff
#   then: FORMAT STORE and INITIALIZE (your SO-PIN, PIN, DKEK shares)
$P --burn stage 3                           # key slots
$P --burn stage 4                           # page-4 lock
$P --burn --table pt-prod-signed.uf2 --image firmware-signed.uf2 \
      --unsigned-image firmware-unsigned.uf2 stage 5   # secure boot
$P --burn stage 6                           # BOOTSEL trimming
$P --burn --soak 10 stage 7                 # glitch detector
$P --burn --so-pin-file so-pin.txt stage 8  # production mode
```

**Stage 0, preflight.**
- Writes: nothing.
- Checks: the chip revision; that the OTP is blank; that the key files are present and free of CRIT1.

**Stage 1, boot keys.**
- Writes: BOOTKEY0 and BOOTKEY1, rows 0x80–0x9F.
- Verified by: every row's data and ECC read back and compared with the key files.
- Reversible: no. The keys are inert until stages 3 and 5.

**Stage 2, storage IKM.**
- Writes: the IKM at rows 0x100–0x11F, and chaff at rows 0x120–0x13F.
- Verified by:
  - an exact raw read-back, tolerating one ECC-corrected bit per row;
  - each chaff row is the complement of its IKM row;
  - the firmware boots and read-locks the key page.
- Reversible: no. The old keystore no longer opens.

**Stage 3, key slots.**
- Writes: BOOT_FLAGS1, 3 copies: KEY_VALID 0b0011, KEY_INVALID 0b1100.
- Verified by: all three copies read back.
- Reversible: no. Slots 2 and 3 are gone for good.

**Stage 4, page-4 lock.**
- Writes: PAGE4_LOCK1 = 0x3D3D3D.
- Verified by: read-back; BOOTSEL can no longer read row 0x100; the keystore still opens.
- Reversible: no.

**Stage 5, secure boot.**
- Writes: installs the signed table and image, then sets CRIT1.SECURE_BOOT_ENABLE (8 copies).
- Verified by:
  - the signed image boots before the burn;
  - all 8 copies read back;
  - the firmware reports secure boot;
  - an unsigned image is refused, then the signed one is restored.
- Reversible: **no. This is the point of no return for booting.** RISC-V is also disabled for good.

**Stage 6, BOOTSEL trimming.**
- Writes: BOOT_FLAGS0: UART boot and OTP boot off.
- Verified by: 3 copies read back; BOOTSEL (picotool and UF2) still works; the firmware boots.
- Reversible: no.

**Stage 7, glitch detector.**
- Writes: CRIT1.GLITCH_DETECTOR_ENABLE, default sensitivity.
- Verified by: 8 copies read back; `--soak` reboot cycles through BOOTSEL and the firmware.
- Reversible: no.

**Stage 8, production mode.**
- Writes: the pico2hsm boot flags in row 0x140, through the SET PRODUCTION MODE APDU (needs the SO-PIN).
- Verified by: the flag is visible after a reboot, and the firmware boots.
- Reversible: no.

**Why this order.** Each stage is checked by the next one's boot.

- Secure boot comes only after the keys are proven to match the signed image: stage 5 boots that image first.
- Production mode comes only after secure boot.
  - Release firmware in production mode resets without secure boot.
  - The firmware itself refuses SET PRODUCTION MODE otherwise.
- The page-4 lock comes after the IKM and chaff are complete, because a locked page can never be completed.
- The page-4 lock also comes before secure boot. After secure boot, RAM helpers such as `picotool otp permissions` would need signing.

**Between stage 2 and stage 8.** The new IKM re-keys the keystore. Format it (`pico2hsm-tool store format`) and INITIALIZE the device as you would any new HSM (`sc-hsm-tool --initialize …`). Stage 8 needs the SO-PIN you chose, in a file, as 16 hex digits. Delete that file afterwards.

**What production mode changes.** At every boot, the firmware:

- arms the glitch detector at maximum sensitivity and locks its configuration until the next power-on;
- (release builds) refuses to boot if secure boot is off;
- (release builds) halts if a debugger is attached;
- (release builds) records the bookkeeping bit 0 of row 0x140.

The firmware never writes the CRIT1 debug bits; that is stage 9.

**What the tool will not do:** stages 9 and 10. Both are decisions with no way back. Do them by hand, once the device has run in production for a while.

---

## 6. Stages 9 and 10: by hand, later

**Stage 9, debug.** Until this stage, SWD can read everything, including the derived storage key in RAM. Choose one of three options:

- **Leave debug enabled.**
  - The board stays recoverable over SWD.
  - Secure boot then protects only against accidents and casual attacks.
- **Debug key** (OTP KEY5/KEY6).
  - Debug opens only for whoever presents the 128-bit key.
  - Check that your probe can send the key before you burn it.
- **Disable debug** (`CRIT1.DEBUG_DISABLE`, plus `SECURE_DEBUG_DISABLE`).
  - This is permanent.
  - Never combine it with BOOTSEL fully disabled unless the firmware can update itself, or one firmware bug bricks the board.

**Stage 10, final locks.**

- Make pages 1 and 2 read-only to the bootloader, so no one can add flags or keys through BOOTSEL.
  - This also stops *you* from revoking key 0 through BOOTSEL (§1). After this lock, only firmware can set `KEY_INVALID`, so ship that ability in the firmware before you lock.
- Optionally, lock page 63 against the RMA flag.
- Read the factory lock bits first and merge your changes with them.

**Never set any of these:**

- `BOOT_FLAGS0.DISABLE_WATCHDOG_SCRATCH`: breaks update boots and try-before-you-buy.
- `DISABLE_FLASH_BOOT`.
- `DISABLE_SRAM_WINDOW_BOOT`.
- `FLASH_PARTITION_SLOT_SIZE`: erratum E18.
- `LOCK_S = 3` on page 4 or page 5.
- `SECURE_PARTITION_TABLE` with an unsigned table. The bootrom then treats the table as invalid and installs an empty one, so the board doesn't boot and all of its flash is open to BOOTSEL.

---

## 7. The OTP map

| Rows | Field | Written by | Value |
|---|---|---|---|
| 0x040–0x047 | CRIT1 (8 copies, 3-of-8 vote) | stages 5, 7 | bit 0 SECURE_BOOT_ENABLE; bit 4 GLITCH_DETECTOR_ENABLE |
| 0x048–0x04A | BOOT_FLAGS0 (3 copies) | stage 6 | bit 13 DISABLE_OTP_BOOT; bit 19 DISABLE_BOOTSEL_UART_BOOT |
| 0x04B–0x04D | BOOT_FLAGS1 (3 copies) | stage 3 | KEY_VALID 0b0011; KEY_INVALID 0b1100 |
| 0x080–0x08F | BOOTKEY0 (ECC) | stage 1 | SHA-256 of key 0's public point X‖Y |
| 0x090–0x09F | BOOTKEY1 (ECC) | stage 1 | SHA-256 of key 1's public point |
| 0x100–0x11F | pico2hsm storage IKM (ECC) | stage 2 | 64 random bytes; never leaves the device |
| 0x120–0x13F | chaff (raw) | stage 2 | 24-bit complement of each IKM row (datasheet §13.8.2) |
| 0x140 | pico2hsm boot flags (raw) | stage 8 | bit 1 PRODUCTION_MODE; bit 2 PROVISIONED |
| 0x141 | — | never | must stay blank (erratum E17) |
| 0x180–0x1AF | device identity key + chaff (page 6) | — | reserved; not provisioned |
| 0xF89 | PAGE4_LOCK1 (byte ×3) | stage 4 | 0x3D3D3D: Secure read-only; Non-secure and bootloader have no access |

The storage master key is derived at every boot as `HKDF-SHA256(salt "pico2hsm-smk", IKM, info "storage-master-key")` and is never stored. The source of truth is `firmware/src/security/otp_layout.rs`.

`picotool otp get` prints raw 24-bit rows. For ECC rows, the top byte is the ECC, so compare only the low 16 bits with the expected values.

---

## 8. Recovery and failure scenarios

| Situation | What happens | What to do |
|---|---|---|
| A stage stops with an error | Nothing after the failed check was written. | Read the message, then re-run the stage. `status` shows the device's state. |
| Stage 2 reports a mismatch | Page 4 is partly written. | Stop. The device cannot be provisioned further; keep it as a development board. |
| Unsigned or corrupt firmware after stage 5 | The board stays in BOOTSEL. | Install a signed image: `picotool load -p 0 -x <signed.uf2>`. |
| Keystore refused after an update | Store status says why. | See [KEYSTORE_RECOVERY.md](KEYSTORE_RECOVERY.md). |
| Release firmware reset-loops after stage 8 | Production mode without secure boot. This should be impossible: stage 8 and the firmware both refuse it. | Inspect over SWD (debug is still enabled). |
| Spurious resets after stage 8 | The glitch detector at maximum sensitivity, if the supply is noisy. | Check the supply. A firmware update can lower the sensitivity; the OTP flag cannot be undone. |
| Key 0 compromised | | Follow §1: move to key 1, then revoke slot 0. |
| Device dies | Its keys are gone unless they were backed up. | Restore from a DKEK backup or from domain peers. |

---

## 9. Records to keep per device

```
Chip ID / USB serial:   <from `status`>
Board / feature:        <e.g. rp2350_one_4m>
Silicon revision:       <A2 / A3 / A4>
Firmware version:       <IMAGE_DEF version, signed with BOOTKEY0>
Boot keys:              BOOTKEY0 <fingerprint>, BOOTKEY1 <fingerprint>
Stages completed:       0–8 (debug: enabled)
Provisioned on:         <date>, by <who>
```

Do not record the IKM. It is not available, by design.

---

## 10. Verification log

RP2350-One, chip ID 139E6D9547578EEE, silicon A2, 2026-10-15. The board ran debug firmware (needed for `80 FE 14`, BOOTSEL without a button). It was signed with BOOTKEY0 (fingerprint `84333e14…`; backup BOOTKEY1 `0d7c9108…`).

| Stage | Result |
|---|---|
| 0 | OK; A2 noted. |
| 1 | All 32 rows match (data and ECC). |
| 2 | IKM and chaff written, with 0 corrected bits. The firmware reports the key page locked. The store was formatted under the OTP key. 37/37 storage and layout tests pass. |
| 3 | BOOT_FLAGS1 = 0x0C03 in all 3 copies. |
| 4 | Page 4 is unreadable from BOOTSEL; the keystore opens. |
| 5 | Boot diagnostic: MATCHING KEY + VERIFIED OK. The unsigned image was refused (the board fell back to BOOTSEL), and the signed image restored. |
| — | Full hardware suite under secure boot: see the stage 5 suite run. |
| 6–8 | See below. |

---

## References

- [FLASH_LAYOUT_2_0.md](FLASH_LAYOUT_2_0.md): partition tables, slots, the closed store and BOOTSEL findings.
- [KEYSTORE_RECOVERY.md](KEYSTORE_RECOVERY.md): store recovery runbook.
- RP2350 datasheet:
  - boot and secure boot: chapters 5 and 10;
  - OTP: chapter 13, including §13.8.2 on chaff;
  - errata: the appendix.
- picotool: `seal`, `partition create --sign`, `otp get/load/set`.
- `tools/otp-bootkeys.sh`, `tools/provision-device.py`, `firmware/src/security/otp_layout.rs`.
