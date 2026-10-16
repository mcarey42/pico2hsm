# pico2hsm Architecture

This document describes all significant design decisions for the pico2hsm project.

---

## 1. Flash Memory Layout Per Board

Every board boots through a bootrom partition table. The source of truth is
`firmware/src/storage/flash_layout.rs`; `boards/pt_*.json` are the tables
and `boards/*.x` the linker scripts, and a host test ties the three
together. The full description, with the hardware findings behind it, is
[docs/FLASH_LAYOUT_2_0.md](docs/FLASH_LAYOUT_2_0.md).

### 4 MB boards (Pico 2, RP2350-One): `boards/pt_4m.json`

```
0x000000  partition table      (8 KB)
0x002000  fw-a                 (1,880 KB) — the only firmware slot
0x1D8000  binding              (32 KB)    — Storage V2 binding block ring
0x1E0000  counters             (64 KB)    — counter log v2 (retry counters, anchor)
0x1F0000  rsa-pool             (48 KB)    — pre-generated RSA keys (`rsa`)
0x1FC000  spare                (16 KB)    — the 1.x counter log, migrated once
0x200000  unpartitioned        (4 KB)     — the flash midpoint
0x201000  keystore             (2,044 KB)
```

### 16 MB boards (Geek, Waveshare LCD, RP2350-One 16 MB, QMI and SD variants): `boards/pt_16m.json`

```
0x000000  partition table      (8 KB)
0x002000  fw-a                 (4,088 KB)
0x400000  fw-b                 (4,088 KB) — A/B with fw-a, try-before-you-buy
0x7FE000  unpartitioned        (12 KB)    — the flash midpoint
0x801000  binding              (32 KB)
0x809000  counters             (64 KB)
0x819000  rsa-pool             (48 KB)
0x825000  spare                (16 KB)
0x829000  keystore             (~7.8 MB; reserved on the SD-card builds)
0xFFF000  unpartitioned        (4 KB)     — RP2350-E10
```

The image runs from its slot at `0x1000_0000` through the bootrom's address
translation, so it links against the slot's size; store reads use the
untranslated XIP alias `0x1C00_0000`. The store partitions are closed to
the bootloader (BOOTSEL: picotool, UF2) and to Non-secure code. A release
build checks the loaded table at boot and drops its storage key if the
table differs from the compiled one.

On the SD-card builds (`rp2350_geek_sdcard`, `waveshare_rp2350_lcd_sdcard`) the keystore is the microSD card in the board's built-in slot (`SdCardFlash`). The binding block, the counter log and the RSA key pool stay on internal flash on every board: a removable card must not hold the PIN retry counters or the rollback anchor.

There is no RP2354 build and no external-flash board. pico2hsm targets off-the-shelf boards only (see `README.md`, Supported Boards).

### Firmware Size Hard Limit

Each linker script ends `FLASH` at the slot's end (`0x1D5F00` bytes after the
256-byte `BOOT2` region on 4 MB boards). If the linked firmware exceeds it,
the linker emits a fatal error (`region FLASH overflowed by N bytes`) instead
of the image growing into the store. Release images are ~650–690 KB, debug
images ~1.3 MB.

---

## 2. Storage Stack

The keystore is Storage V2 ([docs/STORAGE_V2.md](docs/STORAGE_V2.md)), layered:

```
┌──────────────────────────────────────────────────────────┐
│  KeyStore trait  (storage/keystore.rs)                   │
│  — what the applets call: save/fetch/erase, group wipes  │
├──────────────────────────────────────────────────────────┤
│  FlashKeyStoreV2  (storage/keystore_v2.rs)               │
│  — KeyObject blobs sealed under K_obj (AES-256-GCM),     │
│    V2 object header as AAD, fresh TRNG nonce             │
│  — binding block (storage/binding.rs), counter-log       │
│    anchor (storage/retry_counter.rs)                     │
├──────────────────────────────────────────────────────────┤
│  Store engine  (storage/store_v2.rs)                     │
│  — journal ring, index snapshots, lookup, allocation     │
│  — every record and snapshot MACed under K_idx           │
├──────────────────────────────────────────────────────────┤
│  StoreFlash  (flash_chip.rs, sdcard.rs)                  │
│  — QMI: the RP2350's own flash chip                      │
│  — SdCardFlash: SD card via embedded-sdmmc (raw blocks)  │
└──────────────────────────────────────────────────────────┘
```

Each build uses exactly one store medium: internal QMI flash, or the SD card
on the SD-card builds. The 1.x filesystem, the write-ahead log, the RAID-1
layer, `SpiFlash`, `HybridKeyStore` and multi-chip support were removed in
Storage V2 phase 5 (`docs/STORAGE_V2.md` §12). `storage/integrity.rs`
(CRC32 + BLAKE2s) is still in the tree but nothing calls it.

When the store refuses to mount (a swapped or damaged card, lost writes,
a 1.x keystore), see [docs/KEYSTORE_RECOVERY.md](docs/KEYSTORE_RECOVERY.md).

---

## 3. Storage Hardware

The keystore lives on the board's own QSPI flash chip (through the RP2350 QMI), or on the microSD card in the SD-card builds. pico2hsm adds no hardware: no external SPI flash chips, no mirrored flash, no custom board. SC-HSM key references are one byte (SmartCard-HSM / OpenSC compatibility), which bounds what one device can usefully hold, so more flash buys nothing. A 4 MB board holds 128 SC-HSM user keys, a 16 MB board all 251 user key refs (`MAX_SC_HSM_KEYS`).

Redundancy comes from other devices instead: members of a domain hold the same keys and keep them in sync (`docs/CLUSTER_PLAN_V3.md`).

The SD-card builds exist for one use case: enroll the board in a domain, then ship it with the card sent separately. The card alone is useless (objects are encrypted under keys derived from the device's OTP-based storage master key); the device alone holds no user keys. On reinsertion the device verifies the card (store ID, MACs, the rollback anchor on internal flash; `docs/STORAGE_V2.md` §8, §11).

Sections 4–6 of earlier versions of this document (SPI flash address modes, RAID-1 pairs, chip replacement and resync) described the unused multi-chip design and have been removed.

---

## 7. Device-Tied Encryption

All keystore objects are encrypted with AES-256-GCM under keys derived from
the Storage Master Key (SMK). The SMK is derived at every boot and never
persisted (`security/otp.rs`, `derive_smk`):

```
OTP rows 0x100–0x11F  →  64-byte storage secret (32 ECC rows, burned at provisioning;
                         its chaff, the complement of each raw row, at 0x120–0x13F)
                              ↓
              HKDF-SHA256(IKM=storage secret,
                          salt="pico2hsm-smk",
                          info="storage-master-key")
                              ↓
                      Storage Master Key (32 bytes)
```

The OTP map is `firmware/src/security/otp_layout.rs` (boot flags at row
`0x140`; never row `0x110`). After deriving the SMK the firmware read-locks
the key page (OTP page 4, rows `0x100`–`0x13F`) for the rest of the boot, so
neither SWD nor later code can read the secret again. Provisioning is
[docs/PROVISIONING.md](docs/PROVISIONING.md).

On a board whose OTP storage secret is blank, a release build has no SMK
and the keystore refuses to store or load keys. Debug builds, and release
builds with the `insecure-dev-keystore` feature, use the fixed (public)
development key instead and warn at boot.

Keys derived from the SMK (`docs/STORAGE_V2.md` §4):
- `K_obj = HKDF(SMK, store_id, group epoch, key_id)` per object; AES-256-GCM
  with a fresh TRNG nonce and the V2 object header as AAD, so an object
  only opens as the version the index names.
- `K_idx` MACs the journal records and index snapshots.
- `K_bind` seals the binding block (which also holds the SC-HSM SO-PIN).

---

## 8. DKEK and the DKEK exchange

The DKEK (Device Key Encryption Key) is the AES-256 key that wraps keys for
HSM-to-HSM backup (WRAP / UNWRAP KEY, CardContact blob format). It is the
XOR of 1–8 shares (SC-HSM-compatible share import; not Shamir sharing),
persisted at the reserved SC-HSM key ref `0xFD` and restored at boot.

A DKEK can also be sent from one device to another by the DKEK exchange
(SC-HSM EXTRAS `0x54`, P1 `0x35`–`0x38`; `security/dkek.rs`): an ephemeral
P-256 ECDH, HKDF-SHA256 and AES-256-GCM, a simplified Noise-like protocol
(the `snow` crate's Noise_XX does not build `no_std` without `alloc`). The
exchange needs the SO-PIN and an enrolled (pinned) peer, and a DKEK is never
overwritten while one is set. See `docs/CLUSTER_PLAN_V2.md` §1 and
`docs/CLUSTER_PLAN_V3.md`.

---

## 9. HSM-to-HSM Backup (Only)

pico2hsm does NOT support plaintext key export to the host. Private key material never leaves the device except as a DKEK-wrapped blob.

The export path is:
```
Key on flash (encrypted under SMK)
    → decrypt under SMK (in RAM only)
    → re-encrypt under DKEK (in RAM)
    → return wrapped blob to host
```

The import path is:
```
Wrapped blob from host
    → decrypt under DKEK (in RAM only)
    → re-encrypt under SMK (in RAM)
    → write to flash
```

At no point is the raw private key material written to any host-visible channel.

---

## 10a. Storage Namespace / Applet Ownership

Keys stored in the flash keystore carry applet ownership via the `KeyId` u32 encoding (in `pico2hsm-core/src/key.rs`):

```
bits 31–24: partition_id  (u8)  — 0 = default partition
bits 23–16: applet_id     (u8)  — 0=SC-HSM, 1=PIV, 2=OpenPGP  (AppletId enum)
bits 15–8:  reserved            — always 0
bits  7–0:  proto_ref     (u8)  — protocol-level key reference
```

Applet byte `0x10` (`AppletId::Domain`) holds the domain records (object-ID sidecars, member certificates, the pinned peer; `firmware/src/domain/`).

Each applet's objects form a *group* in the store. SC-HSM `INITIALIZE`, PIV reset and OpenPGP TERMINATE wipe their own group (one journal record; the group's epoch is rotated in the binding block), so the other applets' keys are not affected. INITIALIZE also wipes the domain records (`wipe_by_owner(AppletId::Domain)`).

Per-applet PINs are implemented. Each applet stores its PIN record as a
sentinel `KeyObject` in the shared keystore under its own `AppletId`
namespace; the retry counters live in the counter log on internal flash
(`storage/retry_counter.rs`) and are spent before each comparison:

| Applet | PIN storage |
|--------|-------------|
| SC-HSM | `KeyId::sc_hsm(0, 0xFF)` — user PIN / PUK; the SO-PIN is in the binding block |
| PIV    | `KeyId::piv(0xFF)` — PIN / PUK (and the management key at `KeyId::piv(0x9B)`) |
| OpenPGP | `KeyId::openpgp(0xFE)` — PW1 |
|         | `KeyId::openpgp(0xFF)` — PW3 |

---

## 10. Protocol Pluggability

The firmware supports multiple card protocols behind a single USB CCID interface. The `HsmProtocol` trait (defined in `pico2hsm-core`) is the plugin interface:

```rust
pub trait HsmProtocol {
    fn process_apdu(&mut self, apdu: &[u8]) -> Vec<u8, 4098>;
    fn handles_aid(&self, aid: &[u8]) -> bool;
    fn protocol_name(&self) -> &'static str;
}
```

The APDU dispatcher (`firmware/src/apdu/dispatcher.rs`) holds one field per compiled-in protocol (`sc_hsm`, `piv`, `openpgp`). On `SELECT AID` (INS=0xA4, P1=0x04) it activates the protocol whose `handles_aid()` matches; every other APDU goes to the active protocol's `process_apdu_with_store()`, which takes the board's `KeyStore`.

**Security state is reset on every SELECT AID.** The dispatcher unconditionally
clears the active protocol's session state (e.g. `pin_verified`,
`mgmt_key_authenticated`) whenever a client re-selects an applet, as required
by NIST SP 800-73-4 §3.1.2 and the OpenPGP Card 3.4 specification.

### Currently registered protocols

1. **SC-HSM** (primary) — SmartCard-HSM 2 command set. Fully implemented and hardware-validated.
2. **PIV** — NIST SP 800-73-4. Fully implemented (`applet-piv` feature). Hardware-validated 2026-04-05.
3. **OpenPGP** — OpenPGP Card 3.4. Fully implemented (`applet-openpgp` feature). Hardware-validated 2026-04-05.
4. **OpenPGP + Ed25519/X25519** — (`applet-openpgp-curve25519` feature). Implemented; awaiting hardware validation.

Adding a new protocol requires: implementing `HsmProtocol` (and a `process_apdu_with_store`), adding it to the dispatcher's `ActiveProtocol` routing, and defining the AID.

### PIV implementation details (NIST SP 800-73-4)

- Supported commands: SELECT, GET DATA, PUT DATA, VERIFY, CHANGE REFERENCE DATA, RESET RETRY COUNTER, GENERAL AUTHENTICATE, GENERATE KEY PAIR, SET MANAGEMENT KEY (`FF`), GET METADATA (`F7`), RESET (`FB`)
- Slots: 9A (Authentication), 9C (Digital Signature), 9D (Key Management), 9E (Card Authentication)
- Algorithms: P-256, P-384 ECDSA; 3DES management key authentication
- GENERATE KEY PAIR response wraps EC point in `7C → 7F49 → 86` TLV per Table 3.3-1
- Keys and PIN are flash-persistent via the shared keystore (`AppletId::Piv`)

### OpenPGP implementation details (OpenPGP Card 3.4)

- Supported commands: SELECT, GET DATA, PUT DATA, VERIFY, CHANGE REFERENCE DATA, RESET RETRY COUNTER, PSO:CDS, PSO:DECIPHER, INTERNAL AUTHENTICATE, GENERATE KEY PAIR, GET CHALLENGE, GET RESPONSE, TERMINATE DF / ACTIVATE FILE
- Slots: SIG, DEC, AUTH
- Algorithms: P-256, P-384, P-521 ECDSA/ECDH; Ed25519/X25519 via `applet-openpgp-curve25519`
- PSO:CDS returns raw r‖s (not DER) for ECDSA as per OpenPGP Card spec
- PW1 and PW3 (admin) are independently flash-persistent
- PW1 and PW3 retry counters are in the counter log on internal flash; they survive power cycles

---

## 11. Binary Size Strategy

The firmware must fit its slot (1,880 KB on 4 MB boards, 4,088 KB on 16 MB
boards; enforced by the linker). Strategies used:

- `opt-level = "z"` — optimize for size (profile.release)
- `lto = true` — link-time optimization removes dead code across crates
- `codegen-units = 1` — single codegen unit for maximum LTO effectiveness
- `panic = "abort"` — removes panic unwinding infrastructure
- `strip = true` — strips debug symbols from release binary
- RSA gated behind `rsa` feature (~115 KB of flash and a 48 KB heap)
- Elliptic curve crates use `default-features = false` — disable `std` and `alloc`
- `heapless` for buffers — the only allocator is the RSA heap (`rsa`)

Measured sizes (release, 2026-10-15; `docs/BUILD_CONFIGURATIONS.md`):
- SC-HSM only, no RSA: ~500 KB
- All applets + RSA: ~650 KB (4 MB boards) to ~690 KB (display boards)
- Debug build, all applets + RSA: ~1.3 MB

---

## 12. Debug Mode

When compiled with `--features debug`:

- The debug APDUs (SC-HSM INS `0xFE`) are compiled in (`debug_dump.rs`):
  watchdog and recovery test hooks, reboot to BOOTSEL, image and
  partition-table info, RSA benchmarks. The memory-dump sub-commands are
  still a stub (6A80).
- The production-mode boot checks are skipped (debugger-attached halt,
  secure-boot-enabled assertion, the JTAG-disabled bookkeeping bit).
- Display detail screens are shown.

Separately, debug **builds** (the dev profile, `debug_assertions`) use the
development storage key on blank OTP and open the store even when the
partition table does not match. `DEFMT_LOG` sets the log level at compile
time; `build-all-debug.sh` sets `trace`.

**CRITICAL**: The `debug` feature MUST NEVER be enabled for devices deployed in production. It would expose memory contents and bypass all hardware security checks.

The CI pipeline does not build `debug` feature variants.

---

## 13. Security Hardening

### OTP lock

Provisioning (`tools/provision-device.py`, stages 0–8 of
[docs/PROVISIONING.md](docs/PROVISIONING.md)) burns the two boot-key hashes
(BOOTKEY0/1) and invalidates slots 2 and 3; writes the 64-byte storage
secret (rows `0x100`–`0x11F`) and its chaff (`0x120`–`0x13F`); locks OTP
page 4 against BOOTSEL; installs the signed production partition table and
enables secure boot; trims BOOTSEL; enables the glitch detector; and sets
production mode in the boot flags (row `0x140`). Independently, the
firmware read-locks the key page on every boot once it has derived the
SMK.

### Debug disable

Debug access is decided in stage 9, by hand ([docs/PROVISIONING.md](docs/PROVISIONING.md)
§6): leave it enabled, protect it with a debug key, or disable it for good
(CRIT1 `DEBUG_DISABLE`). In production mode the firmware only records a
JTAG-disabled bookkeeping bit in the boot flags row; it does not burn CRIT1
itself, and it halts at boot if a debugger is attached.

### PIN lockout

- Retry counters live in the counter log on internal flash and are
  decremented **before** the PIN is compared (`with_persisted_attempt`),
  so cutting power mid-check does not save an attempt.
- After the counter reaches 0: SW=0x6983 (AUTH BLOCKED) on all VERIFY attempts.
- SC-HSM: recovery of the user PIN via the SO-PIN or PUK (RESET RETRY
  COUNTER); a blocked SO-PIN leaves only re-initialisation.
- PINs are stored as salted PBKDF2-HMAC-SHA256 hashes (10,000 iterations).

### Zeroize

Secrets are wiped in place: zeroized before they are moved or dropped,
`Zeroizing` wrappers and `security::zeroize::key_buf` for fixed key buffers
(see `CLAUDE.md`, Security invariants).

### Watchdog

The hardware watchdog is armed at boot with an 8-second timeout
(`firmware/src/watchdog.rs`). Only core0 feeds it, every 1 s, while core1
is idle or making progress (heartbeat or request/reply counters moved
within 30 s). A core1 stuck for 30 s, or a core0 that stops running its
executor, resets the chip; the next boot logs the cause.

---

## 14. Dual-Core Runtime

The RP2350 has two Cortex-M33 cores. Core0 runs an Embassy async executor;
core1 runs a synchronous loop with no executor.

### Core 0 — USB + Transport

Core 0 runs the main Embassy executor with these tasks:

- **USB device driver** (`usb.run()`) — handles USB enumeration, endpoints
- **CCID transport loop** — receives APDUs via USB bulk-out, sends responses
  via bulk-in. Sends CCID time-extension messages every 1.5 s while
  waiting for core1 (`await_core1_response`)
- **CDC-ACM serial logger** (`drain_one()`) — forwards `cdc_log!` lines to
  `/dev/ttyACMx`; checks DTR before writing to avoid CCID stalls
- **Display task** (LCD boards) — renders core1's published snapshot through
  a 16-row band buffer (no framebuffer; `docs/DISPLAY_ARCHITECTURE.md`)
- **Flash service** (`flash_service`) — runs core1's `FlashOp`s from
  `FLASH_REQ` (embassy-rp's `in_ram()` asserts core 0)
- **Watchdog feeder** — see §13

Core 0 uses `embassy_futures::join` to run USB, CCID, the flash service and
the display task concurrently.

### Core 1 — APDU Dispatch

Core 1 runs `dispatcher_loop()`, a synchronous loop: it takes each APDU
from the `APDU_BOX` mailbox, runs the dispatch chain, writes the response
straight into `RESP_BOX` and signals `RESP_READY`. Between APDUs it runs
the RSA key pool's background work in short slices; with nothing to do it
sleeps in `wfe` until core0's `sev`.

```
dispatcher_loop()
  └─ Dispatcher::dispatch_into()
       ├─ SELECT AID → activates applet (ScHsm / Piv / OpenPgp)
       └─ all other INS → active protocol's process_apdu_with_store()
            └─ dispatch_with_store() → route_with_store() → <command>::handle*()
```

### Cross-Core Communication

| Channel | Direction | Purpose | Sync mechanism |
|---------|-----------|---------|----------------|
| `APDU_BOX` | Core 0 → 1 | APDU bytes from USB, filled and read in place | `mailbox::Mailbox` (Acquire/Release flag) + `sev` |
| `RESP_BOX` | Core 1 → 0 | Response bytes, written in place | `mailbox::Mailbox` |
| `RESP_READY` | Core 1 → 0 | "response ready" doorbell | Channel, RP2350 spinlock 30 |
| `FLASH_REQ` | Core 1 → 0 | Flash write requests (`FlashOp`) | Channel, RP2350 spinlock 27 |
| `FLASH_RESP` | Core 0 → 1 | Flash op results | Channel, RP2350 spinlock 26 |
| `CDC_LOG_CHANNEL` | both → 0 | `cdc_log!` lines | Channel, RP2350 spinlock 25 |
| `WATCHDOG_HEARTBEAT` | Core 1 → 0 | Liveness counter | Atomic |
| `CORE1_PROGRESS` | Core 1 → 0 | Operation progress | Atomic |

### Core 1 Stack

Core 1 uses a 96 KB static stack (`CORE1_STACK`), painted at boot. Measured
on hardware (2026-10-12, debug build, full hardware suite): peak 60.5 KB on
`pico2_4m`, 62.9 KB on `waveshare_rp2350_lcd_sdcard`; the watchdog feeder
logs the high water as it grows. MSPLIM at the stack base turns an overflow
into a fault. The `Dispatcher` (with the protocol state) lives in a static,
initialised in place (`init_in_place()`), not on this stack.

### defmt Constraint

Core 1 **must not** log through `defmt`. defmt's logger lock is a critical
section, and the firmware uses `cortex-m`'s `critical-section-single-core`,
which masks interrupts on one core only: a core1 log that overlaps a core0
log panics ("defmt logger taken reentrantly") and the watchdog resets the
chip. That includes embassy-rp internals, so internal-flash reads go through
`flash_chip::xip_read`. Core 1 diagnostics use `cdc_log!` (its channel takes
hardware spinlock 25) or `watchdog::crumb`.
