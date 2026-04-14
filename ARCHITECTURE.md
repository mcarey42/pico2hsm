# pico2hsm Architecture

This document describes all significant design decisions for the pico2hsm project.

---

## 1. Flash Memory Layout Per Board

### RP2350-One 4MB

```
0x10000000  BOOT2    (256 bytes) — RP2350 second-stage bootloader
0x10000100  FLASH    (2MB - 256 bytes) — firmware (hard limit; linker errors if exceeded)
0x10200000  KEYSTORE (2MB) — pico2hsm keystore sectors
```

### RP2350-Geek 16MB / Waveshare LCD 16MB / SDCard variants

```
0x10000000  BOOT2    (256 bytes)
0x10000100  FLASH    (2MB - 256 bytes) — firmware
0x10200000  KEYSTORE (14MB) — pico2hsm keystore sectors
```

SDCard storage extends the keystore beyond the internal flash address space. The RAID manager treats SDCard FlashChip instances identically to SPI flash instances; no additional linker regions are required.

### RP2354 (Embedded Flash)

```
0x10000000  BOOT2    (256 bytes)
0x10000100  FLASH    (2MB - 256 bytes) — firmware
(no KEYSTORE region — external SPI flash only)
```

The RP2354's embedded flash is used only for firmware. All keystore data is stored on external SPI flash chips attached to SPI0/SPI1.

### Firmware Size Hard Limit

All linker scripts define `FLASH` with `LENGTH = 2M - 256`. If the linked firmware exceeds this size, the linker emits a fatal error (`region FLASH overflowed by N bytes`). This is intentional: the `rsa` feature is estimated to add ~1MB; the base firmware must fit in ~1MB to leave room for RSA.

---

## 2. Storage Stack

The storage system is layered. Each layer has one responsibility:

```
┌──────────────────────────────────────────────────────────┐
│  PKCS#15 Filesystem  (filesystem.rs)                     │
│  — EF/DF virtual file hierarchy, FCI templates           │
├──────────────────────────────────────────────────────────┤
│  Storage Encryption  (StorageManager + crypto)           │
│  — AES-256-GCM per key object, nonce = key_id || seq_no  │
│  — Key: Storage Master Key derived from OTP              │
├──────────────────────────────────────────────────────────┤
│  Integrity Verification  (integrity.rs)                  │
│  — CRC32 of header + ciphertext (fast, checked on read)  │
│  — BLAKE2s-256 of plaintext (checked after decrypt)      │
│  — seq_no monotonicity check (rollback protection)       │
├──────────────────────────────────────────────────────────┤
│  Write-Ahead Log  (wal.rs)                               │
│  — WAL sectors 1 and 2 per chip                          │
│  — Atomic write: WAL write → commit → data write → clear │
│  — Boot-time replay of committed-but-unapplied entries   │
├──────────────────────────────────────────────────────────┤
│  RAID-1 Mirror Layer  (raid.rs)                          │
│  — Reads: primary-first, mirror fallback on failure      │
│  — Writes: both members, WAL must be committed first     │
│  — Bad sector tracking, chip health state machine        │
├──────────────────────────────────────────────────────────┤
│  FlashChip Trait  (flash_chip.rs, sdcard.rs)             │
│  — SpiFlash: SPI0/SPI1 external flash chips              │
│  — QmiFlash: RP2350 built-in QMI flash (firmware chip)   │
│  — SdCardFlash: SDCard via embedded-sdmmc                │
└──────────────────────────────────────────────────────────┘
```

---

## 3. Multi-Chip SPI Topology

### QMI (Quad SPI Memory Interface) — CS0 only

The RP2350 QMI interface provides XIP (execute-in-place) for CS0. pico2hsm uses CS0 exclusively for firmware execution. The firmware binary is in the first 2MB; the keystore occupies the remaining flash of the same chip (addressed via memory-mapped reads or explicit SPI commands after exiting XIP).

CS1 on QMI is not used (reserved for future use).

### SPI0 and SPI1 — Keystore Flash

Two independent SPI buses (SPI0, SPI1) each support up to 4 flash chips using software GPIO chip-select lines:

```
SPI0: CLK=GPIO2, MOSI=GPIO3, MISO=GPIO4
  CS0: GPIO5   (chip 0)
  CS1: GPIO6   (chip 1)
  CS2: GPIO7   (chip 2)
  CS3: GPIO8   (chip 3)

SPI1: CLK=GPIO10, MOSI=GPIO11, MISO=GPIO12
  CS0: GPIO13  (chip 4 — mirrors chip 0)
  CS1: GPIO14  (chip 5 — mirrors chip 1)
  CS2: GPIO15  (chip 6 — mirrors chip 2)
  CS3: GPIO9   (chip 7 — mirrors chip 3)
```

GPIO pin assignments are board-specific and finalized in the board module.

---

## 4. 3-Byte vs 4-Byte Address Auto-Detection

Flash chips up to 128 Mbit (16 MB) use 3-byte addressing (24-bit addresses, opcodes 0x03/0x02/0x20). Larger chips require 4-byte addressing (32-bit addresses, opcodes 0x13/0x12/0x21).

The `SpiFlash` implementation detects the addressing mode at init time via the JEDEC ID:
- If capacity > 16MB → switch to 4-byte mode (send EN4B command 0xB7)
- Record in `SpiFlash::addr_mode` field
- All subsequent read/write/erase commands use the appropriate opcode

No manual configuration is required; the firmware auto-detects and adapts.

---

## 5. RAID-1 Bilateral Symmetry

Mirror pairs are always SPI0/n ↔ SPI1/n (same CS index, different bus):

```
Pair 0: SPI0/CS0 (chip 0) ↔ SPI1/CS0 (chip 4)
Pair 1: SPI0/CS1 (chip 1) ↔ SPI1/CS1 (chip 5)
Pair 2: SPI0/CS2 (chip 2) ↔ SPI1/CS2 (chip 6)
Pair 3: SPI0/CS3 (chip 3) ↔ SPI1/CS3 (chip 7)
```

This bilateral symmetry means that a failure of an entire SPI bus (broken trace, failed SPI controller) loses only one side of each mirror pair — all data remains accessible from the other bus.

All writes are mirrored: the WAL is written to both chips in a pair before the commit record is written. If the primary write fails, the firmware degrades the pair and continues with mirror-only operation.

---

## 6. Bad Chip Detection, Replacement Workflow, Resync

### Detection

Bad sectors are detected when:
- A flash read returns unexpected data (SPI error or bit flip)
- A CRC32 integrity check fails on a sector header
- An erase or write operation fails (flash returns error status)

When a sector fails, `mark_bad_sector()` is called, recording the sector in the chip's directory sector bad-block table. After N bad sectors (configurable, default 8), the chip is marked `Degraded`.

If `jedec_id()` returns `None`, the chip is immediately marked `Dead` (physically unresponsive).

### Replacement Workflow

1. Operator removes the dead chip and inserts a new blank chip
2. On the next JEDEC probe, the new chip responds but its directory sector does not contain `SECTOR_MAGIC` → state becomes `Blank`
3. Firmware reports this via `chip_state()` (visible to hsm-tool)
4. StorageManager initiates resync for the affected pair

### Resync Procedure

Resync copies all sectors from the healthy pair member to the recovering member:

1. Set pair state to `Resyncing { progress_sector: 0 }`
2. For each sector from `DATA_START_SECTOR` to `capacity / SECTOR_SIZE`:
   a. Read sector from healthy member (with integrity check)
   b. Erase corresponding sector on recovering member
   c. Write sector to recovering member
   d. Verify write succeeded (read-back CRC32 check)
   e. Increment `progress_sector`
3. Copy directory sector and WAL sectors last
4. Set pair state to `InSync`

Resync is interruptible: `progress_sector` is persisted in the directory sector of the healthy member. After a power cycle, resync resumes from the last recorded `progress_sector`.

---

## 7. Device-Tied Encryption

All keystore sectors are encrypted with AES-256-GCM under the Storage Master Key (SMK). The SMK is derived at every boot and never persisted:

```
OTP rows 0x20–0x3F  →  32-byte device root secret (burned at provisioning)
                              ↓
              HKDF-SHA256(IKM=root_secret,
                          salt="pico2hsm-smk",
                          info=device_serial_number)
                              ↓
                      Storage Master Key (32 bytes)
```

The device serial number is stored in OTP rows 0x40–0x47 and is unique per device. This binds the SMK to both the hardware (OTP root secret) and the device identity (serial number).

The root secret rows are read-locked after provisioning. No software can read them after that point — the HKDF derivation happens once during provisioning to test correctness, then the rows are locked.

Encryption parameters per key object:
- Algorithm: AES-256-GCM
- Key: SMK
- Nonce (96 bits): `key_id (16 bits) || seq_no (8 bits) || random (72 bits)`
- AAD: `ObjectHeader` bytes (excluding `crc32` and `blake2s` fields)

---

## 8. DKEK Exchange via Noise_XX

The DKEK (Device Key Encryption Key) is used exclusively for HSM-to-HSM key backup. It is established via a Shamir Secret Sharing ceremony using the Noise_XX protocol for secure transport.

### Why Noise_XX

Noise_XX provides:
- Mutual authentication (both devices prove ownership of static key pairs)
- Forward secrecy (new ephemeral keys per session)
- Simple, auditable implementation using the `snow` crate

### Transport options

**USB (local):** Noise frames are carried in SC-HSM EXTRAS APDUs (INS=0x54, P1=0x10). Both HSM devices must be connected to the same host machine. A host-side tool sends APDUs to both devices to relay Noise frames between them.

### DKEK share accumulation

```
Device A generates share_A (32 random bytes)
Device B generates share_B (32 random bytes)
...
DKEK = share_A XOR share_B XOR ... XOR share_N
```

Each device loads its share(s) via Noise_XX exchange. When `shares_loaded >= threshold`, the DKEK is established in RAM. Key wrap/unwrap operations are enabled.

The DKEK is never written to flash. It must be re-established (by loading shares again) after each power cycle. This is by design: an attacker with physical access to the flash cannot recover wrapped keys without also performing the Noise exchange ceremony.

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

`KeyStore::wipe_by_owner(AppletId)` erases only keys whose `applet_id` byte matches the given owner. SC-HSM `INITIALIZE` calls `wipe_by_owner(AppletId::ScHsm)` so PIV and OpenPGP keys are not affected.

Flash magic `"P2K2"` was bumped from the older single-byte scheme; on-flash data from a pre-u32 build is rejected and surfaced as incompatible (re-INITIALIZE required).

Per-applet PIN slots are fully implemented. Each applet stores its PIN(s) as
sentinel `KeyObject` entries in the shared flash keystore under their own
`AppletId` namespace:

| Applet | PIN storage |
|--------|-------------|
| SC-HSM | `KeyId::sc_hsm(0, 0xFF)` — 101-byte sentinel |
| PIV    | `KeyId::piv(0xFF)` — 101-byte sentinel (same format) |
| OpenPGP | `KeyId::openpgp(0xFE)` — PW1 (35-byte sentinel) |
|         | `KeyId::openpgp(0xFF)` — PW3 (35-byte sentinel) |

---

## 10. Protocol Pluggability

The firmware supports multiple card protocols behind a single USB CCID interface. The `HsmProtocol` trait (defined in `pico2hsm-core`) is the plugin interface:

```rust
pub trait HsmProtocol {
    fn process_apdu(&mut self, apdu: &[u8]) -> Vec<u8, 4096>;
    fn handles_aid(&self, aid: &[u8]) -> bool;
    fn protocol_name(&self) -> &'static str;
}
```

The APDU dispatcher (`firmware/src/apdu/dispatcher.rs`) holds an array of registered protocol implementations. On `SELECT AID` (INS=0xA4, P1=0x04), it iterates the array and activates the first implementation that returns `true` from `handles_aid()`.

**Security state is reset on every SELECT AID.** The dispatcher unconditionally
clears the active protocol's session state (e.g. `pin_verified`,
`mgmt_key_authenticated`) whenever a client re-selects an applet, as required
by NIST SP 800-73-4 §3.1.2 and the OpenPGP Card 3.4 specification.

### Currently registered protocols

1. **SC-HSM** (primary) — SmartCard-HSM 2 command set. Fully implemented and hardware-validated.
2. **PIV** — NIST SP 800-73-4. Fully implemented (`applet-piv` feature). Hardware-validated 2026-04-05.
3. **OpenPGP** — OpenPGP Card 3.4. Fully implemented (`applet-openpgp` feature). Hardware-validated 2026-04-05.
4. **OpenPGP + Ed25519/X25519** — (`applet-openpgp-curve25519` feature). Implemented; awaiting hardware validation.

Adding a new protocol requires only: implementing `HsmProtocol`, registering it in the dispatcher array, and defining the AID.

### PIV implementation details (NIST SP 800-73-4)

- Supported commands: SELECT, GET DATA, VERIFY, CHANGE REFERENCE DATA, RESET RETRY COUNTER, GENERAL AUTHENTICATE, GENERATE KEY PAIR
- Slots: 9A (Authentication), 9C (Digital Signature), 9D (Key Management), 9E (Card Authentication)
- Algorithms: P-256, P-384 ECDSA; 3DES management key authentication
- GENERATE KEY PAIR response wraps EC point in `7C → 7F49 → 86` TLV per Table 3.3-1
- Keys and PIN are flash-persistent via the shared keystore (`AppletId::Piv`)

### OpenPGP implementation details (OpenPGP Card 3.4)

- Supported commands: SELECT, GET DATA, VERIFY, CHANGE REFERENCE DATA, PSO:CDS, PSO:DECIPHER, INTERNAL AUTHENTICATE, GENERATE KEY PAIR, GET CHALLENGE
- Slots: SIG, DEC, AUTH
- Algorithms: P-256, P-384, P-521 ECDSA/ECDH; Ed25519/X25519 via `applet-openpgp-curve25519`
- PSO:CDS returns raw r‖s (not DER) for ECDSA as per OpenPGP Card spec
- PW1 (sign mode 82) and PW3 (admin) are independently flash-persistent
- PW1 retry counter is RAM-only per the spec; it resets on power cycle

---

## 11. Binary Size Strategy

The firmware must fit in 2MB (enforced by the linker). Strategies used:

- `opt-level = "z"` — optimize for size (profile.release)
- `lto = true` — link-time optimization removes dead code across crates
- `codegen-units = 1` — single codegen unit for maximum LTO effectiveness
- `panic = "abort"` — removes panic unwinding infrastructure (~50KB saving)
- `strip = true` — strips debug symbols from release binary
- RSA gated behind `rsa` feature — RSA crate adds ~1MB (soft multiplications)
- Elliptic curve crates use `default-features = false` — disable `std` and `alloc`
- `heapless` for all dynamic buffers — no allocator needed

Target sizes (estimates):
- Base firmware (no RSA): ~600KB
- With RSA: ~1.6MB
- Both fit within the 2MB FLASH region

---

## 12. Debug Mode

When compiled with `--features debug`:

- Memory dump APDUs are compiled in (`debug_dump.rs` handler)
- Secure boot enforcement is relaxed (firmware runs without valid signature)
- JTAG disable check is logged but not enforced
- defmt log level is set to TRACE

**CRITICAL**: The `debug` feature MUST NEVER be enabled for devices deployed in production. It would expose memory contents and bypass all hardware security checks.

The CI pipeline does not build `debug` feature variants.

---

## 13. Security Hardening

### OTP lock

After device provisioning:
1. Root secret rows (0x20–0x3F) are read-locked via OTP peripheral
2. Serial number rows (0x40–0x47) are write-locked (prevent overwrite)
3. Provisioning status byte is written and write-locked

### JTAG disable

JTAG is permanently disabled by burning the `JTAG_DISABLE` OTP fuse during provisioning. After this fuse is set, JTAG access is blocked at the hardware level regardless of firmware state.

### PIN lockout

User PIN:
- Default retry counter: 3 (configurable at init, max 15)
- Counter is decremented BEFORE verifying the PIN (prevents timing oracle)
- After counter reaches 0: SW=0x6983 (AUTH BLOCKED) on all VERIFY attempts
- Recovery requires SO-PIN or PUK via RESET RETRY COUNTER

SO-PIN:
- 8 bytes (numeric)
- Separate retry counter (default 5)
- If SO-PIN is also locked, the device requires physical reset and re-initialization

### Zeroize on drop

All types that hold secret material implement `zeroize::ZeroizeOnDrop`:
- `KeyMaterial` — private key bytes
- `Dkek` — DKEK key bytes
- `PinManager` — PIN hash and salt
- Temporary crypto buffers use `ZeroizeGuard` RAII wrapper

### Watchdog

The hardware watchdog is armed at boot with a 5-second timeout. The watchdog is serviced by the main Embassy task every 500ms. A firmware hang (e.g. infinite loop in a command handler) results in a hardware reset within 5 seconds.

---

## 14. Dual-Core Async Runtime

The RP2350 has two Cortex-M33 cores. pico2hsm uses both with separate
Embassy async executors.

### Core 0 — USB + Transport

Core 0 runs the main Embassy executor with these tasks:

- **USB device driver** (`usb.run()`) — handles USB enumeration, endpoints
- **CCID transport loop** — receives APDUs via USB bulk-out, sends responses
  via bulk-in. Sends CCID time-extension messages (BWT) every 1.5 s while
  waiting for Core 1 to finish processing
- **CDC-ACM serial logger** (`drain_one()`) — forwards defmt log lines to
  `/dev/ttyACMx`; checks DTR before writing to avoid CCID stalls
- **Display rendering** (LCD boards) — async DMA SPI flush of framebuffer
- **Flash service** — handles `FLASH_REQ` channel for Core 1 flash writes
  (embassy-rp `in_ram()` asserts Core 0)

Core 0 uses `embassy_futures::join` to run USB and CCID concurrently.

### Core 1 — APDU Dispatch

Core 1 runs a dedicated Embassy executor with a single task:

- **`dispatcher_task()`** — receives APDUs from `APDU_CHANNEL`, calls the
  synchronous `Dispatcher::dispatch()` chain, sends responses back via
  `RESP_CHANNEL`

The dispatch chain is fully synchronous on Core 1:
```
dispatcher_task()
  └─ Dispatcher::dispatch()
       ├─ SELECT AID → activates applet (ScHsm / Piv / OpenPgp)
       └─ all other INS → active protocol's process_apdu()
            └─ ScHsm::dispatch() → <command>::handle()
```

### Cross-Core Communication

| Channel | Direction | Purpose | Sync mechanism |
|---------|-----------|---------|----------------|
| `APDU_CHANNEL` | Core 0 → 1 | APDU bytes from USB | RP2350 spinlock 29 |
| `RESP_CHANNEL` | Core 1 → 0 | Response bytes | RP2350 spinlock 30 |
| `FLASH_REQ` | Core 1 → 0 | Flash write requests | Embassy channel |
| `WATCHDOG_HEARTBEAT` | Core 1 → 0 | Liveness counter | AtomicU32 |
| `CORE1_PROGRESS` | Core 1 → 0 | Operation progress | AtomicU32 |

### Core 1 Stack

Core 1 uses a 192 KB static stack (`CORE1_STACK`). Measured peak usage is
~65 KB (38 KB `ScHsmState` inline storage + 16 KB dispatch-chain
temporaries), giving ~3x headroom. The `Dispatcher` is initialized via
`init_in_place()` on Core 0 to avoid stack overflow during construction.

### defmt Constraint

Core 1 **must not** call `defmt` logging functions. The defmt RTT channel
uses RP2350 spinlock 31 with `BLOCK_IF_FULL` mode. If Core 0 is servicing
USB while Core 1 calls defmt, a deadlock occurs: Core 1 spins on spinlock
31 waiting for Core 0 to drain the RTT buffer, but Core 0 is blocked
waiting for Core 1's APDU response. All Core 1 logging uses
`serial_println!` (direct UART writes) instead.
