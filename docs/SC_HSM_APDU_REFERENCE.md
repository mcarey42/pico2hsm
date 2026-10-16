# SC-HSM APDU Reference — pico2hsm

Developer reference for the SmartCard-HSM 2 APDU command set as implemented in pico2hsm. All values are hexadecimal unless otherwise stated. This document is derived from the actual firmware source in `firmware/src/protocol/sc_hsm/`.

---

## 1. Overview

### Application Identifier (AID)

```
E8 2B 06 01 04 01 81 C3 1F 02 01
```

This is the CardContact SmartCard-HSM AID. Selecting it activates the SC-HSM protocol. OpenSC discovers the applet by matching this AID against the EF.DIR entry at file ID `0x2F00`.

### Answer to Reset (ATR)

```
3B FE 18 00 00 81 31 FE 45 80 31 81 54 48 53 4D 31 73 80 21 40 81 07 FA
```

24 bytes. The historical bytes `54 48 53 4D 31` decode to "THsm1" — the SmartCard-HSM marker that triggers OpenSC's `sc-hsm` driver to bind automatically. The TCK byte `0xFA` is an XOR checksum over T0 through the last historical byte. Do not modify this ATR.

### SELECT AID Response (FCI)

When the dispatcher responds to `SELECT` by AID, it returns an FCI in this exact structure:

```
6F <len>
  84 0B  E8 2B 06 01 04 01 81 C3 1F 02 01   -- DF name (AID)
  A5 07                                      -- proprietary info
    9F 6E 04  20 00 00 00                    -- COS version (2.0.0.0)
```

OpenSC's `iso7816_process_fci` requires outer tag `0x6F`, inner tag `0x84` for the DF name (not `0x4F`), and the `A5 → 9F6E` version structure.

### CLA Byte

All SC-HSM commands use `CLA = 0x00` unless noted. OpenSC's session-PIN flow uses `CLA = 0x80` for `SESSION PIN` (INS=0x26).

### Key Storage Limits

| Resource | Limit |
|---|---|
| SC-HSM user keys (`MAX_SC_HSM_KEYS`) | 128 on 4 MB boards, 251 (every user key ref) on 16 MB boards; past it 6A84 |
| Key / EF index entries (`MAX_KEY_INDEX`) | 400 on 4 MB boards, 768 on 16 MB boards |
| Reserved key refs | `0xFC`–`0xFF` (refused by user key commands) |
| EF cache (in RAM) | 16 entries of up to 1024 bytes |
| Max PIN length | 16 bytes |
| Max SO-PIN length | 16 bytes |

Keys and EFs live in the Storage V2 keystore (internal flash or the SD
card); RAM holds one decrypted object at a time (`OpBuffer`) plus the EF
cache.

---

## 2. Command Summary Table

| INS | Mnemonic | Description | Status |
|---|---|---|---|
| `0x20` | VERIFY | Verify User PIN, SO-PIN, or session PIN | Implemented |
| `0x22` | MSE SET | Manage Security Environment — select key/algo | Implemented |
| `0x24` | CHANGE REFERENCE DATA | Change User PIN or SO-PIN | Implemented |
| `0x26` | SESSION PIN | Generate and return a one-time session PIN | Implemented |
| `0x28` | PUK AUTH | Authenticate with PUK to unblock PIN | Implemented |
| `0x2A` | PSO | Perform Security Operation (sign / decipher / MAC) | Implemented |
| `0x2C` | RESET RETRY COUNTER | Reset PIN retry counter (requires SO-PIN) | Implemented |
| `0x34` / `0x72` | EXPORT KEY | Export a CardContact key blob under the DKEK (refused for NO_EXPORT keys) | Implemented |
| `0x46` | GENERATE KEY PAIR | Generate asymmetric key pair on-device | Implemented |
| `0x48` | GENERATE SYMMETRIC KEY | Generate AES-128/192/256 key on-device | Implemented |
| `0x50` | INITIALIZE | Initialize / re-initialize device | Implemented |
| `0x52` | KEY DOMAIN | DKEK share import and status (CardContact); pico2hsm domain management | Partially implemented |
| `0x54` | EXTRAS | Additional KDF / MAC primitives | Implemented |
| `0x58` | LIST KEYS | List key slots (IMPORT KEY uses `0x74`; see §3.25) | Implemented |
| `0x60` | BIP/SLIP HD DERIVE | BIP32 / SLIP-0010 hierarchical key derivation | Implemented |
| `0x62` | DECIPHER / DERIVE ASYM | ECDH key agreement or RSA decrypt (P1=key_id, P2=algo) or derive asymmetric key (P1=0x01 **and** P2=0x00) | Implemented |
| `0x68` | SIGN | Compute digital signature (ECDSA / RSA) | Implemented |
| `0x78` | SYMMETRIC CIPHER | AES-CBC / CTR / GCM / CMAC | Implemented |
| `0x82` | EXTERNAL AUTHENTICATE | Removed (2026-10): keyed by the stored SO-PIN hash, so reading the PIN record granted SO. Returns `6D00`. | Removed |
| `0x84` | GET CHALLENGE | Return random bytes from TRNG | Implemented |
| `0x86` | GENERAL AUTHENTICATE | Single-step challenge-sign via Dynamic Auth Template | Implemented |
| `0xA4` | SELECT | Select EF/DF within SC-HSM virtual filesystem | Implemented |
| `0xB0` | READ BINARY | Read PKCS#15 virtual EF data | Implemented |
| `0xB1` | READ BINARY ODD | Read EF data with explicit file-reference TLV | Implemented |
| `0xD6` | UPDATE BINARY | Write data to currently selected EF | Implemented |
| `0xD7` | WRITE DATA | Write TLV-framed data blob to addressed EF | Implemented |
| `0xE0` | CREATE FILE | Create new transparent EF (sets current file) | Implemented |
| `0xE4` | DELETE FILE | Delete key or EF from store | Implemented |
| `0xFE` | DEBUG DUMP | Dump RAM/flash region (debug feature only) | Debug build only |

---

## 3. Per-Command Reference

### 3.1 SELECT (INS = 0xA4)

Selects an EF or DF in the SC-HSM virtual PKCS#15 filesystem. When the SC-HSM applet is being activated from the dispatcher, `SELECT by AID` (P1=0x04, data=AID) is handled at the dispatcher level before this handler is invoked.

**Command:**

| Field | Value |
|---|---|
| CLA | `0x00` |
| INS | `0xA4` |
| P1 | `0x00` child of current DF; `0x01` child of MF; `0x02` parent; `0x04` by AID; `0x08` by path from MF; `0x09` by path from current DF |
| P2 | `0x00` return FCI; `0x04` return FCP; `0x0C` no response data |
| Data | File ID (2 bytes) for P1=0x00/0x01/0x02; AID bytes for P1=0x04; path for P1=0x08/0x09 |
| Le | (absent or 0x00) |

**Response data** (when P2 ≠ 0x0C):

```
62 0B
  80 02 <size_hi> <size_lo>   -- file data size
  82 01 01                    -- file descriptor (transparent EF)
  83 02 <fid_hi> <fid_lo>     -- file identifier
```

**Status words:**

| SW | Meaning |
|---|---|
| `9000` | Success |
| `6A82` | File not found |

**Known file IDs:**

| File ID | Description |
|---|---|
| `0x3F00` | MF (Master File / root DF) |
| `0x5015` | DF.CIA |
| `0x2F00` | EF.DIR (application directory) |
| `0x2F02` | EF.C_DevAut (device certificate stub) |
| `0x2F03` | EF.TokenInfo written by sc-hsm-tool |
| `0x5031` | EF.ODF (Object Directory File) |
| `0x5032` | EF.TokenInfo (PKCS#15 token info) |
| `0xC000` | EF.AODF (Authentication Object DF) |
| `0xC100` | EF.PrKDF (always empty — SC-HSM uses LIST KEYS) |
| `0xC200` | EF.PuKDF (empty) |
| `0xC4xx` | PRKD for key slot `xx` (private key descriptor) |
| `0xCCxx` | Key container slot `xx` (presence flag for LIST KEYS) |
| `0xCExx` | EE certificate EF for key slot `xx` |

**Key file FCP (`CCxx`, P2 ≠ 0x0C):** as a SmartCard-HSM does, the FCP of a
key file carries the key's usage policy (§3.31) in a proprietary `A5` part:

```
62 L 80 02 .. 82 01 01 83 02 CC xx
     A5 L 90 04 <uses left | FFFFFFFF>  [91 n <algorithm IDs>]  [92 01 <key domain>]
```

`90 04 FFFFFFFF` = no use counter; `91` only for a key with an algorithm list.

**pico2hsm notes:** `CExx` files exist only if written via WRITE DATA (0xD7). `CCxx` files exist if the corresponding key is in the keystore. `C4xx` files exist if an EC key is in the keystore, an RSA key is in the keystore (feature `rsa`), or an EF was written via WRITE DATA. SELECT updates `state.current_file` for subsequent READ BINARY ODD operations.

---

### 3.2 READ BINARY (INS = 0xB0)

Reads bytes from the PKCS#15 virtual filesystem. In SC-HSM, P1P2 encodes a file identifier rather than a byte offset.

**Command:**

| Field | Value |
|---|---|
| CLA | `0x00` |
| INS | `0xB0` |
| P1 | High byte of file ID (bit7 must be 0) |
| P2 | Low byte of file ID |
| Le | Number of bytes to return (0x00 = 256) |

**Response data:** Raw file contents (up to Le bytes from offset 0).

**Status words:**

| SW | Meaning |
|---|---|
| `9000` | Success, data returned |
| `6A82` | File not found |
| `6A80` | Wrong P1 (bit7 set) |

---

### 3.3 READ BINARY ODD (INS = 0xB1)

SC-HSM proprietary command. Reads from a file specified by TLV reference in the command data, supporting an explicit byte offset.

**Command:**

| Field | Value |
|---|---|
| CLA | `0x00` |
| INS | `0xB1` |
| P1 | `0x00` |
| P2 | `0x00` |
| Data | TLV (see below) |
| Le | Bytes to return (`0x0000` in extended APDU = return all) |

**Command data TLV:**

```
54 02 <off_hi> <off_lo>
```
Reads from `state.current_file` (set by preceding SELECT) at the given offset.

```
54 04 <fid_hi> <fid_lo> <off_hi> <off_lo>
```
Reads from the explicitly specified file ID at the given offset.

**Response data:** File contents slice `[offset .. offset+Le]`.

**Status words:**

| SW | Meaning |
|---|---|
| `9000` | Success |
| `6A82` | File not found |
| `6A80` | Malformed TLV |

**pico2hsm notes:** OpenSC's `sc_hsm_read_binary` always sends the `54 02` form. Extended-length APDUs with Le=`0x0000` (meaning 65536) are capped to 4094 bytes.

---

### 3.4 UPDATE BINARY (INS = 0xD6)

Writes data to the currently selected EF. Used by `sc_hsm_update_ef` (pkcs15init) after CREATE FILE.

**Command:**

| Field | Value |
|---|---|
| CLA | `0x00` |
| INS | `0xD6` |
| P1P2 | Write offset (only offset 0 is effective; existing data is overwritten entirely) |
| Data | Raw bytes to write |

**Status words:**

| SW | Meaning |
|---|---|
| `9000` | Success |
| `6982` | Security status not satisfied (no PIN session) |
| `6A82` | No currently selected file |
| `6985` | EF slot table full |

---

### 3.5 WRITE DATA (INS = 0xD7)

SC-HSM extension. Stores an arbitrary TLV-framed data blob to a file addressed by P1||P2. Used by sc-hsm-tool to write device certificates and by pkcs15-init to write PRKD/CVC files.

**Command:**

| Field | Value |
|---|---|
| CLA | `0x00` |
| INS | `0xD7` |
| P1 | High byte of target file ID (or `0x00` for implicit/current file) |
| P2 | Low byte of target file ID (or `0x00` for implicit) |
| Data | TLV (see below) |

**Command data format:**

```
54 02 <off_hi> <off_lo>   -- write offset (big-endian)
53 <BER-len> <payload>    -- data tag + BER-TLV length + payload bytes
```

BER-TLV length encoding for tag `0x53`:
- `LL` (1 byte, value < `0x80`): `0x00–0x7F`
- `81 LL` (2 bytes): `0x80–0xFF`
- `82 LL LL` (3 bytes): up to `0xFFFF`

**Write target determination:**

- P1P2 ≠ `0x0000`: Write payload to file `P1||P2` at `offset`. Sets `current_file` and `write_target_file`.
- P1P2 = `0x0000`: Write payload to `current_file` at `offset`. Does not change `current_file`.

**Status words:**

| SW | Meaning |
|---|---|
| `9000` | Success |
| `6982` | No PIN or SO-PIN session active |
| `6A80` | Malformed TLV data |
| `6985` | Offset non-zero for a new file; or EF slot table full |

---

### 3.6 CREATE FILE (INS = 0xE0)

Creates a new transparent EF (elementary file). Only records the file ID as the current selected file; the actual EF entry is created lazily by a subsequent UPDATE BINARY.

**Command:**

| Field | Value |
|---|---|
| CLA | `0x00` |
| INS | `0xE0` |
| P1 | `0x00` |
| P2 | `0x00` |
| Data | `<fid_hi> <fid_lo>` (2 bytes: new file identifier) |

**Status words:**

| SW | Meaning |
|---|---|
| `9000` | Success |
| `6982` | No PIN session |
| `6A80` | Data too short |

---

### 3.7 DELETE FILE (INS = 0xE4)

Deletes a key object or EF from the in-memory store and from persistent flash.

**Command:**

| Field | Value |
|---|---|
| CLA | `0x00` |
| INS | `0xE4` |
| P1 | `0x02` = file ID in data; `0x00` = delete currently selected file |
| P2 | `0x00` |
| Data | `<fid_hi> <fid_lo>` (when P1=0x02) |

**Behavior by file range:**

- `0xC4xx`: Removes EC key, RSA key, and any associated EF from store. Erases from flash.
- Any other EF: Removes from EF store.

**Status words:**

| SW | Meaning |
|---|---|
| `9000` | Success |
| `6982` | No PIN session |
| `6A80` | Bad P1 or data too short |
| `6A82` | File not found |

---

### 3.8 LIST KEYS (INS = 0x58, P2 = 0x00)

Returns a list of occupied key container slots. No authentication required (OpenSC calls this before VERIFY when building the PKCS#15 tree).

**Command:**

| Field | Value |
|---|---|
| CLA | `0x00` |
| INS | `0x58` |
| P1 | `0x00` |
| P2 | `0x00` |
| Le | `0x00` |

**Response data:**

Sequence of 2-byte pairs. Each pair is `<prefix> <key_id>`:

```
CC <key_id>    -- occupied key container (EC or RSA key at slot key_id)
C4 <key_id>    -- PRKD EF present (from ef_files)
CE <key_id>    -- EE certificate EF present (from ef_files)
```

OpenSC's `sc_hsm_determine_free_id` uses the `0xCC` prefix to find the next free key slot ID.

**Status words:**

| SW | Meaning |
|---|---|
| `9000` | Success (empty list is valid) |

---

### 3.9 VERIFY (INS = 0x20)

Verifies a PIN reference and opens an authenticated session.

**Command:**

| Field | Value |
|---|---|
| CLA | `0x00` |
| INS | `0x20` |
| P1 | `0x00` |
| P2 | `0x81` User PIN; `0x82` session PIN; `0x88` SO-PIN |
| Data | PIN bytes (empty = query retry count) |

**PIN constraints:**

| PIN type | Min length | Max length | Default retries |
|---|---|---|---|
| User PIN (0x81) | 4 bytes | 16 bytes | 3 |
| SO-PIN (0x88) | 6 bytes | 16 bytes | 5 |
| Session PIN (0x82) | 8 bytes (exact) | 8 bytes | N/A (one-time) |

**Query retry count:** Send with empty data (no Lc). Returns `SW = 0x63CX` where X = remaining retries. Returns `SW = 0x6983` if blocked.

**Session PIN:** Must be exactly 8 bytes. The stored session PIN (from SESSION PIN command) is cleared immediately after this VERIFY — whether it succeeds or fails — preventing replay.

**Unknown P2:** Returns `SW = 0x6A88` (referenced data not found) so OpenSC maps this to `SC_ERROR_DATA_OBJECT_NOT_FOUND` rather than a fatal error.

**Status words:**

| SW | Meaning |
|---|---|
| `9000` | PIN correct, session opened |
| `63CX` | PIN wrong, X retries remaining |
| `6983` | PIN blocked |
| `6984` | PIN not set (no hash stored) |
| `6985` | Session PIN: no session PIN stored |
| `6700` | Wrong length |
| `6A80` | Wrong P1 |

---

### 3.10 CHANGE REFERENCE DATA (INS = 0x24)

Changes the User PIN or SO-PIN. Does not require a prior VERIFY; the old PIN must be provided in the command data.

**Command:**

| Field | Value |
|---|---|
| CLA | `0x00` |
| INS | `0x24` |
| P1 | `0x00` concatenated old||new; `0x01` TLV-encoded |
| P2 | `0x81` User PIN; `0x88` SO-PIN |
| Data | (see P1) |

**Command data formats:**

P1=0x01 (TLV):
```
80 <len> <old_pin>   -- old PIN
81 <len> <new_pin>   -- new PIN
```

P1=0x00: Raw bytes split at midpoint (`old = data[:len/2]`, `new = data[len/2:]`).

**Status words:**

| SW | Meaning |
|---|---|
| `9000` | Success (session closed; re-VERIFY required) |
| `63CX` | Old PIN wrong, X retries remaining |
| `6983` | PIN blocked |
| `6984` | PIN not initialized |
| `6700` | New PIN wrong length |
| `6A80` | Malformed data |

---

### 3.11 RESET RETRY COUNTER (INS = 0x2C)

Resets the User PIN retry counter. Requires SO-PIN authenticated session (`state.so_pin_verified = true`).

**Command:**

| Field | Value |
|---|---|
| CLA | `0x00` |
| INS | `0x2C` |
| P1 | `0x00` reset counter only; `0x02` reset + set new PIN |
| P2 | `0x81` (User PIN reference) |
| Data | New PIN bytes (when P1=0x02) |

**Status words:**

| SW | Meaning |
|---|---|
| `9000` | Success |
| `6982` | SO-PIN not verified |
| `6700` | New PIN wrong length |
| `6A80` | Unknown P1 |

---

### 3.12 SESSION PIN (INS = 0x26)

Generates a one-time 8-byte session PIN and returns it to the host. Requires an active PIN or SO-PIN session. The caller may subsequently use this PIN via `VERIFY P2=0x82` to grant a single authenticated operation.

**Command:**

| Field | Value |
|---|---|
| CLA | `0x00` or `0x80` |
| INS | `0x26` |
| P1 | `0x00` |
| P2 | `0x00` |
| Le | `0x00` (expect 8 bytes back) |

**Response data:** 8 random bytes (on hardware, from TRNG; on host tests, from counter-hash PRNG).

**Status words:**

| SW | Meaning |
|---|---|
| `9000` | Success |
| `6982` | No PIN or SO-PIN session |

---

### 3.13 PUK AUTH (INS = 0x28)

Authenticates with the PUK (PIN Unblocking Key) to unblock the User PIN after lockout. On success, sets `pin_verified = true` and resets `pin_retry_count = 3`.

**Command:**

| Field | Value |
|---|---|
| CLA | `0x00` |
| INS | `0x28` |
| P1 | `0x00` |
| P2 | `0x00` |
| Data | PUK bytes (8–16 bytes) |

**Status words:**

| SW | Meaning |
|---|---|
| `9000` | PUK correct, PIN unblocked |
| `63CX` | PUK wrong, X retries remaining (initial = 10) |
| `6983` | PUK blocked |
| `6985` | No PUK configured |
| `6700` | Wrong length |

---

### 3.14 INITIALIZE (INS = 0x50)

Formats the HSM: wipes SC-HSM-owned keys from flash, clears in-memory state, sets the SO-PIN (init code) and optionally the User PIN. On re-initialization, authenticates via the init code in the command itself — no prior VERIFY is needed.

**Command:**

| Field | Value |
|---|---|
| CLA | `0x00` |
| INS | `0x50` |
| P1 | `0x00` |
| P2 | `0x00` |
| Data | TLV (see below) |

**Command data TLV tags:**

| Tag | Mandatory | Length | Description |
|---|---|---|---|
| `0x80` | No | 2 bytes LE | Options bitmask |
| `0x81` | No | 6–16 bytes | User PIN |
| `0x82` | Yes | 8 bytes | Init code (SO-PIN) — must always be exactly 8 bytes |
| `0x91` | No | 1 byte | User PIN retry counter (default: 3) |
| `0x92` | No | 1 byte | DKEK share count (0 = no DKEK) |
| `0x93` | No | 8–16 bytes | PUK |

**SO-PIN check:** whenever an SO-PIN is set — re-initialization, or a store emptied by FORMAT STORE, which carries the SO-PIN forward — the init code in tag `0x82` is compared (PBKDF2) against it, and each comparison spends an SO-PIN retry first. Mismatch returns `SW = 0x6982`. A device that never had an SO-PIN initializes with any init code.

**Where the SO-PIN lives (2.0):** in the Storage V2 binding block on internal flash, not in the SC-HSM PIN record, so it still verifies while the keystore is refused (see §3.29, "Storage V2 store commands"). INITIALIZE writes the new SO-PIN in the same binding write as SC-HSM's new key epoch.

**Effects:**
- Clears all in-memory keys (EC, RSA, symmetric, EF files)
- Wipes SC-HSM-owned keys and domain records from flash, and sets the new SO-PIN with them
- Pre-populates a sentinel entry at key slot 0 (reserved for device auth key)
- Resets all auth state, MSE state, and challenge

**Status words:**

| SW | Meaning |
|---|---|
| `9000` | Success |
| `6982` | Re-init: provided init code does not match stored hash |
| `6700` | Init code not 8 bytes; or User PIN / PUK wrong length |
| `6A80` | Missing mandatory tag 0x82; P1P2 not 0x00/0x00 |

---

### 3.15 MANAGE SECURITY ENVIRONMENT (INS = 0x22)

Configures the security environment for a subsequent cryptographic operation.

**Command:**

| Field | Value |
|---|---|
| CLA | `0x00` |
| INS | `0x22` |
| P1 | `0x41` SET; `0xF3` RESTORE |
| P2 | `0xA4` Computation (sign); `0xB8` Decipherment (ECDH/decrypt); `0xB4` Confidentiality (SM); `0x03` (with P1=0xF3 to restore SE#3) |
| Data | TLV (see below) |

**Command data TLV tags:**

| Tag | Description |
|---|---|
| `0x80` | Algorithm identifier (1 byte; see Algorithm Identifier table) |
| `0x84` | Key reference (1 byte key ID, `0x01–0xFE`) |

**Operations:**

| P1 | P2 | Operation |
|---|---|---|
| `0x41` | `0xA4` | SET for Computation — select key/algo for signing |
| `0x41` | `0xB8` | SET for Decipherment — select key/algo for ECDH or RSA decrypt |
| `0x41` | `0xB4` | SET for Confidentiality — select key/algo for symmetric cipher |
| `0xF3` | `0x03` | RESTORE SE#3 — reset to default (clears `current_key_id`, `current_algo`, `current_se_op`) |

At least one of tag `0x80` or `0x84` must be present. Either may be omitted if only one attribute needs updating.

**Status words:**

| SW | Meaning |
|---|---|
| `9000` | Success |
| `6A80` | Neither tag present; unknown P1/P2 |

---

### 3.16 GET CHALLENGE (INS = 0x84)

Returns random bytes from the hardware TRNG. The first 8 bytes are also stored in `state.challenge`.

**Command:**

| Field | Value |
|---|---|
| CLA | `0x00` |
| INS | `0x84` |
| P1 | `0x00` |
| P2 | `0x00` |
| Le | Number of bytes requested (0 = 256; max 256) |

**Response data:** Le random bytes.

**Status words:**

| SW | Meaning |
|---|---|
| `9000` | Success |

---

### 3.17 EXTERNAL AUTHENTICATE (INS = 0x82) — removed

Removed in October 2026. The pico2hsm variant verified
`HMAC-SHA256(so_pin_hash, challenge)`, i.e. it was keyed by the *stored*
SO-PIN hash: anyone able to read the PIN record became SO without knowing
the SO-PIN. No client used it. The command now returns `6D00`.

### 3.18 GENERAL AUTHENTICATE (INS = 0x86)

Single-step challenge-sign using a Dynamic Authentication Template (DAT). The key and algorithm must have been pre-selected by MSE SET. The challenge is hashed with SHA-256 before ECDSA signing.

**Command:**

| Field | Value |
|---|---|
| CLA | `0x00` |
| INS | `0x86` |
| P1 | `0x00` |
| P2 | `0x00` |
| Data | DAT TLV (see below) |

**Command data:**

```
7C <len>
  81 <challenge_len> <challenge_bytes>   -- host-provided challenge
```

**Response data:**

```
7C <len>
  82 <sig_len> <ecdsa_signature_bytes>   -- DER-encoded ECDSA signature
```

Requires `pin_verified` or `so_pin_verified`. The MSE-selected key must be an EC key (only EC keys are supported; RSA is not supported by this command).

**Status words:**

| SW | Meaning |
|---|---|
| `9000` | Success |
| `6982` | No PIN session |
| `6A80` | No 0x7C outer tag; or no 0x81 inner tag |
| `6985` | No MSE key selected |
| `6A82` | Key not found |

---

### 3.19 GENERATE KEY PAIR (INS = 0x46)

Generates an asymmetric key pair (EC or RSA) on-device. Requires User PIN. Returns a Card Verifiable Certificate (CVC) containing the public key and full EC domain parameters.

**Command:**

| Field | Value |
|---|---|
| CLA | `0x00` |
| INS | `0x46` |
| P1 | Key slot ID (`0x01–0xFE`, or `0x00` for auto-assign) |
| P2 | `0x00` |
| Data | GAK parameters TLV (extended APDU) |

**Command data TLV:**

| Tag | Description |
|---|---|
| `5F 29` (2-byte) | Certificate Profile Identifier / algorithm byte (0x00 = infer from params) |
| `42` | Key reference label (optional) |
| `7F 49` | Public key template; contains curve domain params or RSA modulus-size |
| `5F 20` | CA reference (optional) |
| `D4` | pico2hsm key flags (bit 3 = NO_EXPORT) |
| `90` | Key use counter, 4 bytes BE (CardContact; §3.31) |
| `91` | Algorithm list: allowed algorithm IDs (CardContact; §3.31) |
| `92` | Key domain, 1 byte; only `00` exists (CardContact; §3.31) |

The command data is parsed as BER-TLV (1- and 2-byte tags, lengths up to
`82 xx xx`); a structure that does not parse is refused with `6A80` rather
than stored without its attributes (OpenSC's P-521 request has a 2-byte
`7F49` length before `90`/`91`).

**Algorithm inference from `7F49` content:**

| `7F49` content | Algorithm byte | Key type |
|---|---|---|
| Tag `0x85` (order) length = 32 bytes (P-256 prime) | `0x13` | ECDSA P-256 |
| Tag `0x85` length = 32 bytes (K-256 prime) | `0x19` | ECDSA K-256 |
| Tag `0x85` length = 48 bytes | `0x15` | ECDSA P-384 |
| Tag `0x85` length = 66 bytes | `0x17` | ECDSA P-521 |
| Tag `0x02` value = `0x0800` (2048 bits) | `0x05` | RSA-2048 |
| Tag `0x02` value = `0x0C00` (3072 bits) | `0x06` | RSA-3072 |
| Tag `0x02` value = `0x1000` (4096 bits) | `0x07` | RSA-4096 |

**Response data:** A CVC in BSI TR-03110 "authenticated request" format:

```
67 <len>              -- authenticated request
  7F 21 <len>         -- CVC
    7F 4E <len>       -- Certificate Body
      5F 29 01 00     -- Certificate Profile Identifier = 0
      7F 49 <len>     -- Public Key
        06 <oid_len> <curve_OID>
        81 <len> <prime_p>
        82 <len> <coeff_a>
        83 <len> <coeff_b>
        84 <len> <base_G>        -- uncompressed 04||Gx||Gy
        85 <len> <order_n>
        86 <len> <public_point>  -- uncompressed 04||Qx||Qy
        87 01 01                 -- cofactor h = 1
      5F 20 09 <CHR>             -- "UTDV00001"
    5F 37 <sig_len> <zeros>      -- dummy signature
  42 <len> <zeros>               -- outer CA reference (dummy)
  5F 37 <sig_len> <zeros>        -- outer signature (dummy)
```

**RSA response:** RSA keys return `7F49 (82 <len> <modulus>  82 03 01 00 01)` — modulus + exponent in the public key block.

**Key is stored** in the in-memory EC or RSA keystore and persisted to flash.

**RSA keys and the key pool (`rsa` firmware).**  For RSA-2048/3072/4096
the card takes the newest pooled key of the size that is younger than the
pool's maximum age (EXTRAS `0x50`/`0x51` above), marks its pool slot taken
on flash first, and stores it under the requested reference exactly like
a freshly generated key (same object, policy, CVC; the Lamport counter and
object IDs as for any GENERATE).  With no such key — pool empty, off, or
RSA-1024 — it generates the key during the command (time extensions keep
the host waiting).  `6581` also when the slot cannot be marked taken.

**Status words:**

| SW | Meaning |
|---|---|
| `9000` | Success |
| `6982` | PIN not verified |
| `6A80` | Missing algorithm byte or unknown algorithm; malformed TLV or key attribute |
| `6A88` | Key domain (`92`) other than 0 |
| `6985` | Keystore full |
| `6581` | The key could not be stored |

---

### 3.20 GENERATE SYMMETRIC KEY (INS = 0x48)

Generates an AES key from the on-chip TRNG and stores it in the in-memory symmetric keystore and flash.

**Command:**

| Field | Value |
|---|---|
| CLA | `0x00` |
| INS | `0x48` |
| P1 | Key slot ID (`0x01–0xFE`) |
| P2 | SmartCard-HSM form: `0xB0` / `0xB1` / `0xB2` = AES-128 / 192 / 256; or `0x00` (pico2hsm form) |
| Data | P2 = B0–B2: optional key attributes `90` / `91` / `92` (§3.31). P2 = 00: 1 byte size tag (`0x82`=AES-128, `0x83`=AES-192, `0x84`=AES-256), then the same optional attributes |

**Status words:**

| SW | Meaning |
|---|---|
| `9000` | Success |
| `6982` | PIN not verified |
| `6A80` | Invalid key ID, unknown size tag, malformed attribute |
| `6A88` | Key domain other than 0 |
| `6581` | Flash write failed (was `6985`) |

---

### 3.21 COMPUTE DIGITAL SIGNATURE (INS = 0x68)

Computes an ECDSA or RSA digital signature. The key reference and algorithm are encoded directly in P1/P2 (no prior MSE SET required for this command).

**Command:**

| Field | Value |
|---|---|
| CLA | `0x00` |
| INS | `0x68` |
| P1 | Key slot ID (1 byte) |
| P2 | Algorithm byte (see table below) |
| Data | Message digest or raw message (see algorithm) |

**Algorithm bytes (P2):**

| P2 | Name | Input | Notes |
|---|---|---|---|
| `0x13` | ECDSA P-256 (pre-hashed) | 32-byte SHA-256 digest | |
| `0x15` | ECDSA P-384 (pre-hashed) | 48-byte SHA-384 digest | |
| `0x17` | ECDSA P-521 (pre-hashed) | 64-byte SHA-512 digest | |
| `0x19` | ECDSA K-256 (pre-hashed) | 32-byte SHA-256 digest | |
| `0x20` | RSA RAW | 256- or 512-byte PKCS#1-padded block | Host pre-pads; card does raw `m^d mod n` |
| `0x31` | RSA PKCS#1v1.5 + SHA-1 | Raw message | Card hashes; `rsa` feature required |
| `0x32` | RSA PKCS#1v1.5 + SHA-224 | Raw message | Card hashes |
| `0x33` | RSA PKCS#1v1.5 + SHA-256 | Raw message | Card hashes |
| `0x34` | RSA PKCS#1v1.5 + SHA-384 | Raw message | Card hashes |
| `0x35` | RSA PKCS#1v1.5 + SHA-512 | Raw message | Card hashes |
| `0x40` | RSA-PSS, external hash | 32-byte SHA-256 digest only | Other digest lengths `6A80` |

Since 2026-10 the RSA codes are the CardContact ones (OpenSC
`card-sc-hsm.h`). Before, `31`/`32`/`33` signed a host digest as
SHA-256/384/512 and `34` was PSS; OpenSC never sent them.
| `0x70` | ECDSA EC-RAW (pre-hashed) | Any digest | Passes directly to sign primitive |
| `0x71` | ECDSA + SHA-1 | Raw message | Card computes SHA-1 |
| `0x72` | ECDSA + SHA-224 | Raw message | Card computes SHA-224 |
| `0x73` | ECDSA + SHA-256 | Raw message | Card computes SHA-256 |
| `0x74` | ECDSA + SHA-384 | Raw message | Card computes SHA-384 |
| `0x75` | ECDSA + SHA-512 | Raw message | Card computes SHA-512 |

**Response data:** ECDSA: DER-encoded signature (`30 <len> 02 <rlen> <r> 02 <slen> <s>`). RSA: raw modulus-width signature bytes.

**Status words:**

| SW | Meaning |
|---|---|
| `9000` | Success |
| `6982` | PIN not verified |
| `6985` | Empty data field; algorithm not in the key's list (`91`) |
| `6A84` | Key use counter (`90`) exhausted |
| `6A82` | Key not found |
| `6D00` | Unknown algorithm byte |
| `6581` | The spent use could not be written |

The key's usage policy (§3.31) is checked against P2 — the per-curve
codes `13`/`15`/`17`/`19` as `70` — and one use is written to flash before
the signature is computed.

---

### 3.22 DECIPHER / DERIVE ASYMMETRIC KEY (INS = 0x62)

INS `0x62` is shared between two operations, disambiguated by P1 **and** P2
(since v1.0.1):

- P1 = `0x01` and P2 = `0x00`: **DERIVE ASYMMETRIC KEY** — KDF-based derivation using a stored key
- anything else: **DECIPHER** — ECDH key agreement or RSA decrypt (P1 = key slot, P2 = non-zero algorithm code)

P1 alone is not enough: OpenSC assigns key reference `0x01` to the first
generated key, so a P-256 ECDH DECIPHER on slot 1 (`80 62 01 80`) must not
reach the derive handler.

#### 3.22a DECIPHER

**Command:**

| Field | Value |
|---|---|
| CLA | `0x00` |
| INS | `0x62` |
| P1 | Key slot ID |
| P2 | Algorithm byte (see table) |
| Data | Peer public key point or RSA ciphertext |

**Algorithm bytes (P2):**

| P2 | Operation | Input | Response |
|---|---|---|---|
| `0x21` | RSA decrypt (raw) | RSA ciphertext (`c`) | Raw `c^d mod n`; host strips padding |
| `0x22` | RSA decrypt, card removes PKCS#1 v1.5 padding | — | **Refused (`6D00`)** before the key is touched |
| `0x23` | ECDH P-256 | `04 \|\| Qx \|\| Qy` (65 bytes) | Raw X-coordinate (32 bytes) |
| `0x25` | ECDH P-384 | `04 \|\| Qx \|\| Qy` (97 bytes) | Raw X-coordinate (48 bytes) |
| `0x27` | ECDH P-521 | `04 \|\| Qx \|\| Qy` (133 bytes) | Raw X-coordinate (66 bytes) |
| `0x29` | ECDH K-256 | `04 \|\| Qx \|\| Qy` (65 bytes) | Raw X-coordinate (32 bytes) |
| `0x80` | ECDH generic (ALGO_EC_DH) | `04 \|\| Qx \|\| Qy` | `04 \|\| X-coord` (OpenSC strips the 0x04 prefix) |

`0x22` used to run the raw operation of `0x21`; card-side unpadding would
answer bad padding differently from good (a Bleichenbacher oracle), so
`0x22` and `0x23` (OAEP, on an RSA key) are not supported. OpenSC sends
`0x21` only. For the usage policy every ECDH code counts as `0x80`
(`ALGO_EC_DH`); `0x23` is CardContact's RSA-OAEP ID and is never looked up
as such for an EC key.

**Response notes:** For `P2 = 0x80`, pico2hsm prepends `0x04` to the X-coordinate. OpenSC's `sc_hsm_decipher` strips this prefix to recover the field-size X bytes. For explicit ECDH codes (`0x23/0x25/0x27/0x29`), the raw X-coordinate is returned without the prefix.

**Note — ECDH1-COFACTOR-DERIVE vs ECDH1-DERIVE:** For all supported curves (P-256/P-384/P-521/K-256) the cofactor h=1, so `ECDH1-COFACTOR-DERIVE` (0x1051) and `ECDH1-DERIVE` (0x1050) are mathematically identical. Tests use `ECDH1-DERIVE` uniformly because the `OpenSC 0.25 sc-hsm driver + pico2hsm firmware` combination rejects `ECDH1-COFACTOR-DERIVE` for P-256 keys: the driver translates the mechanism into a `80 62 01 80 …` DECIPHER APDU that the device answers with `SW=6985` ("conditions of use not satisfied"), which OpenSC surfaces as `CKR_GENERAL_ERROR`. Plain `ECDH1-DERIVE` works for all four curves.

**Status words:**

| SW | Meaning |
|---|---|
| `9000` | Success |
| `6982` | PIN not verified |
| `6985` | Empty data / type mismatch |
| `6A82` | Key not found |
| `6D00` | Unsupported algorithm |

#### 3.22b DERIVE ASYMMETRIC KEY (P1 = 0x01)

Derives a new asymmetric key pair from a stored master key (EC or symmetric) using X9.63 or HKDF. Key selected by MSE SET (`state.current_key_id`).

**Command:**

| Field | Value |
|---|---|
| CLA | `0x00` |
| INS | `0x62` |
| P1 | `0x01` |
| P2 | `0x00` |
| Data | Derivation parameters (key-type specific) |

**Status words:**

| SW | Meaning |
|---|---|
| `9000` | Success |
| `6982` | PIN not verified |
| `6985` | No MSE key selected |
| `6A82` | Source key not found |
| `6A80` | Empty data |

---

### 3.23 PERFORM SECURITY OPERATION (INS = 0x2A)

Multipurpose command for cryptographic operations using the key/algorithm configured by the preceding MSE SET. This is the ISO 7816-8 standard path; INS=0x68 and INS=0x62 are SC-HSM shortcuts that encode key ID in P1.

**Command:**

| Field | Value |
|---|---|
| CLA | `0x00` |
| INS | `0x2A` |
| P1 | Operation selector (see table) |
| P2 | Operation selector (see table) |
| Data | Input data |

**Operations:**

| P1 | P2 | Operation |
|---|---|---|
| `0x9E` | `0x9A` | Compute Digital Signature (delegates to sign path) |
| `0x80` | `0x86` | Decipher (delegates to ECDH / RSA path) |
| `0x8E` | `0x80` | Compute Cryptographic Checksum (AES-CMAC or HMAC-SHA256) |
| `0x86` | `0x80` | Verify Cryptographic Checksum |

For `P1=0x9E, P2=0x9A` and `P1=0x80, P2=0x86`: key ID and algorithm come from `state.current_key_id` and `state.current_algo` (set by MSE SET). Algorithm bytes and input formats are identical to INS=0x68 (SIGN) and INS=0x62 (DECIPHER).

**Status words:**

| SW | Meaning |
|---|---|
| `9000` | Success |
| `6982` | PIN not verified |
| `6985` | MSE key or algo not set |
| `6A82` | Key not found |
| `6A80` | Unknown P1/P2 combination |

---

### 3.24 SYMMETRIC CIPHER (INS = 0x78)

Performs symmetric encryption or decryption. Key must be selected by a preceding MSE SET (`state.current_key_id`).

**Command:**

| Field | Value |
|---|---|
| CLA | `0x00` |
| INS | `0x78` |
| P1 | `0x01` encrypt; `0x02` decrypt |
| P2 | Mode (see table) |
| Data | Mode-specific input (see below) |

**Modes (P2):**

| P2 | Mode | Input format | Response |
|---|---|---|---|
| `0x02` | AES-CBC | `[IV: 16 bytes][whole blocks]` | Same number of blocks; **no padding** either way (host pads) |
| `0x03` | AES-CTR | `[nonce: 16 bytes][data]` | XOR-keystream applied (encrypt=decrypt) |
| `0x05` | AES-GCM | `[nonce: 12 bytes][aad_len: 2 BE][aad][payload]` | Encrypt: `ct \|\| tag(16)`; Decrypt: plaintext |
| `0x06` | AES-CMAC | `[message]` | 16-byte CMAC tag (P1 ignored) |

**Constraints:**
- AES-CTR: AES-256 only (32-byte key). Payload max 4080 bytes.
- AES-GCM decrypt: payload must include the 16-byte authentication tag appended to ciphertext.
- AES-CBC: data must be one or more whole blocks (`6700` otherwise). Since
  2026-10 there is no PKCS#7 padding: encrypt added and decrypt stripped it,
  and decrypt answered bad padding with `6985` — a CBC padding oracle.
- Usage policy (§3.31): CBC encrypt = `0x10`, CBC decrypt = `0x11`, CMAC =
  `0x18`; CTR and GCM have no CardContact ID and are refused for a key with
  an algorithm list.

**Status words:**

| SW | Meaning |
|---|---|
| `9000` | Success |
| `6982` | PIN not verified |
| `6985` | No MSE key selected |
| `6A82` | Key not found |
| `6700` | Data too short for mode |
| `6D00` | Unknown mode |

---

### 3.25 IMPORT KEY / UNWRAP KEY (INS = 0x74)

Imports a DKEK-wrapped key into slot P1 (P2 = `0x93`). User PIN and a ready
DKEK are required. The blob is either inline or written beforehand to EF
`2F10` (the `sc-hsm-tool --unwrap-key` path: WRITE `2F10`, then a case-1
`80 74 <ref> 93`). Slots `0x00` and `0xFC`–`0xFF` are refused.

**Accepted formats:**

- the SmartCard-HSM (CardContact) key blob, §3.32 — what WRAP writes, what
  `sc-hsm-tool --wrap-key` stores in a `.wky` file, and what a real
  SmartCard-HSM or pico-hsm exports;
- **deprecated, this release only:** the pico2hsm formats of the previous
  release (byte 8 = `0x02` or `0x03`, never a CardContact key type):

  ```
  KCV'(8) || 0x02|0x03 || IV(16) || AES-256-CBC(kenc', key [|| A5 L {..} || L+2] || algo || flags || PKCS#7) || MAC(16)
  KCV'  = AES-256-CMAC(DKEK, 0^16)[..8]
  kenc' = HMAC-SHA256(DKEK, "pico2hsm-wrap-v2-enc")
  kmac' = HMAC-SHA256(DKEK, "pico2hsm-wrap-v2-mac")
  MAC   = HMAC-SHA256(kmac', everything before the MAC)[..16]
  ```
  Version 3 carries the key's usage policy (§3.31), use counter included.
  Version-1 blobs (no version byte, no MAC) are refused.

Either way the blob is authenticated (KCV, then CMAC / HMAC, compared in
constant time) before anything in it is decrypted or parsed, so every
forged, altered or foreign blob fails the same way (`6A80`, which
`sc-hsm-tool` reports as "Wrapped key does not match DKEK"). The imported
key keeps the blob's algorithm list and key flags, joins key domain 0, and
gets its public key (EC: recomputed as d·G and checked against the blob's
Q; RSA: n and e).

**Status words:** `9000` imported; `6A80` bad/forged blob, wrong DKEK, or
inconsistent content; `6A81` authentic blob of a key this firmware cannot
hold (brainpool, Curve25519, AES-512, RSA in a build without `rsa`, RSA
outside 1024–4096 bits); `6A86` reserved slot; `6982` PIN not verified;
`6985` no DKEK; `6581` the key could not be stored.

---

### 3.26 EXPORT KEY / WRAP KEY (INS = 0x72, alias 0x34)

Exports the key in slot P1 (P2 = `0x92`) as a CardContact key blob
(§3.32). User PIN and a ready DKEK are required; keys generated or imported
with the NO_EXPORT flag (bit 3 of tag `D4`) are refused with `6985`, as are
reserved slots `0xFC`–`0xFF` (`6A86`).

Usage policy (§3.31): a key with an algorithm list must list `0x92`
(`ALGO_WRAP`), else `6985`. A key with a **use counter is not exportable**
(`6985`): every unwrap of a wrapped copy (into other slots, or back over
the original after use) would start again from the exported count, and the
CardContact format has no field for it anyway. Wrapping does not spend a
use.

Keys without a CardContact encoding — Ed25519, X25519, brainpool, BIP32
masters — are refused with `6A81`.

OpenSC reads the WRAP response into a 1500-byte buffer
(`card-sc-hsm.c` `sc_hsm_wrap_key`), so `sc-hsm-tool --wrap-key` handles
RSA up to 3072 bits (1421-byte blob); an RSA-4096 blob (1869 bytes) needs a
client with a larger buffer (e.g. `pico2hsm-tool`).

---

### 3.27 KEY DOMAIN (INS = 0x52)

The device has one key domain (0) and one DKEK.

**P1 = `0x00` — status and DKEK share import (CardContact, no PIN):**

| Data | Operation |
|---|---|
| none | status (what `sc-hsm-tool` without a command asks for each domain) |
| 32 bytes | import one DKEK share (`sc-hsm-tool --import-dkek-share` decrypts the share file on the host and sends the raw share) |

Response, as OpenSC `sc_hsm_manage_key_domain` reads it:
`[shares in the DKEK (1), shares still missing (1), KCV (8)]`, KCV =
SHA-256(DKEK)[0..8] (§3.32), zeros while shares are missing.
`sc-hsm-tool` prints it as "Key Check Value", so devices loaded with the
same shares — and a real SmartCard-HSM — show the same value.

Shares combine by XOR: DKEK = share₁ ⊕ … ⊕ shareₙ (pico-hsm
`import_dkek_share`; the SmartCard-HSM key-domain scheme).

`P2 ≠ 0` → `6A86` (ends `sc-hsm-tool`'s domain loop); no DKEK configured
(INITIALIZE without `--dkek-shares`) → `6A88` (`sc-hsm-tool` prints
"Empty"); a share when the DKEK is complete → `6A80`.

**P1 = `0x01`–`0x05` — pico2hsm domain management (SO-PIN):** create
(`01`: restart share collection), delete (`02`), import an encrypted share
blob (`03`), status `[required, imported, ready]` (`04`), assign (`05`, not
supported). Create and delete are refused while a DKEK is set. These P1
values differ from CardContact's (`01` create DKEK domain with the share
count as data, `02` create XKEK domain, `03` delete domain, `04` delete
KEK); `sc-hsm-tool --create-dkek-key-domain` / `--delete-key-domain` are not
supported.

---

### 3.28 BIP32/SLIP-0010 HD KEY DERIVE (INS = 0x60)

Derives a child key from a stored BIP32 master key. Key must be an EC key with exactly 64 bytes of private key material (private scalar || chain code). Derivation path is a sequence of 4-byte big-endian index values (bit31 set = hardened).

**Command:**

| Field | Value |
|---|---|
| CLA | `0x00` |
| INS | `0x60` |
| P1 | Source master key slot ID |
| P2 | Flags (bit0 = store derived key; bit1 = return public key) |
| Data | Derivation path: N × 4-byte index values (max 16 levels) |

**Status words:**

| SW | Meaning |
|---|---|
| `9000` | Success |
| `6982` | PIN not verified |
| `6A82` | Source key not found |
| `6A80` | Path length not multiple of 4; master key not 64 bytes |
| `6985` | Key derivation failed |

---

### 3.29 EXTRAS (INS = 0x54)

Additional cryptographic primitive operations dispatched by P1. Requires User PIN. All operations use raw input data (no TLV wrapping at the APDU level).

**Command:**

| Field | Value |
|---|---|
| CLA | `0x00` |
| INS | `0x54` |
| P1 | Sub-command |
| P2 | `0x00` |
| Data | Sub-command specific (see below) |

**Sub-commands:**

#### P1=0x01: HKDF-Extract

Input: `[salt_len: 1][salt: salt_len bytes][IKM: remaining bytes]`  
Response: 32-byte PRK.

#### P1=0x02: HKDF-Expand

Input: `[PRK: 32 bytes][output_length: 1][info: remaining bytes]`  
Response: `output_length` bytes of OKM (max 255).

#### P1=0x03: PBKDF2-SHA256

Input:
```
[pw_len: 1][password: pw_len]
[salt_len: 1][salt: salt_len]
[iterations: 4 BE][dklen: 1]
```
Response: `dklen` bytes (max 64).

#### P1=0x04: X9.63-KDF

Input: `[Z_len: 1][Z: Z_len][key_len: 1][SharedInfo: remaining]`  
Response: `key_len` derived bytes.

#### P1=0x05: AES-CMAC

Input: `[key: 16/24/32 bytes][message: remaining]`  
Response: 16-byte CMAC tag.

#### P1=0x06: HMAC-SHA256

Input: `[key_len: 1][key: key_len][message: remaining]`  
Response: 32-byte HMAC-SHA256 tag.

**Status words:**

| SW | Meaning |
|---|---|
| `9000` | Success |
| `6982` | PIN not verified |
| `6700` | Wrong length / insufficient data |
| `6985` | Computation failed |
| `6A80` | Unknown P1 |

#### Domain and sync sub-commands (pico2hsm vendor, cluster plan V3)

`docs/CLUSTER_PLAN_V3.md` describes the design; this is the wire format.
CLA `0x80`.  Responses longer than the short-APDU Le are chained with GET
RESPONSE (`61xx`); no response exceeds 4084 bytes.

| P1 | Name | Auth | Data | Response |
|---|---|---|---|---|
| `0x30` | GET_DEVICE_PUBLIC_KEY | none | — | 65-byte P-256 point (the member key) |
| `0x34` | GET_GENERATION | none | — | low 32 bits of the Lamport counter, BE |
| `0x35`–`0x38` | V2 DKEK exchange | SO-PIN | see §Security notes | consumes the pinned peer |
| `0x39` | GET_KEY_MANIFEST | user PIN | absent/`01` (v1) or `02` (v2); P2 = first key ref | entries, see below |
| `0x3A` | GET_STATE_HASH | none | — | `lamport(8) ‖ root(32) ‖ sig(64)` |
| `0x3C` | GET_GENERATION_V2 | none | — | Lamport counter, u64 BE |
| `0x3D` | ENROLL_PEER_PUBKEY | SO-PIN | 65-byte point | pins the peer for the next exchange |
| `0x40` | DOMAIN_STATUS | none | — | 117 bytes, see below |
| `0x45` | ISSUE_MEMBER_CERT | SO-PIN | `member_pub(65) [‖ flags(1)]` | 187-byte certificate |
| `0x46` | REVOKE_MEMBER | SO-PIN | `member_id(16)` | 121-byte revocation |
| `0x47` | GET_MEMBERS | none | P2 = first slot; absent/`01` (v1) or `02` (v2) | page, see below |
| `0x49` | IMPORT_MEMBER_CERT | none | 187-byte certificate | `01` added / `00` replaced |
| `0x4A` | IMPORT_REVOCATION | none | `revocation(121) [‖ certificate(187)]` | `01` added / `00` marked revoked |
| `0x50` | RSA_POOL_STATUS | none | — | 43 bytes, see "RSA key pool" |
| `0x51` | RSA_POOL_CONFIG | SO-PIN | 8 bytes, see "RSA key pool" | the new status |
| `0x4E` | FORMAT_STORE | SO-PIN (see below) | `FORMAT-STORE-V2` | — |
| `0x4F` | OPEN_DEGRADED | SO-PIN | `OPEN-DEGRADED` | — |
| `0x52` | STORE_STATUS | none | — | 26 bytes, see "Storage V2 store commands" |
| `0x53` | ACCEPT_STORE | SO-PIN | `ACCEPT-STORE-V2` ‖ lost(8 BE) | — |

**Lamport counter (`0x34`, `0x3C`, `0x3A`).** Persisted on internal flash
(retry-counter log, record kind `'L'`) and never decreasing; it replaces
the RAM-only generation counter, which restarted at 0 on every boot.  It
is advanced *before* every change it numbers — GENERATE KEY PAIR (`46`),
GENERATE KEY (`48`), UNWRAP (`74`), DELETE FILE (`E4`), WRITE DATA (`D7`),
UPDATE BINARY (`D6`) in a session with the user PIN or SO-PIN verified,
and the member self certificate.  If the counter cannot be written the
command is refused with `6581` and nothing changes.  INITIALIZE does not
reset it.  A failed command may leave a gap.

**GET_KEY_MANIFEST (`0x39`).** Keys in ascending key-reference order,
from P2 (default 1), as many as fit in one response; ask again with
P2 = last listed reference + 1 until a page comes back empty.  There is no
fixed cap (it used to stop at 32 keys).

```
v1 entry (44 bytes): key_ref(1) algo(1) key_flags(1) 00(1) timestamp_ms(8 BE)
                     SHA-256(public key)(32)
v2 entry (64 bytes): key_ref(1) algo(1) key_flags(1) id_len(1) timestamp_ms(8 BE)
                     SHA-256(public key)(32) object_id(20, zero-padded)
```

The object ID (v2) is the key's global ID: for EC and RSA keys OpenSC's
intrinsic CKA_ID, SHA-1 of the X coordinate / of the modulus (`id_len`
20); for others a random 16-byte ID kept in the key's sidecar, assigned on
this call if the key predates it (`6581` if that write fails).

**ENROLL_PEER_PUBKEY (`0x3D`).** Pins the peer's key for **one** V2 DKEK
exchange: SOURCE spends the pin before it returns the encrypted DKEK
(`0x37`), TARGET before it installs the DKEK (`0x38`); a pin that cannot be
erased stops the exchange with `6581`.  Failed steps keep the pin.
Pinning again replaces it.  A peer enrolled by earlier firmware in key
reference `0xFC` becomes the pin at the first boot (0xFC is then erased;
the reference stays reserved).

**DOMAIN_STATUS (`0x40`)**, 117 bytes:

| Offset | Size | Field |
|---|---|---|
| 0 | 1 | format version, 1 |
| 1 | 1 | flags: `01` DKEK present, `02` OTP production mode (else development), `04` this device's certificate is in the member list, `08` a peer is pinned, `10` an exchange this session served a peer that ISSUE_MEMBER_CERT may certify, `20` this device's own certificate is revoked |
| 2 | 16 | domain_id = SHA-256(Q_domain)[0..16] (zeros without a DKEK) |
| 18 | 8 | KCV = SHA-256(DKEK)[0..8] (zeros without a DKEK) |
| 26 | 65 | Q_domain, uncompressed P-256 (zeros without a DKEK) |
| 91 | 16 | own member ID = SHA-256(device public key)[0..16] (zeros before INITIALIZE) |
| 107 | 8 | Lamport counter, u64 BE |
| 115 | 1 | member-list entries |
| 116 | 1 | member-list capacity (32) |

The domain key is `d = OS2IP(HKDF-SHA256(ikm=DKEK, salt="pico2hsm-domain-v1",
info="sign", L=48)) mod n` on P-256; every device with the same DKEK
reports the same domain_id.  Reference: `tools/python/pico2hsm/domain.py`,
vectors `firmware/tests/vectors/domain_v1.txt`.

**GET_MEMBERS (`0x47`).** `total(1) ‖ first(1) = P2 ‖ n(1) ‖ n × entry`;
ask again with P2 = first + n while first + n < total.  `6A86` if
P2 > total, `6A80` for other data.  Data absent or `01`: version-1
entries (197 bytes), at most 16 per page.  Data `02`: version-2 entries
(277 bytes) = the version-1 layout with version byte 2, then
`revoker_id(16) ‖ revocation sig(64)` (zeros while active), at most 14 per
page; a revoked entry rebuilds into its revocation record (below).
Version-1 entry (197 bytes):

```
version(1) = 1 | status(1) 0 active / 1 revoked | revoked_lamport(8 BE)
| certificate(187):
    version(1) = 1 | domain_id(16) | member_id(16) = SHA-256(member_pub)[0..16]
    | member_pub(65) | sponsor_id(16) | issued_lamport(8 BE) | flags(1) bit0 may sponsor
    | sig(64) = ECDSA-P256(d_domain, r‖s) over
                SHA-256("pico2hsm-member-cert-v1" ‖ the 123 bytes before it)
```

#### Storage V2 store commands (`0x4E`, `0x4F`, `0x52`, `0x53`, pico2hsm vendor)

`docs/STORAGE_V2.md` §8.3, §9.3 and §16 describe the design;
`docs/KEYSTORE_RECOVERY.md` is the operator's runbook.  CLA `0x80`, SC-HSM
selected.  The SO-PIN (VERIFY P2 = `0x88`) lives in the binding block, so it
verifies while the store is refused.  After a successful FORMAT STORE, OPEN
DEGRADED or ACCEPT STORE every applet's state is reloaded from the store,
which ends the session's authentication: SELECT and VERIFY again.

**STORE_STATUS (`0x52`)** — no PIN, no data.  Response (big-endian):

```
state(1) | reason(1) | lost(8) | degraded_opens(4) | reanchors(4) | head(8)
```

| `state` | Meaning |
|---|---|
| `0` | up (read-write) |
| `1` | read-only: OPEN DEGRADED mounted it |
| `2` | refused; the binding is valid: OPEN DEGRADED, ACCEPT STORE or FORMAT STORE |
| `3` | no 2.0 store or no verifiable binding: FORMAT STORE only |
| `4` | down (no storage key) |

`reason` (states 1 and 2): `1` blank, `2` another store's journal, `3` no
anchor, `4` behind the anchor, `5` damaged, `6` key rotation pending, `7`
read error.  `lost`: journal records the anchor counts that the store does
not hold (reason 4 before OPEN DEGRADED; exact once mounted read-only).
`degraded_opens`, `reanchors`: lifetime counts from the counter log.
`head`: the mounted state's newest journal record.

**FORMAT_STORE (`0x4E`)** — data `FORMAT-STORE-V2`.  Replaces the store
with a new, empty one: every key of every applet is gone.  Needs the
SO-PIN, except when there is no valid binding (state 3) or the store is
refused and no SO-PIN is set.  Carries the SO-PIN forward, so the next
INITIALIZE needs it.  SW `6982` without the needed SO-PIN, `6A80` wrong
data, `6581` write failure.

**OPEN_DEGRADED (`0x4F`)** — SO-PIN, data `OPEN-DEGRADED`.  Mounts a refused
store (state 2) read-only, as far as it verifies: keys work and can be
exported, every change fails with `6581`, until ACCEPT STORE, FORMAT STORE
or a reboot.  The open is counted in the counter log first.  SW `6985` if
the store is not refused, `6982` without the SO-PIN, `6581` if nothing
verifiable is left.

**ACCEPT_STORE (`0x53`)** — SO-PIN, data `ACCEPT-STORE-V2` followed by the
`lost` count STORE_STATUS reported (u64 BE).  Only after OPEN DEGRADED,
and only for reason 4 (behind the anchor) or 5 (damaged).  Makes the
read-only state the store's new read-write state, giving up the `lost`
records: keys deleted or changed in them may come back in their earlier
form.  A re-index under a new journal key, resumable after a power cut;
counted, with the old and accepted heads, in the counter log first.  SW
`6985` in any other state or reason, `6A80` for a different count, `6982`
without the SO-PIN, `6581` write failure.

#### RSA key pool (`0x50`, `0x51`, pico2hsm vendor, `rsa` firmware)

The device pre-generates RSA-2048/3072/4096 keys between APDUs and SC-HSM
GENERATE KEY PAIR (§3.19) hands out a pooled key when it has one (design
and security notes: `docs/SECURITY_SUMMARY.md`, "RSA key pool").  Without
the `rsa` feature both sub-commands answer `6A81`.

**RSA_POOL_STATUS (`80 54 50 00`)**, no PIN, 43 bytes, big-endian:

| Offset | Size | Field |
|---|---|---|
| 0 | 1 | format version, 1 |
| 1 | 1 | health: `01` boot RNG check passed (pool may run), `02` pool region present, `04` background work stopped after 3 failed flash writes / erases in a row (until reboot), `08` configuration or pool clock unreadable / not persisted: pool held off and emptied (fail closed) |
| 2 | 8 | configuration, as RSA_POOL_CONFIG's data |
| 10 | 3 | issuable keys (valid and younger than the maximum age): RSA-2048, -3072, -4096 |
| 13 | 2 | size being generated, in bits; 0 = none |
| 15 | 8 | pool clock: minutes of powered-on time, persisted |
| 23 | 4 | sequence number of the newest pooled key |
| 27 | 4 | keys pooled since boot |
| 31 | 4 | keys retired by age since boot |
| 35 | 4 | pooled keys issued since boot |
| 39 | 4 | keys generated live (pool empty or off) since boot |

**RSA_POOL_CONFIG (`80 54 51 00`)**, SO-PIN (`6982` otherwise), data
8 bytes:

| Offset | Size | Field |
|---|---|---|
| 0 | 1 | flags: `01` pool enabled, `02` rotation / age-out; other bits `6A80` |
| 1 | 4 | maximum age in minutes of powered-on time, BE, 60 to 525 600 (`6A80` otherwise) |
| 5 | 3 | keys kept per size, RSA-2048 / -3072 / -4096, each 0–4 (`6A80` otherwise) |

Factory setting: `03 000000F0 04 02 02` (on, rotation on, 4 hours, 4/2/2).
Another length is `6700`.  The setting is persisted (retry-counter log,
value id 3) before it takes effect — `6581` if that write fails — and
survives INITIALIZE.  Clearing `01` erases every pooled key before the
answer (`6581` if an erase fails; the background finishes the job).
Lowering a depth retires the oldest surplus keys in the background.  The
answer is the new RSA_POOL_STATUS.

INITIALIZE erases every pooled key (a re-initialisation is a trust reset);
the configuration, clock and sequence number stay.

A device that holds the DKEK and has no member list certifies itself
(sponsor = itself): when the last DKEK share is imported or an exchange
installs the DKEK, and at boot if it held a DKEK before this firmware.
SC-HSM INITIALIZE erases the member list, the object sidecars and the pin.
The member key is generated by INITIALIZE, so a re-initialised device is a
new member.

**Revocation record** (121 bytes):

```
version(1) = 1 | domain_id(16) | member_id(16) revoked | revoker_id(16)
| revoked_lamport(8 BE) | sig(64) = ECDSA-P256(d_domain, r‖s) over
                SHA-256("pico2hsm-member-revoke-v1" ‖ the 57 bytes before it)
```

**ISSUE_MEMBER_CERT (`0x45`, SO-PIN).** Certifies an enrolling member and
stores the certificate in this device's list.  `flags` defaults to `01`
(may sponsor); only bit 0 may be set.  `member_pub` must be the peer this
device sent its DKEK to (`0x37`) **in this card session**, or the peer
currently pinned with `0x3D`.  Either is single use and spent by the
certificate.  The exchange binding also ends at SELECT, at a new pin
(`0x3D`), and when another SOURCE run starts (`0x36`).  This device's own
certificate must be active with may-sponsor.  The Lamport counter is advanced first; the certificate
carries the new value and outranks any certificate held for the member.

| SW | Meaning |
|---|---|
| `6985` | no DKEK, no identity key, or no exchanged / pinned peer |
| `6700` | data not 65 or 66 bytes |
| `6A80` | not a P-256 point, unknown flag bits, or this device's own key |
| `6982` | SO-PIN not verified; not the exchanged / pinned peer; or this device may not sponsor |
| `6984` | the member is revoked (permanent) |
| `6A84` | the member list is full (32 entries, revoked included) |
| `6581` | the counter, the pin or the list could not be written |

**REVOKE_MEMBER (`0x46`, SO-PIN).** Marks the member revoked here (the
entry stays) and returns the revocation for the other members.  Same
authority as issuing; a device never revokes itself (`6A80`).  `6A88`
unknown member, `6A89` already revoked, `6982` / `6985` / `6581` as above.

**IMPORT_MEMBER_CERT (`0x49`) / IMPORT_REVOCATION (`0x4A`), no PIN.**
The device checks the domain signature (authority comes from the domain
key).  Certificates for one member rank sponsor-issued above self-issued,
then by higher `issued_lamport`; of two revocations of one member, the
earliest (lowest `revoked_lamport`, `revoker_id`, `sig`) is kept.  A
revocation comes with the revoked member's certificate when the device has
not listed that member yet (308 bytes: extended APDU).

| SW | Meaning |
|---|---|
| `9000` | data `01`: member added; `00`: entry replaced / marked revoked |
| `6985` | no DKEK (no domain) |
| `6700` | IMPORT_REVOCATION data neither 121 nor 308 bytes |
| `6A80` | malformed, another domain, bad signature, self-revocation, a certificate for another member, or a Lamport value above 2^62 |
| `6A89` | already held, or outranked by what is held |
| `6984` | the member is revoked (any certificate, however new), or its sponsor was revoked before issuing it |
| `6982` | the sponsor (or revoker) is listed on this device without may-sponsor, or the revoker was revoked before it |
| `6A88` | revocation of an unlisted member without its certificate |
| `6A84` | the member list is full |
| `6581` | the list could not be written |

---

### 3.30 DEBUG DUMP (INS = 0xFE)

**Only compiled when the `debug` Cargo feature is enabled.** Never present in production builds.

Dumps a region of RAM, flash, or OTP memory. Currently a stub returning `SW = 0x6A80`.

Test hooks on the same INS (CLA `0x80`): P1 `0x10` wedges core1, `0x11`
wedges core0 after replying, `0x12` resets through the watchdog (watchdog
tests); `0x13` moves the keystore anchor P2 records ahead of the journal,
so the next boot refuses the store as behind its anchor (recovery test,
`tests/hw/test_21_store_recovery.py`); `0x14` reboots into BOOTSEL,
`0x15` returns the image version and the bootrom's boot info (slot,
trial state), `0x16` the loaded partition table
([FLASH_LAYOUT_2_0.md](FLASH_LAYOUT_2_0.md) §3); `0x20`/`0x21` RSA
benchmark and self-test (`rsa` builds).

**Command:**

| Field | Value |
|---|---|
| CLA | `0x00` |
| INS | `0xFE` |
| P1 | `0x00` RAM; `0x01` flash; `0x02` OTP |
| P2 | `0x00` |
| Data | `[address: 4 BE][length: 2 BE]` for RAM/flash; `[page: 1][row: 1]` for OTP |

---

### 3.31 Key usage policy (CardContact key attributes)

Since 2026-10 (audit S-10). A key may be created with:

| Tag | Length | Meaning |
|---|---|---|
| `90` | 4 | Key use counter: uses left (BE). `0` = unusable |
| `91` | 1–32 | Algorithm list: the algorithm IDs (CardContact, OpenSC `card-sc-hsm.h`) the key may be used with |
| `92` | 1 | Key domain; only domain `00` exists (one DKEK) — others `6A88` |

Without `91` every algorithm valid for the key type is allowed; without
`90` there is no limit. Keys created before this firmware load with no
restriction (that is what the spec gives a key generated without the
tags). An empty `91` counts as absent.

**Enforcement.** Every use checks the operation's algorithm ID against the
list, then, for a key with a counter, writes the decremented counter to
flash **before** the operation (like the PIN retry counters): a result never
leaves the device without its use on flash, and a malformed request (bad
P2, empty data, wrong key type, CBC length) is refused before anything is
spent. Errors: `6A84` counter exhausted, `6985` algorithm not allowed,
`6581` the counter could not be written.

| Operation | Algorithm ID checked |
|---|---|
| COMPUTE DIGITAL SIGNATURE, PSO:CDS | P2 / MSE algorithm (`13`/`15`/`17`/`19` as `70`) |
| DECIPHER, PSO:DECIPHER | RSA: `21`; ECDH (any code): `80` |
| GENERAL AUTHENTICATE (ECDSA over SHA-256 of the challenge) | `73` |
| PSO checksum AES-CMAC (compute or verify) | `18` |
| CIPHER CBC encrypt / decrypt / CMAC | `10` / `11` / `18` |
| WRAP KEY (export) | `92` (no use spent; counted keys refused) |
| CIPHER CTR / GCM, PSO HMAC, DERIVE (HKDF, `62 01 00`), BIP/SLIP | none in CardContact's list: only keys **without** a list |

**Who sets it.** OpenSC's default key generation (pkcs11-tool,
pkcs15-init) sends none of the tags. `sc-hsm-tool --generate-key
--key-use-counter N --key-domain D` sends `90` (and `92` = D−1); no OpenSC
tool sends `91` — use a raw GENERATE KEY PAIR (see `tests/hw/test_17_key_policy.py`)
or CardContact's own tooling.

**Storage.** The policy is part of the encrypted key object (magic `P2KP`
= `P2K4` + policy; keys without a policy keep `P2K4`, so firmware before
2026-10 refuses a restricted key rather than use it unrestricted). It is
reported in the key file's FCP (§3.1). WRAP / UNWRAP carry the algorithm
list in the CardContact blob's own field (§3.32); a use counter makes a key
unexportable. A key created by DERIVE gets no policy (none is
stored by this firmware's derive commands, which return data).

---

### 3.32 Key backup blob (WRAP / UNWRAP) — CardContact format

The blob WRAP KEY returns and UNWRAP KEY accepts on a SmartCard-HSM.
`sc-hsm-tool --wrap-key` stores it in a `.wky` file as
`30 { 04 <blob>, [PRKD from EF C4xx], [certificate from EF CExx] }` and
`--unwrap-key` writes the blob to EF `2F10`, sends UNWRAP, then restores the
PRKD and certificate EFs.

**Sources.**
[1] OpenSC `src/tools/sc-hsm-tool.c` (`wrap_key`, `unwrap_key`,
`print_dkek_info`, `import_dkek_share`) and `src/libopensc/card-sc-hsm.c`
(`sc_hsm_wrap_key`, `sc_hsm_unwrap_key`, `sc_hsm_manage_key_domain`),
master, fetched 2026-10-11.
[2] pico-hsm (the C reference firmware, which imports SmartCard-HSM
backups) `src/hsm/kek.c` — `dkek_kcv`, `dkek_kenc`, `dkek_kmac`,
`dkek_encode_key`, `dkek_decode_key`, `import_dkek_share` — and
`cmd_key_wrap.c`, `cmd_key_unwrap.c`, `cmd_key_domain.c`, commit
`32435f01`; `py-picohsm` `PicoHSM.wrap_key`.
[3] CardContact Smart Card Shell `scsh/sc-hsm/DKEK.js` `dumpKeyBLOB`
field list and descriptions, as printed in Nitrokey support threads
(support.nitrokey.com, "How to port keys and certificates from nitrokey
USB to softhsm token", 2024; "How to encrypt the wky file outside of the
Nitrokey HSM"): KCV "[Must match the KCV of the DKEK for import]", key type
"[5=RSA, 6=RSA-CRT, 12=ECC, 15=AES]", "Default Algorithm ID", "Allowed
Algorithm IDs", "Access Conditions [Not used]", "Key OID [Not used]",
"Randomize [Random data prepended at export]", "Key size [Key size in bits
(ECC/RSA) or bytes (AES)]", RSA-CRT fields in the order DP1, DQ1, prime
factor p, PQ, prime factor q, modulus, public exponent.

**Keys** (DKEK = 32 bytes, the XOR of the shares) [2]:

```
KCV   = SHA-256(DKEK)[0..8]
K_enc = SHA-256(DKEK || 00 00 00 01)      AES-256 key
K_mac = SHA-256(DKEK || 00 00 00 02)      AES-256 key
```

**Layout** (`LV(x)` = 2-byte big-endian length, then `x`) [2][3]:

| Offset | Length | Field |
|---|---|---|
| 0 | 8 | KCV — must match the importing device's |
| 8 | 1 | key type: `5` RSA, `6` RSA-CRT, `12` EC, `15` AES |
| 9 | 2 + o | default algorithm OID (DER content octets) |
| … | 2 + m | allowed algorithm IDs (tag `91` list; empty = all algorithms valid for the key type) |
| … | 2 + a | access conditions (unused by CardContact: empty) |
| … | 2 + k | key OID (unused: empty) |
| … | 16·n | AES-256-CBC(K_enc, IV = 0, encrypted part) |
| end − 16 | 16 | AES-256-CMAC(K_mac, every byte before it) |

Default algorithm OIDs: RSA `04 00 7F 00 07 02 02 02 01 02`
(id-TA-RSA-v1-5-SHA-256), EC `04 00 7F 00 07 02 02 02 02 03`
(id-TA-ECDSA-SHA-256), AES `60 86 48 01 65 03 04 01` (aes).

**Encrypted part** (before encryption):

| Offset | Length | Field |
|---|---|---|
| 0 | 8 | random ("Randomize"); with IV = 0 it makes each blob unique |
| 8 | 2 | key size: bits of the modulus (RSA) or field prime (EC), bytes (AES) |
| 10 | … | key material, below |
| … | ≥ 1 | padding `80 00 …` to a multiple of 16 (ISO/IEC 9797-1 method 2) |

| Type | Key material |
|---|---|
| 5 RSA | `LV(d) LV(n) LV(e)` |
| 6 RSA-CRT | `LV(dP) LV(dQ) LV(p) LV(qInv = q⁻¹ mod p) LV(q) LV(n) LV(e)` |
| 12 EC | `LV(a) LV(b) LV(p) LV(order) LV(G) LV(d) LV(Q)`; G, Q uncompressed `04‖X‖Y` |
| 15 AES | the key (16, 24 or 32 bytes; length = key size field) |

**pico2hsm encoding choices.** WRAP writes RSA as type 6 (what a
SmartCard-HSM exports [3]); EC a, b, p fixed to the field length, order
and d to the order length, key size 521 for P-521; integers of RSA without
leading zeros; always at least one padding byte; empty key OID. The
allowed-algorithm list is the key's (§3.31). The access-condition field is
empty unless the key has key flags (`D4` bits ALLOW_SIGN / ALLOW_DECRYPT /
ALLOW_DERIVE), which pico2hsm puts there as one byte so another pico2hsm
restores them; other devices ignore the field [2][3]. A use counter or key
domain has no field: counted keys are not exportable, and UNWRAP places the
key in domain 0, the domain whose DKEK opened it.

**UNWRAP decoding** is lenient where implementations differ, strict where
it matters: KCV, then CMAC (constant time) before anything else; header
fields bounded (OIDs ≤ 32, list ≤ 32, access ≤ 16 bytes); integers of any
length with or without leading zeros (pico-hsm writes minimal lengths,
an empty `a` for curves with a = −3 or 0, and key size 528 for P-521); the
curve is identified by its prime (P-256, P-384, P-521, secp256k1) and the
order must match; d must be in [1, n−1] and Q, when present, must equal
d·G; RSA types 5 and 6, 1024–4096 bits, key rebuilt and validated (type 5
by prime recovery); padding bytes are not checked (covered by the CMAC);
the key OID and default algorithm OID are not interpreted.

**Test vectors.** `firmware/tests/vectors/cardcontact_wrap.txt` (from the
independent Python reference `tools/python/pico2hsm/cardcontact_wrap.py`;
every blob also decodes with pico-hsm's own `dkek_decode_key` built on the
host) and `picohsm_wrap.txt` (written by pico-hsm's `dkek_encode_key`);
`firmware/tests/cardcontact_wrap_vectors.rs` checks both, and that WRAP
reproduces the reference blobs byte for byte.

---

## 4. TLV Tag Glossary

Common BER-TLV tags used across SC-HSM commands.

| Tag | Class | Context | Description |
|---|---|---|---|
| `0x80` | Context primitive | MSE, INITIALIZE | Algorithm identifier byte; or INITIALIZE options bitmask |
| `0x81` | Context primitive | MSE, INITIALIZE, CHANGE PIN | Key reference or User PIN |
| `0x82` | Context primitive | INITIALIZE, CHANGE PIN | Init code (SO-PIN) or new PIN |
| `0x83` | Context primitive | GENERATE KEY PAIR | PUK reference |
| `0x84` | Context primitive | MSE | Key reference (1 byte key slot ID) |
| `0x85` | Context primitive | GENERATE KEY PAIR / 7F49 | EC group order |
| `0x86` | Context primitive | GENERATE KEY PAIR / 7F49 | EC public point (`04 \|\| X \|\| Y`) |
| `0x87` | Context primitive | GENERATE KEY PAIR / 7F49 | EC cofactor |
| `0x91` | Context primitive | INITIALIZE | User PIN retry counter |
| `0x92` | Context primitive | INITIALIZE | DKEK share count |
| `0x93` | Context primitive | INITIALIZE, IMPORT KEY | PUK; or P2 value for IMPORT KEY operation |
| `0x42` | Application primitive | GENERATE KEY PAIR | Key reference/label; or outer CA reference in CVC |
| `0x53` | Application primitive | WRITE DATA | Data payload (BER-TLV length) |
| `0x54` | Application primitive | WRITE DATA, READ BINARY ODD | Write/read offset (and optional file ID) |
| `0x62` | Application constructed | SELECT | File Control Parameters (FCP) |
| `0x6F` | Application constructed | SELECT AID | File Control Information (FCI) |
| `0x7C` | Context constructed | GENERAL AUTHENTICATE | Dynamic Authentication Template |
| `0x81` | Context primitive | GENERAL AUTHENTICATE / 7C | Host challenge |
| `0x82` | Context primitive | GENERAL AUTHENTICATE / 7C | Card response (signature) |
| `0x5F 29` | Application primitive | GENERATE KEY PAIR | Certificate Profile Identifier (CPI) |
| `0x5F 20` | Application primitive | GENERATE KEY PAIR | Certificate Holder Reference (CHR) |
| `0x5F 37` | Application primitive | GENERATE KEY PAIR | Signature in CVC |
| `0x7F 21` | Application constructed | GENERATE KEY PAIR | CVC outer wrapper |
| `0x7F 4E` | Application constructed | GENERATE KEY PAIR | Certificate Body |
| `0x7F 49` | Application constructed | GENERATE KEY PAIR | Public Key template |
| `0x9F 6E` | Application primitive | SELECT AID FCI | Card OS / HW version (4 bytes) |

---

## 5. Algorithm Identifier Table

SC-HSM AlgorithmId bytes used in MSE SET (tag `0x80`) and directly in INS=0x68 P2 / INS=0x62 P2.

| Byte | Name | Key type | Notes |
|---|---|---|---|
| `0x05` | RSA-2048 keygen | `RsaPrivate2048` | Used in GENERATE KEY PAIR; `rsa` feature |
| `0x07` | RSA-4096 keygen | `RsaPrivate4096` | `rsa` feature |
| `0x13` | ECDSA P-256 (pre-hashed) | `EcPrivateP256` | Sign input = digest |
| `0x15` | ECDSA P-384 (pre-hashed) | `EcPrivateP384` | |
| `0x17` | ECDSA P-521 (pre-hashed) | `EcPrivateP521` | |
| `0x19` | ECDSA K-256 (pre-hashed) | `EcPrivateK256` | secp256k1 |
| `0x20` | RSA RAW | `RsaPrivate2048/4096` | Host pre-pads; card does `m^d mod n` |
| `0x21` | RSA decrypt (PKCS#1/OAEP) | `RsaPrivate2048/4096` | Raw `c^d mod n`; host unpadding |
| `0x22` | RSA decrypt, PKCS#1 unpadding on card | — | Refused (`6D00`): padding oracle |
| `0x23` | ECDH P-256 | `EcPrivateP256` | Decipher; returns raw X |
| `0x25` | ECDH P-384 | `EcPrivateP384` | |
| `0x27` | ECDH P-521 | `EcPrivateP521` | |
| `0x29` | ECDH K-256 | `EcPrivateK256` | |
| `0x31` | RSA PKCS#1v1.5 + SHA-1 | `RsaPrivate*` | Card hashes |
| `0x32` | RSA PKCS#1v1.5 + SHA-224 | `RsaPrivate*` | Card hashes |
| `0x33` | RSA PKCS#1v1.5 + SHA-256 | `RsaPrivate*` | Card hashes |
| `0x34` | RSA PKCS#1v1.5 + SHA-384 | `RsaPrivate*` | Card hashes |
| `0x35` | RSA PKCS#1v1.5 + SHA-512 | `RsaPrivate*` | Card hashes |
| `0x40` | RSA-PSS, external SHA-256 digest | `RsaPrivate*` | 32-byte input only |
| `0x70` | ECDSA EC-RAW (pre-hashed) | Any EC | Generic; digest passed directly |
| `0x71` | ECDSA + SHA-1 | Any EC | Card hashes; 20-byte digest |
| `0x72` | ECDSA + SHA-224 | Any EC | Card hashes; 28-byte digest |
| `0x73` | ECDSA + SHA-256 | Any EC | Card hashes; 32-byte digest |
| `0x74` | ECDSA + SHA-384 | Any EC | Card hashes; 48-byte digest |
| `0x75` | ECDSA + SHA-512 | Any EC | Card hashes; 64-byte digest |
| `0x80` | ECDH generic (ALGO_EC_DH) | Any EC | OpenSC generic; response has `0x04` prefix |
| `0x10` / `0x11` | AES-CBC encrypt / decrypt | AES | Usage-policy IDs (CIPHER P2 is pico2hsm's own) |
| `0x18` | AES-CMAC | AES | Usage-policy ID |
| `0x92` | WRAP | Any | Usage-policy ID for EXPORT KEY |
| `0x82` | AES-128 keygen | Symmetric | GENERATE SYMMETRIC KEY only |
| `0x83` | AES-192 keygen | Symmetric | |
| `0x84` | AES-256 keygen | Symmetric | |

---

## 6. Key Type Table

SC-HSM key slot ID conventions and corresponding internal types.

| Key slot ID range | Owner | Type examples | Notes |
|---|---|---|---|
| `0x00` | SC-HSM (reserved) | EC P-256 | Sentinel entry for device auth key; slot is pre-occupied after INITIALIZE |
| `0x01–0x7F` | SC-HSM | EC P-256/384/521/K-256; RSA-2048/4096; AES-128/192/256 | User-assigned key range |
| `0x80–0x8F` | PIV applet (reserved) | (varies) | See storage namespace design |
| `0x90–0x92` | OpenPGP applet (reserved) | (varies) | SIG=0x90, DEC=0x91, AUTH=0x92 |
| `0xFF` | (invalid) | — | Rejected by keygen and import commands |

**Key type bytes** (from `pico2hsm_core::key::KeyType`):

| Internal type | Algo byte | Private key size | Public key size |
|---|---|---|---|
| `EcPrivateP256` | `0x13` / `0x23` | 32 bytes | 65 bytes (`04 \|\| X \|\| Y`) |
| `EcPrivateP384` | `0x15` / `0x25` | 48 bytes | 97 bytes |
| `EcPrivateP521` | `0x17` / `0x27` | 66 bytes | 133 bytes |
| `EcPrivateK256` | `0x19` / `0x29` | 32 bytes | 65 bytes |
| `RsaPrivate2048` | `0x05` | ≤1200 bytes PKCS#1 DER | 256-byte modulus |
| `RsaPrivate4096` | `0x07` | ≤2350 bytes PKCS#1 DER | 512-byte modulus |
| `Aes` / `Aes128` | `0x82` | 16 bytes | — |
| `Aes192` | `0x83` | 24 bytes | — |
| `Aes256` | `0x84` | 32 bytes | — |

---

## 7. Status Word Reference

| SW | ISO 7816-4 name | pico2hsm usage |
|---|---|---|
| `9000` | Normal processing — No further qualification | Success |
| `63CX` | Warning — Counter provided by 'X' | PIN/PUK wrong; X retries remaining |
| `6700` | Wrong length | PIN too short/long; wrong data length |
| `6982` | Security status not satisfied | No valid PIN/SO-PIN session |
| `6983` | Authentication method blocked | PIN/PUK retry counter = 0 |
| `6984` | Referenced data invalidated | No PIN hash stored (uninitialized) |
| `6985` | Conditions of use not satisfied | No challenge outstanding; MSE not set; slot full |
| `6A80` | Incorrect parameters in the command data field | Malformed TLV; unknown P1/P2; UNWRAP blob not authentic for this DKEK |
| `6A81` | Function not supported | WRAP / UNWRAP of a key with no CardContact encoding (Ed25519, X25519, brainpool, AES-512; RSA without the `rsa` feature) |
| `6A82` | File or application not found | Key not in store; EF not found |
| `6A84` | Not enough memory space in the file | Key use counter (`90`) exhausted |
| `6A88` | Referenced data not found | Unknown PIN reference P2; key domain other than 0; KEY DOMAIN status with no DKEK configured |
| `6D00` | Instruction code not supported or invalid | Unknown INS; not-yet-implemented command |

---

## 8. PKCS#15 Virtual Filesystem Map

The SC-HSM protocol exposes a virtual PKCS#15 filesystem. Files are read-only static blobs or dynamically generated from keystore state.

```
MF  (3F00)
  DF.CIA  (5015)
    EF.DIR      (2F00)   -- Static: AID pointer → pico2hsm
    EF.C_DevAut (2F02)   -- Static: minimal device CVC stub ("DESE00001")
    EF.ODF      (5031)   -- Static: pointers to PrKDF/PuKDF/AODF
    EF.TokenInfo(5032)   -- Static: PKCS#15 token description
    EF.AODF     (C000)   -- Static: User PIN descriptor
    EF.PrKDF    (C100)   -- Always empty (SC-HSM uses LIST KEYS + C4xx)
    EF.PuKDF    (C200)   -- Always empty
    PRKD        (C4xx)   -- Dynamic per key: PKCS#15 PrivateECKey descriptor
    Key blob    (CCxx)   -- Presence indicator for key slot xx
    EE cert     (CExx)   -- Written via WRITE DATA by OpenSC/pkcs15-init
```

**Token label:** `"SmartHSM"` (encoded in EF.TokenInfo)  
**Serial number:** `"pico2hsm"` (8 bytes, encoded in EF.TokenInfo)  
**Manufacturer:** `"pico2hsm"`

---

## 9. pico2hsm-Specific Deviations from Reference SC-HSM

1. **PIN storage:** the user PIN and PUK are stored as salted PBKDF2-HMAC-SHA256 hashes (10,000 iterations) in the PIN record (reserved key ref `0xFF`); the SO-PIN lives in the Storage V2 binding block, so it verifies even on a refused store. Retry counters are in the counter log on internal flash and are spent before each comparison. All survive power cycles.

2. **Key persistence:** EC and RSA keys are persisted to flash via `storage::KeyStore`. Symmetric keys are also persisted. Keys survive power cycles.

3. **DKEK / key wrapping:** WRAP / UNWRAP KEY use the CardContact key blob (§3.32); the previous pico2hsm v2/v3 blobs still import, deprecated, for one release. KCV = SHA-256(DKEK)[0..8] as on a SmartCard-HSM. The DKEK is persisted (reserved slot `0xFD`) and restored at boot. KEY DOMAIN P1 = `01`–`05` are pico2hsm-specific (§3.27); one key domain.

4. **Session PIN P2=0x82:** The session PIN is cleared from state after the first VERIFY attempt, whether correct or wrong, preventing replay. This matches the reference spec behavior.

5. **SIGN uses P1=key_id, P2=algo directly** rather than requiring a prior MSE SET. Both paths (direct P1/P2 in INS=0x68, and MSE SET + INS=0x2A) are supported.

6. **DECIPHER / DERIVE ASYM sharing INS=0x62:** DERIVE ASYMMETRIC is selected only by P1=0x01 **and** P2=0x00; everything else routes to DECIPHER (see §3.22).

7. **LIST KEYS / IMPORT KEY sharing INS=0x58:** When INS=0x58 and P2=0x93, the IMPORT KEY handler is invoked. P2=0x00 routes to LIST KEYS.

8. **EF.PrKDF is always empty:** The standard PKCS#15 PrKDF mechanism is not used. OpenSC is expected to call LIST KEYS (INS=0x58) to discover occupied slots, then read per-key PRKD (C4xx) EFs for key metadata.

9. **EXTERNAL AUTHENTICATE:** not supported (removed 2026-10; see §3.17).

10. **DEBUG DUMP (INS=0xFE):** Only compiled in `#[cfg(feature = "debug")]` builds. The stub currently returns `SW_WRONG_DATA`. Never enable the `debug` feature in production.

12. **Usage-policy gaps (§3.31):** RSA-PSS only with an external SHA-256
    digest (`41`–`45` unsupported); `30` (DigestInfo input) and RSA
    decrypt with card-side unpadding (`22`, `23`) unsupported; the
    pico2hsm ECDH (`23`/`25`/`27`/`29`) and pre-hashed ECDSA
    (`13`/`15`/`17`/`19`) codes are extensions; CIPHER uses its own P1/P2
    (direction / mode), not CardContact's P1 = key, P2 = algorithm; only
    key domain 0; no XKEK / `ALGO_EC_DH_XKEK`. Algorithms without a
    CardContact ID are refused for a key with an algorithm list.

11. **ECDH1-COFACTOR-DERIVE:** For all supported curves the cofactor h=1, making COFACTOR-DERIVE and plain DERIVE identical at the APDU level. OpenSC 0.25's SC-HSM driver rejects COFACTOR-DERIVE for P-256 at the PKCS#11 layer; tests use `ECDH1-DERIVE` to avoid this driver-side restriction.

---

## Security notes (October 2026 audit)

See `docs/AUDIT_2026-10.md` for the full list and commits.

- **Retry counters** for the user PIN, SO-PIN and PUK are written to flash
  *before* the credential is compared, so a power cycle or USB reset cannot
  undo a failed guess. Only well-formed attempts count (malformed APDUs
  are rejected without spending a retry). Re-INITIALIZE spends the SO-PIN
  counter and is refused while the SO-PIN is blocked. Minimum user PIN
  length is 6.
- **Reserved key references `0xFC`–`0xFF`** (legacy enrolled peer, DKEK,
  device identity key, PIN record) are refused by SIGN, DECIPHER, PSO via MSE,
  GENERAL AUTHENTICATE, BIP/SLIP, GENERATE KEY [PAIR], IMPORT/EXPORT KEY and
  DELETE FILE.
- **EXTRAS DKEK exchange (`0x35`–`0x38`)** requires the SO-PIN and a peer
  pinned with `0x3D` on both devices; there is no unauthenticated mode.
  SOURCE encrypts the DKEK only to the ephemeral key whose signature it
  verified in `0x36`; TARGET never overwrites an existing DKEK.  The pin
  is single use: a second exchange needs a new pin.
- **EXTRAS `0x39` GET_KEY_MANIFEST** requires the user PIN (`0x3A` state hash
  stays open: it is a device-signed attestation).
- **EXTERNAL AUTHENTICATE (`0x82`)** is removed (returns `6D00`).
- **BIP/SLIP derive** refuses NO_EXPORT keys and the empty path (which would
  return the master key).
- **Write failures** (`6581`) are reported; the card state is left as it was
  on flash.

