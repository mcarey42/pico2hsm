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
| EC key slots (in-memory) | 16 |
| RSA key slots (in-memory, feature `rsa`) | 4 |
| Symmetric key slots (in-memory) | 8 |
| EF (data file) slots (in-memory) | 16 |
| Max EF file size | 2048 bytes |
| Max PIN length | 16 bytes |
| Max SO-PIN length | 16 bytes |

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
| `0x34` | EXPORT KEY | Export DKEK-wrapped key blob | Stubbed (SW_INS_NOT_SUPPORTED) |
| `0x46` | GENERATE KEY PAIR | Generate asymmetric key pair on-device | Implemented |
| `0x48` | GENERATE SYMMETRIC KEY | Generate AES-128/192/256 key on-device | Implemented |
| `0x50` | INITIALIZE | Initialize / re-initialize device | Implemented |
| `0x52` | KEY DOMAIN | Manage DKEK key domains | Partially implemented |
| `0x54` | EXTRAS | Additional KDF / MAC primitives | Implemented |
| `0x58` | LIST KEYS / IMPORT KEY | List key slots (P2=0x00) or import wrapped key (P2=0x93) | LIST: Implemented; IMPORT: Stubbed |
| `0x60` | BIP/SLIP HD DERIVE | BIP32 / SLIP-0010 hierarchical key derivation | Implemented |
| `0x62` | DECIPHER / DERIVE ASYM | ECDH key agreement or RSA decrypt (P1=key_id) or derive asymmetric key (P1=0x01) | Implemented |
| `0x68` | SIGN | Compute digital signature (ECDSA / RSA) | Implemented |
| `0x78` | SYMMETRIC CIPHER | AES-CBC / CTR / GCM / CMAC | Implemented |
| `0x82` | EXTERNAL AUTHENTICATE | Challenge-response authentication (HMAC-SHA256) | Implemented |
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

**Re-initialization:** When `state.initialized == true`, the init code in tag `0x82` is compared (SHA-256 hash) against the stored SO-PIN hash. Mismatch returns `SW = 0x6982`.

**Effects:**
- Clears all in-memory keys (EC, RSA, symmetric, EF files)
- Wipes SC-HSM-owned keys from flash (`store.wipe_by_owner(AppletId::ScHsm)`)
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

Returns random bytes from the hardware TRNG. The first 8 bytes are also stored in `state.challenge` for subsequent EXTERNAL AUTHENTICATE. The challenge is single-use (cleared by EXTERNAL AUTHENTICATE regardless of outcome).

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

### 3.17 EXTERNAL AUTHENTICATE (INS = 0x82)

Authenticates an external entity using HMAC-SHA256 challenge-response. Establishes SO-PIN session (`state.so_pin_verified = true`) without presenting the SO-PIN directly.

**Command:**

| Field | Value |
|---|---|
| CLA | `0x00` |
| INS | `0x82` |
| P1 | `0x00` |
| P2 | `0x00` |
| Data | 32 bytes: `HMAC-SHA256(so_pin_hash, challenge)` |

The challenge is the 8-byte value previously returned by GET CHALLENGE. The key is the 32-byte SHA-256 hash of the SO-PIN (init code). The challenge is cleared from state immediately — whether or not the cryptogram matches — preventing replay.

**Status words:**

| SW | Meaning |
|---|---|
| `9000` | Cryptogram correct, SO-PIN session opened |
| `6982` | SO-PIN hash not set |
| `6984` | No challenge outstanding |
| `6700` | Response not exactly 32 bytes |

---

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

**Algorithm inference from `7F49` content:**

| `7F49` content | Algorithm byte | Key type |
|---|---|---|
| Tag `0x85` (order) length = 32 bytes (P-256 prime) | `0x13` | ECDSA P-256 |
| Tag `0x85` length = 32 bytes (K-256 prime) | `0x19` | ECDSA K-256 |
| Tag `0x85` length = 48 bytes | `0x15` | ECDSA P-384 |
| Tag `0x85` length = 66 bytes | `0x17` | ECDSA P-521 |
| Tag `0x02` value = `0x0800` (2048 bits) | `0x05` | RSA-2048 |
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

**Status words:**

| SW | Meaning |
|---|---|
| `9000` | Success |
| `6982` | PIN not verified |
| `6A80` | Missing algorithm byte or unknown algorithm |
| `6985` | Keystore full |

---

### 3.20 GENERATE SYMMETRIC KEY (INS = 0x48)

Generates an AES key from the on-chip TRNG and stores it in the in-memory symmetric keystore and flash.

**Command:**

| Field | Value |
|---|---|
| CLA | `0x00` |
| INS | `0x48` |
| P1 | Key slot ID (`0x01–0xFE`) |
| P2 | `0x00` |
| Data | 1 byte: algorithm tag (`0x82`=AES-128, `0x83`=AES-192, `0x84`=AES-256) |

**Status words:**

| SW | Meaning |
|---|---|
| `9000` | Success |
| `6982` | PIN not verified |
| `6A80` | Invalid key ID or unknown algorithm tag |
| `6985` | Flash write failed |

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
| `0x31` | RSA PKCS#1v1.5 + SHA-256 | Raw message | Card hashes; `rsa` feature required |
| `0x32` | RSA PKCS#1v1.5 + SHA-384 | Raw message | `rsa` feature required |
| `0x33` | RSA PKCS#1v1.5 + SHA-512 | Raw message | `rsa` feature required |
| `0x34` | RSA-PSS + SHA-256 (internal) | 32-byte SHA-256 digest | `rsa` feature required |
| `0x40` | RSA-PSS + SHA-256 | 32-byte SHA-256 digest | `rsa` feature required |
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
| `6985` | Empty data field |
| `6A82` | Key not found |
| `6D00` | Unknown algorithm byte |

---

### 3.22 DECIPHER / DERIVE ASYMMETRIC KEY (INS = 0x62)

INS `0x62` is shared between two operations, disambiguated by P1:

- P1 = key slot ID (any value except `0x01`): **DECIPHER** — ECDH key agreement or RSA decrypt
- P1 = `0x01`: **DERIVE ASYMMETRIC KEY** — KDF-based derivation using a stored key

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
| `0x21` | RSA decrypt (PKCS#1 or OAEP) | RSA ciphertext (`c`) | Raw `c^d mod n`; host strips padding |
| `0x22` | RSA decrypt (OAEP variant) | Same as 0x21 | Same |
| `0x23` | ECDH P-256 | `04 \|\| Qx \|\| Qy` (65 bytes) | Raw X-coordinate (32 bytes) |
| `0x25` | ECDH P-384 | `04 \|\| Qx \|\| Qy` (97 bytes) | Raw X-coordinate (48 bytes) |
| `0x27` | ECDH P-521 | `04 \|\| Qx \|\| Qy` (133 bytes) | Raw X-coordinate (66 bytes) |
| `0x29` | ECDH K-256 | `04 \|\| Qx \|\| Qy` (65 bytes) | Raw X-coordinate (32 bytes) |
| `0x80` | ECDH generic (ALGO_EC_DH) | `04 \|\| Qx \|\| Qy` | `04 \|\| X-coord` (OpenSC strips the 0x04 prefix) |

**Response notes:** For `P2 = 0x80`, pico2hsm prepends `0x04` to the X-coordinate. OpenSC's `sc_hsm_decipher` strips this prefix to recover the field-size X bytes. For explicit ECDH codes (`0x23/0x25/0x27/0x29`), the raw X-coordinate is returned without the prefix.

**Note — ECDH1-COFACTOR-DERIVE vs ECDH1-DERIVE:** For all supported curves (P-256/P-384/P-521/K-256) the cofactor h=1, so `ECDH1-COFACTOR-DERIVE` (0x1051) and `ECDH1-DERIVE` (0x1050) are mathematically identical. Tests use `ECDH1-DERIVE` because OpenSC 0.25's SC-HSM driver rejects `ECDH1-COFACTOR-DERIVE` for P-256 keys at the PKCS#11 layer (before sending any APDU).

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
| `0x02` | AES-CBC | `[IV: 16 bytes][plaintext or ciphertext]` | CBC-encrypted or decrypted payload |
| `0x03` | AES-CTR | `[nonce: 16 bytes][data]` | XOR-keystream applied (encrypt=decrypt) |
| `0x05` | AES-GCM | `[nonce: 12 bytes][aad_len: 2 BE][aad][payload]` | Encrypt: `ct \|\| tag(16)`; Decrypt: plaintext |
| `0x06` | AES-CMAC | `[message]` | 16-byte CMAC tag (P1 ignored) |

**Constraints:**
- AES-CTR: AES-256 only (32-byte key). Payload max 4080 bytes.
- AES-GCM decrypt: payload must include the 16-byte authentication tag appended to ciphertext.
- AES-CBC: plaintext/ciphertext must be block-aligned (16-byte boundary).

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

### 3.25 IMPORT KEY (INS = 0x58, P2 = 0x93)

Imports a wrapped key blob (SC-HSM DKEK wrap format). Stub — not yet implemented.

**Command:**

| Field | Value |
|---|---|
| CLA | `0x00` |
| INS | `0x58` |
| P1 | Key slot ID |
| P2 | `0x93` |
| Data | Wrapped key blob |

**Status words:**

| SW | Meaning |
|---|---|
| `6D00` | Not implemented (SW_INS_NOT_SUPPORTED) |

---

### 3.26 EXPORT KEY (INS = 0x34)

Exports a key wrapped under the DKEK. Stub — not yet implemented.

**Command:**

| Field | Value |
|---|---|
| CLA | `0x00` |
| INS | `0x34` |
| P1 | Key slot ID |
| P2 | `0x00` |

**Status words:**

| SW | Meaning |
|---|---|
| `6D00` | Not implemented (SW_INS_NOT_SUPPORTED) |

---

### 3.27 KEY DOMAIN (INS = 0x52)

Manages DKEK key domains. Requires SO-PIN session. Domain create/delete/assign and DKEK share import are stubbed; domain status query (P1=0x04) is implemented.

**Command:**

| Field | Value |
|---|---|
| CLA | `0x00` |
| INS | `0x52` |
| P1 | Sub-command (see table) |
| P2 | Domain ID |
| Data | Sub-command specific |

**Sub-commands (P1):**

| P1 | Operation | Status |
|---|---|---|
| `0x01` | Create key domain | Stub |
| `0x02` | Delete key domain | Stub |
| `0x03` | Import DKEK share | Partial (increments counter only) |
| `0x04` | Query domain status | Implemented |
| `0x05` | Assign key to domain | Stub |

**P1=0x04 response:** `[dkek_shares_required, dkek_shares_imported]` (2 bytes).

**Status words:**

| SW | Meaning |
|---|---|
| `9000` | Success (P1=0x04) |
| `6982` | SO-PIN not verified |
| `6D00` | Sub-command not implemented |
| `6A80` | Unknown P1 |

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

---

### 3.30 DEBUG DUMP (INS = 0xFE)

**Only compiled when the `debug` Cargo feature is enabled.** Never present in production builds.

Dumps a region of RAM, flash, or OTP memory. Currently a stub returning `SW = 0x6A80`.

**Command:**

| Field | Value |
|---|---|
| CLA | `0x00` |
| INS | `0xFE` |
| P1 | `0x00` RAM; `0x01` flash; `0x02` OTP |
| P2 | `0x00` |
| Data | `[address: 4 BE][length: 2 BE]` for RAM/flash; `[page: 1][row: 1]` for OTP |

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
| `0x22` | RSA decrypt (OAEP variant) | `RsaPrivate2048/4096` | Same raw op |
| `0x23` | ECDH P-256 | `EcPrivateP256` | Decipher; returns raw X |
| `0x25` | ECDH P-384 | `EcPrivateP384` | |
| `0x27` | ECDH P-521 | `EcPrivateP521` | |
| `0x29` | ECDH K-256 | `EcPrivateK256` | |
| `0x31` | RSA PKCS#1v1.5 + SHA-256 | `RsaPrivate*` | Card hashes |
| `0x32` | RSA PKCS#1v1.5 + SHA-384 | `RsaPrivate*` | |
| `0x33` | RSA PKCS#1v1.5 + SHA-512 | `RsaPrivate*` | |
| `0x34` | RSA-PSS + SHA-256 (internal) | `RsaPrivate*` | Pre-hashed (32-byte input) |
| `0x40` | RSA-PSS + SHA-256 | `RsaPrivate*` | Pre-hashed (32-byte input) |
| `0x70` | ECDSA EC-RAW (pre-hashed) | Any EC | Generic; digest passed directly |
| `0x71` | ECDSA + SHA-1 | Any EC | Card hashes; 20-byte digest |
| `0x72` | ECDSA + SHA-224 | Any EC | Card hashes; 28-byte digest |
| `0x73` | ECDSA + SHA-256 | Any EC | Card hashes; 32-byte digest |
| `0x74` | ECDSA + SHA-384 | Any EC | Card hashes; 48-byte digest |
| `0x75` | ECDSA + SHA-512 | Any EC | Card hashes; 64-byte digest |
| `0x80` | ECDH generic (ALGO_EC_DH) | Any EC | OpenSC generic; response has `0x04` prefix |
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
| `6A80` | Incorrect parameters in the command data field | Malformed TLV; unknown P1/P2 |
| `6A82` | File or application not found | Key not in store; EF not found |
| `6A88` | Referenced data not found | Unknown PIN reference P2 |
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

1. **PIN storage:** PINs are stored as SHA-256 hashes in RAM only (volatile). Flash persistence of PIN hashes is not yet implemented; PINs must be re-set after power cycle by re-running INITIALIZE.

2. **Key persistence:** EC and RSA keys are persisted to flash via `storage::KeyStore`. Symmetric keys are also persisted. Keys survive power cycles.

3. **DKEK / key wrapping:** EXPORT KEY and IMPORT KEY are stubs (return `SW_INS_NOT_SUPPORTED`). KEY DOMAIN management (create/delete/assign) is also not implemented.

4. **Session PIN P2=0x82:** The session PIN is cleared from state after the first VERIFY attempt, whether correct or wrong, preventing replay. This matches the reference spec behavior.

5. **SIGN uses P1=key_id, P2=algo directly** rather than requiring a prior MSE SET. Both paths (direct P1/P2 in INS=0x68, and MSE SET + INS=0x2A) are supported.

6. **DECIPHER / DERIVE ASYM sharing INS=0x62:** When INS=0x62 and P1=0x01, the DERIVE ASYMMETRIC handler is invoked. Any other P1 value routes to DECIPHER.

7. **LIST KEYS / IMPORT KEY sharing INS=0x58:** When INS=0x58 and P2=0x93, the IMPORT KEY handler is invoked. P2=0x00 routes to LIST KEYS.

8. **EF.PrKDF is always empty:** The standard PKCS#15 PrKDF mechanism is not used. OpenSC is expected to call LIST KEYS (INS=0x58) to discover occupied slots, then read per-key PRKD (C4xx) EFs for key metadata.

9. **EXTERNAL AUTHENTICATE:** Uses `HMAC-SHA256(so_pin_hash, challenge)` rather than a hardware-stored key pair. This is a pico2hsm simplification.

10. **DEBUG DUMP (INS=0xFE):** Only compiled in `#[cfg(feature = "debug")]` builds. The stub currently returns `SW_WRONG_DATA`. Never enable the `debug` feature in production.

11. **ECDH1-COFACTOR-DERIVE:** For all supported curves the cofactor h=1, making COFACTOR-DERIVE and plain DERIVE identical at the APDU level. OpenSC 0.25's SC-HSM driver rejects COFACTOR-DERIVE for P-256 at the PKCS#11 layer; tests use `ECDH1-DERIVE` to avoid this driver-side restriction.
