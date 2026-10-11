# PIV APDU Reference

**Specification**: NIST SP 800-73-4 "Interfaces for Personal Identity Verification"
**Implementation target**: pico2hsm PIV applet (`applet-piv` feature)
**AID**: `A0 00 00 03 08 00 00 10 00 01 00`

Sources used:
- NIST SP 800-73-4 Parts 1 and 2
- OpenSC `card-piv.c` (OpenSC project, master branch)
- `yubikit/piv.py` (Yubico yubikey-manager, main branch)
- YubiKey PIV extensions (INS 0xF7–0xFF)

---

## 1. Overview

### 1.1 PIV Application Identifier

```
AID (full):  A0 00 00 03 08 00 00 10 00 01 00  (11 bytes)
AID (short): A0 00 00 03 08  (RID only, 5 bytes — used by some clients for SELECT)
```

### 1.2 Application Lifecycle

1. **Factory state** — No keys, no certificates, default management key, default PIN/PUK.
2. **Personalization** — Management key authenticated; keys generated or imported; certificates and data objects written with PUT DATA.
3. **Operational** — User authenticates with PIN (0x80) or card authenticates with 9E key. Cryptographic operations performed via GENERAL AUTHENTICATE.
4. **Reset** — All PIV data erased by unblocking attempts exhausted or by explicit reset (YubiKey extension INS 0xFB). Returns to factory state.

### 1.3 Authentication Model

| Credential | Key Reference | P2 Byte | Length | Notes |
|---|---|---|---|---|
| PIN | — | `0x80` | 6–8 bytes ASCII digits, padded to 8 with `0xFF` | Primary user PIN |
| PUK | — | `0x81` | 8 bytes, any value | PIN Unblocking Key |
| Management Key | `0x9B` | — | 24 bytes (3DES) or 16/24/32 bytes (AES) | Card admin key |
| Card Auth Key | `0x9E` | — | — | Used in GENERAL AUTHENTICATE, no PIN required |

**Default PIN**: `31 32 33 34 35 36 FF FF` ("123456" + 2 × 0xFF padding)
**Default PUK**: `31 32 33 33 33 33 35 36` (YubiKey: "12345678")
**Default management key (3DES)**: `01 02 03 04 05 06 07 08  01 02 03 04 05 06 07 08  01 02 03 04 05 06 07 08` (24 bytes)

PIN retry counter defaults to 3 on standard PIV cards, 3/3 on YubiKey.
PUK retry counter defaults to 3.

### 1.4 Key Slot Model

Four mandatory slots, up to 20 retired Key Management slots, plus card management and attestation slots. See Section 5 for the full table.

---

## 2. Command Summary Table

| INS | Mnemonic | CLA | Description |
|---|---|---|---|
| `0xA4` | SELECT | `0x00` | Select PIV application by AID |
| `0x20` | VERIFY | `0x00` | Verify PIN (or query retry status) |
| `0x24` | CHANGE REFERENCE DATA | `0x00` | Change PIN or PUK |
| `0x2C` | RESET RETRY COUNTER | `0x00` | Unblock PIN using PUK |
| `0xCB` | GET DATA | `0x00` | Read a PIV data object by tag |
| `0xDB` | PUT DATA | `0x00` | Write a PIV data object (admin) |
| `0x87` | GENERAL AUTHENTICATE | `0x00` | Sign, decrypt, ECDH, card auth, mutual auth |
| `0x47` | GENERATE KEY PAIR | `0x00` | Generate asymmetric key pair on card |
| `0xC0` | GET RESPONSE | `0x00` | Retrieve remaining response data |
| `0xF7` | GET METADATA | `0x00` | YubiKey: query key/PIN metadata |
| `0xF8` | GET SERIAL | `0x00` | YubiKey: get serial number |
| `0xF9` | ATTEST | `0x00` | YubiKey: generate attestation certificate |
| `0xFA` | SET PIN RETRIES | `0x00` | YubiKey: set PIN/PUK attempt counts |
| `0xFB` | RESET | `0x00` | YubiKey: factory reset PIV application |
| `0xFD` | GET VERSION | `0x00` | YubiKey: get firmware version |
| `0xFE` | IMPORT KEY | `0x00` | YubiKey: import private key material |
| `0xFF` | SET MANAGEMENT KEY | `0x00` | YubiKey: change/set management key |

---

## 3. Per-Command Reference

### 3.1 SELECT (AID)

Selects the PIV card application. Must be sent before any other PIV command.

| Field | Value |
|---|---|
| CLA | `0x00` |
| INS | `0xA4` |
| P1 | `0x04` (select by AID) |
| P2 | `0x00` (first or only occurrence) |
| Lc | `0x0B` (full AID length) |
| Data | `A0 00 00 03 08 00 00 10 00 01 00` |
| Le | `0x00` (request all available response bytes) |

**Response data** (File Control Information template, outer tag `0x61`):

```
61 xx                     — Application Template
  4F yy <AID bytes>       — Application Identifier (PIX portion or full AID)
  50 zz <name bytes>      — Application Label (e.g. "PIV" in ASCII: 50 03 50 49 56)
  79 xx                   — Coexistent Tag Allocation Authority (optional)
  AC xx                   — Supported Cipher Suite Algorithm (800-73-4 SM, optional)
    80 01 <cs_id>         — Cipher Suite ID (e.g. 0x27 = CS2, 0x2E = CS7)
```

Minimal conformant response (no SM support):
```
61 11
  4F 0B A0 00 00 03 08 00 00 10 00 01 00
  50 03 50 49 56
```

**Status words**:

| SW | Meaning |
|---|---|
| `90 00` | Success |
| `6A 82` | Application not found |
| `6E 00` | CLA not supported |

---

### 3.2 VERIFY (PIN)

Submits the cardholder PIN for verification, or queries the remaining retry count.

| Field | Value |
|---|---|
| CLA | `0x00` |
| INS | `0x20` |
| P1 | `0x00` (always) |
| P2 | `0x80` (PIN), `0x81` (PUK — non-standard, avoid), `0x96` (OCC/biometric — YubiKey Bio) |
| Lc | `0x08` (PIN present) or absent (query only, Lc=0) |
| Data | PIN bytes (ASCII digits) padded to 8 bytes with `0xFF`. E.g. PIN "123456" = `31 32 33 34 35 36 FF FF` |

**Query mode** (Lc=0, no data field): Returns retry count without consuming an attempt. Some cards return `6X XX` on this even if not verified — use actual VERIFY with SW to determine state.

**Response**: No data field on success.

**Status words**:

| SW | Meaning |
|---|---|
| `90 00` | PIN verified |
| `63 Cn` | Verification failed, `n` = remaining attempts (0–15) |
| `63 0n` | Same as above (YubiKey NEO non-standard variant) |
| `69 83` | Authentication method blocked (0 retries left) |
| `69 84` | Reference data not usable |
| `6A 86` | Incorrect P1/P2 |
| `6A 88` | Reference data not found (key reference not supported) |

**Authentication requirement**: None (this command establishes authentication).

---

### 3.3 CHANGE REFERENCE DATA

Changes the PIN or PUK. Requires knowledge of the current value.

| Field | Value |
|---|---|
| CLA | `0x00` |
| INS | `0x24` |
| P1 | `0x00` |
| P2 | `0x80` (PIN) or `0x81` (PUK) |
| Lc | `0x10` (16 bytes: old value + new value) |
| Data | `<old value, 8 bytes padded>` + `<new value, 8 bytes padded>` |

PIN padding: ASCII digits padded to 8 bytes with `0xFF`.
PUK padding: Any 8-byte value padded with `0xFF` if shorter.

FIPS 201 requires numeric-only PIN (ASCII `0x30`–`0x39`) and minimum length 6.

**Status words**:

| SW | Meaning |
|---|---|
| `90 00` | Success |
| `63 Cn` | Wrong current value, `n` retries remaining |
| `69 83` | Blocked (0 retries) |
| `6A 86` | Incorrect P2 |

---

### 3.4 RESET RETRY COUNTER (PIN Unblock)

Resets the PIN using the PUK, simultaneously setting a new PIN value.

| Field | Value |
|---|---|
| CLA | `0x00` |
| INS | `0x2C` |
| P1 | `0x00` |
| P2 | `0x80` (reset PIN) |
| Lc | `0x10` (16 bytes) |
| Data | `<PUK, 8 bytes padded>` + `<new PIN, 8 bytes padded>` |

**Status words**:

| SW | Meaning |
|---|---|
| `90 00` | PIN reset successfully |
| `63 Cn` | Wrong PUK, `n` retries remaining |
| `69 83` | PUK blocked |
| `6A 86` | Incorrect P2 |

---

### 3.5 GET DATA

Retrieves a PIV data object by its BER-TLV tag. Returns the full object body wrapped in tag `0x53` (or `0x7E` for Discovery Object).

| Field | Value |
|---|---|
| CLA | `0x00` |
| INS | `0xCB` |
| P1 | `0x3F` |
| P2 | `0xFF` |
| Lc | Length of the tag field |
| Data | `5C` + length + object tag bytes (see Section 4) |
| Le | `0x00` (extended: `00 00 00` for large objects) |

**Command data example** — fetch CHUID (tag `5F C1 02`):
```
00 CB 3F FF 05  5C 03 5F C1 02  00
```

**Command data example** — fetch Discovery Object (tag `0x7E`, single byte):
```
00 CB 3F FF 03  5C 01 7E  00
```

**Response data**: The raw object TLV, outer tag `0x53` (content wrapper). For example:
```
53 xx
  <inner TLV data per object type>
  FE 00    — Error Detection Code (trailing, mandatory for most objects)
```

For Discovery Object, outer tag is `0x7E`.

**Status words**:

| SW | Meaning |
|---|---|
| `90 00` | Success |
| `61 xx` | More data available; `xx` = bytes remaining (use GET RESPONSE) |
| `6A 82` | Object not found |
| `69 82` | Security status not satisfied (PIN required for this object) |
| `6A 86` | Incorrect P1/P2 |

**Authentication requirement**: Some objects require PIN (e.g. Fingerprints, Printed Info, Cardholder Facial Images, Iris Images). Most certificate objects can be read unauthenticated. See Section 4 for per-object access rules.

---

### 3.6 PUT DATA

Writes a PIV data object. Requires prior mutual authentication with the management key (GENERAL AUTHENTICATE with key 0x9B).

| Field | Value |
|---|---|
| CLA | `0x00` |
| INS | `0xDB` |
| P1 | `0x3F` |
| P2 | `0xFF` |
| Lc | Length of the data field |
| Data | `5C` + len + tag bytes + `53` + len + object content |

**Command data structure**:
```
5C <tag_len> <object_tag_bytes>   — identifies the object to write
53 <content_len> <object_content> — the full object body including inner TLVs
```

For a certificate object (e.g. 9A cert, tag `5F C1 05`):
```
5C 03 5F C1 05
53 <len>
  70 <cert_len> <DER certificate>
  71 01 00         — cert info byte (00 = uncompressed, 01 = gzip)
  FE 00            — error detection code
```

**Status words**:

| SW | Meaning |
|---|---|
| `90 00` | Success |
| `69 82` | Security status not satisfied (management key auth required) |
| `6A 82` | Object not found / tag not recognised |
| `6A 84` | Not enough memory |
| `6A 86` | Incorrect P1/P2 |

---

### 3.7 GENERAL AUTHENTICATE

The core cryptographic command. Used for:
- Card-holder authentication (sign with 9A / 9C / 9D / 9E private key)
- Card authentication (challenge/response with 9E — no PIN required)
- Management key mutual authentication (3DES/AES with 9B)
- Key agreement / ECDH (9D key)
- Random challenge generation

| Field | Value |
|---|---|
| CLA | `0x00` (or `0x10` for command chaining if data exceeds 255 bytes) |
| INS | `0x87` |
| P1 | Algorithm identifier (see Section 6) |
| P2 | Key reference (see Section 5) |
| Lc | Length of command data |
| Data | Dynamic Authentication Template (tag `0x7C`), see Section 7 |
| Le | `0x00` (or extended Le for large keys) |

**Response**: Dynamic Authentication Template (tag `0x7C`) containing the result.

**Status words**:

| SW | Meaning |
|---|---|
| `90 00` | Success |
| `61 xx` | More data (use GET RESPONSE) |
| `69 82` | Security status not satisfied (PIN required and not verified) |
| `69 84` | Reference data not usable |
| `6A 80` | Incorrect command data / bad TLV |
| `6A 86` | P1/P2 incorrect (bad key reference or algorithm) |
| `6A 88` | Reference data not found (key slot empty) |

**Authentication requirement** by slot:

| Slot | Required authentication |
|---|---|
| `0x9A` | PIN (once per session by default) |
| `0x9C` | PIN (every use — "PIN Always") |
| `0x9D` | PIN (once per session) |
| `0x9E` | None (card authentication) |
| `0x9B` | None (management auth flow begins here) |
| `0x82`–`0x95` | PIN (once per session) |

See Section 7 for detailed TLV structure of each use case.

---

### 3.8 GENERATE KEY PAIR

Generates an asymmetric key pair on the card. Returns the public key. Requires prior mutual authentication with the management key.

| Field | Value |
|---|---|
| CLA | `0x00` |
| INS | `0x47` |
| P1 | `0x00` |
| P2 | Key reference (slot number, e.g. `0x9A`) |
| Lc | Length of template |
| Data | Cryptographic Algorithm Identifier Template (tag `0xAC`) |
| Le | `0x00` |

**Command data** (tag `0xAC`):
```
AC <len>
  80 01 <alg_id>      — algorithm identifier (required, see Section 6)
  AA 01 <pin_policy>  — PIN policy (optional, YubiKey extension)
  AB 01 <touch_policy>— touch policy (optional, YubiKey extension)
```

**Response data** (tag `0x7F49` — public key template):

For RSA keys:
```
7F 49 <len>
  81 <modulus_len> <modulus>    — RSA modulus N
  82 <exp_len>    <exponent>    — RSA public exponent e (typically 01 00 01)
```

For EC keys (P-256, P-384):
```
7F 49 <len>
  86 <point_len> <uncompressed_point>  — 04 || X || Y
```

For Ed25519 / X25519:
```
7F 49 <len>
  86 20 <32-byte_public_key>
```

**Status words**:

| SW | Meaning |
|---|---|
| `90 00` | Success |
| `69 82` | Security status not satisfied (management key auth required) |
| `6A 80` | Incorrect data (bad template) |
| `6A 81` | Function not supported (algorithm not supported) |
| `6A 86` | P2 incorrect (invalid key reference) |

---

### 3.9 GET RESPONSE

Retrieves the remainder of a response that was too large for a single APDU. Called when the previous command returned SW `61 xx`.

| Field | Value |
|---|---|
| CLA | `0x00` |
| INS | `0xC0` |
| P1 | `0x00` |
| P2 | `0x00` |
| Le | `0x00` (request up to 256 bytes) or the `xx` value from `61 xx` |

**Response**: Next chunk of the pending response data.

**Status words**:

| SW | Meaning |
|---|---|
| `90 00` | This is the final chunk |
| `61 xx` | More data remains |
| `6A 86` | P1/P2 incorrect |

Note: Most modern readers and CCID drivers handle `61 xx` chaining automatically. The card must implement GET RESPONSE to be compatible with pcscd/OpenSC.

---

### 3.10 GET METADATA (YubiKey Extension)

Returns metadata about a key slot or PIN/PUK reference. Available on YubiKey firmware >= 5.3.0.

| Field | Value |
|---|---|
| CLA | `0x00` |
| INS | `0xF7` |
| P1 | `0x00` |
| P2 | Key reference or PIN reference (`0x80`, `0x81`, `0x9A`, `0x9B`, `0x9C`, `0x9D`, `0x9E`, `0x82`–`0x95`, `0x96`, `0xF9`) |
| Le | `0x00` |

**Response data** for a key slot (flat TLV sequence, not nested):

```
01 01 <alg_id>          — TAG_METADATA_ALGO: algorithm byte (see Section 6)
02 02 <pin_pol> <touch>  — TAG_METADATA_POLICY: [PIN_POLICY, TOUCH_POLICY]
03 01 <origin>           — TAG_METADATA_ORIGIN: 0x01=generated, 0x02=imported
04 <pubkey_len> <pubkey> — TAG_METADATA_PUBLIC_KEY: encoded public key (7F49 contents)
05 01 <is_default>       — TAG_METADATA_IS_DEFAULT: 0x00=not default, 0x01=default
```

**Response data** for management key (`P2 = 0x9B`):

```
01 01 <key_type>         — MANAGEMENT_KEY_TYPE: 0x03=3DES, 0x08=AES128, 0x0A=AES192, 0x0C=AES256
02 02 <FF> <touch>       — policy: first byte unused, second is touch policy
05 01 <is_default>       — 0x01 if management key is still the factory default
```

**Response data** for PIN/PUK (`P2 = 0x80` or `0x81`):

```
05 01 <is_default>       — 0x01 if value is factory default
06 02 <total> <remaining>— TAG_METADATA_RETRIES: [max_attempts, current_remaining]
```

**PIN_POLICY values** (tag `0x02`, first byte of policy pair):

| Value | Meaning |
|---|---|
| `0x00` | Default (slot-dependent) |
| `0x01` | Never (no PIN required) |
| `0x02` | Once (once per session) |
| `0x03` | Always (every use) |
| `0x04` | Match-Once (biometric, once) |
| `0x05` | Match-Always (biometric, every use) |

**TOUCH_POLICY values** (tag `0x02`, second byte of policy pair):

| Value | Meaning |
|---|---|
| `0x00` | Default |
| `0x01` | Never |
| `0x02` | Always |
| `0x03` | Cached (15 seconds) |

**Status words**:

| SW | Meaning |
|---|---|
| `90 00` | Success |
| `6A 88` | Reference not found (slot empty or unsupported reference) |
| `6D 00` | INS not supported (firmware < 5.3.0) |

---

## 4. Data Objects (DO) Reference

PIV data objects are addressed by a 1–3 byte BER-TLV tag, passed inside a `5C` TLV wrapper in GET DATA / PUT DATA commands.

### 4.1 Mandatory Data Objects

| Tag (hex) | Container ID | Object Name | Read Access | Write Access |
|---|---|---|---|---|
| `5F C1 07` | `DB 00` | Card Capability Container (CCC) | Free | Management key |
| `5F C1 02` | `30 00` | Cardholder Unique Identifier (CHUID) | Free | Management key |
| `5F C1 05` | `01 01` | X.509 Certificate for PIV Authentication (9A) | Free (VCI on contactless) | Management key |
| `5F C1 0A` | `01 00` | X.509 Certificate for Digital Signature (9C) | Free (VCI) | Management key |
| `5F C1 0B` | `01 02` | X.509 Certificate for Key Management (9D) | Free | Management key |
| `5F C1 01` | `05 00` | X.509 Certificate for Card Authentication (9E) | Free | Management key |
| `5F C1 03` | `60 10` | Cardholder Fingerprints | PIN required (VCI) | Management key |
| `5F C1 09` | `30 01` | Printed Information | PIN required (VCI) | Management key |
| `5F C1 08` | `60 30` | Cardholder Facial Images | PIN required (VCI) | Management key |
| `5F C1 06` | `90 00` | Security Object | Free (VCI) | Management key |
| `7E` | `60 50` | Discovery Object | Free | Management key |
| `5F C1 0C` | `60 60` | Key History Object | Free (VCI) | Management key |
| `5F C1 21` | `10 15` | Cardholder Iris Images | PIN required (VCI) | Management key |

### 4.2 Retired Key Management Certificates (800-73-3+)

| Tag (hex) | Container ID | Object Name |
|---|---|---|
| `5F C1 0D` | `10 01` | Retired X.509 Certificate for Key Management 1 |
| `5F C1 0E` | `10 02` | Retired X.509 Certificate for Key Management 2 |
| `5F C1 0F` | `10 03` | Retired X.509 Certificate for Key Management 3 |
| `5F C1 10` | `10 04` | Retired X.509 Certificate for Key Management 4 |
| `5F C1 11` | `10 05` | Retired X.509 Certificate for Key Management 5 |
| `5F C1 12` | `10 06` | Retired X.509 Certificate for Key Management 6 |
| `5F C1 13` | `10 07` | Retired X.509 Certificate for Key Management 7 |
| `5F C1 14` | `10 08` | Retired X.509 Certificate for Key Management 8 |
| `5F C1 15` | `10 09` | Retired X.509 Certificate for Key Management 9 |
| `5F C1 16` | `10 0A` | Retired X.509 Certificate for Key Management 10 |
| `5F C1 17` | `10 0B` | Retired X.509 Certificate for Key Management 11 |
| `5F C1 18` | `10 0C` | Retired X.509 Certificate for Key Management 12 |
| `5F C1 19` | `10 0D` | Retired X.509 Certificate for Key Management 13 |
| `5F C1 1A` | `10 0E` | Retired X.509 Certificate for Key Management 14 |
| `5F C1 1B` | `10 0F` | Retired X.509 Certificate for Key Management 15 |
| `5F C1 1C` | `10 10` | Retired X.509 Certificate for Key Management 16 |
| `5F C1 1D` | `10 11` | Retired X.509 Certificate for Key Management 17 |
| `5F C1 1E` | `10 12` | Retired X.509 Certificate for Key Management 18 |
| `5F C1 1F` | `10 13` | Retired X.509 Certificate for Key Management 19 |
| `5F C1 20` | `10 14` | Retired X.509 Certificate for Key Management 20 |

### 4.3 800-73-4 New Objects

| Tag (hex) | Container ID | Object Name | Notes |
|---|---|---|---|
| `7F 61` | `10 16` | Biometric Information Templates Group Template | 800-73-4 |
| `5F C1 22` | `10 17` | Secure Messaging Certificate Signer | 800-73-4 SM |
| `5F C1 23` | `10 18` | Pairing Code Reference Data Container | 800-73-4 VCI |

### 4.4 YubiKey Extension Objects

| Tag (hex) | Object Name | Notes |
|---|---|---|
| `5F FF 01` | Attestation Certificate | YubiKey attestation cert for slot `0xF9` |

### 4.5 Certificate Object Internal Structure

All X.509 certificate objects use this internal layout within the `0x53` wrapper:

```
53 <total_len>
  70 <cert_len> <DER_X.509_certificate>
  71 01 <info>              — Cert Info: 0x00=uncompressed, 0x01=gzip
  FE 00                     — Error Detection Code (mandatory)
```

### 4.6 Discovery Object Internal Structure

```
7E <len>
  4F 0B A0 00 00 03 08 00 00 10 00 01 00  — PIV AID
  5F 2F 02 <pin_policy_byte> <puk_byte>   — PIN usage policy
```

`pin_policy_byte` bits:
- Bit 6 (`0x40`): Global PIN is primary
- Bit 5 (`0x20`): Application (PIV) PIN is primary
- Bit 4 (`0x10`): OCC (biometric) is used
- Bit 3 (`0x08`): VCI is implemented

---

## 5. Key Slot Reference

### 5.1 Standard PIV Key Slots

| Key Ref | Name | NIST Description | Default PIN Policy | Algorithms |
|---|---|---|---|---|
| `0x9A` | PIV Authentication | Authenticates the cardholder to the system | Once per session | RSA-1024/2048/3072, ECC P-256/P-384 |
| `0x9B` | PIV Card Application Administration | Card management / mutual auth | Management key (not PIN) | 3DES-ECB, AES-128/192/256-ECB |
| `0x9C` | Digital Signature | Signing documents | Every use ("PIN Always") | RSA-1024/2048/3072, ECC P-256/P-384 |
| `0x9D` | Key Management | Asymmetric key agreement / decryption | Once per session | RSA-1024/2048/3072, ECC P-256/P-384 |
| `0x9E` | Card Authentication | Authenticate the card (no PIN) | Never | 3DES-ECB, ECC P-256/P-384 |

### 5.2 Retired Key Management Slots

| Key Ref | Name | PIN Policy |
|---|---|---|
| `0x82` | Retired Key Management 1 | Once per session |
| `0x83` | Retired Key Management 2 | Once per session |
| `0x84` | Retired Key Management 3 | Once per session |
| `0x85` | Retired Key Management 4 | Once per session |
| `0x86` | Retired Key Management 5 | Once per session |
| `0x87` | Retired Key Management 6 | Once per session |
| `0x88` | Retired Key Management 7 | Once per session |
| `0x89` | Retired Key Management 8 | Once per session |
| `0x8A` | Retired Key Management 9 | Once per session |
| `0x8B` | Retired Key Management 10 | Once per session |
| `0x8C` | Retired Key Management 11 | Once per session |
| `0x8D` | Retired Key Management 12 | Once per session |
| `0x8E` | Retired Key Management 13 | Once per session |
| `0x8F` | Retired Key Management 14 | Once per session |
| `0x90` | Retired Key Management 15 | Once per session |
| `0x91` | Retired Key Management 16 | Once per session |
| `0x92` | Retired Key Management 17 | Once per session |
| `0x93` | Retired Key Management 18 | Once per session |
| `0x94` | Retired Key Management 19 | Once per session |
| `0x95` | Retired Key Management 20 | Once per session |

### 5.3 Special Slots

| Key Ref | Name | Description |
|---|---|---|
| `0x9B` | Card Management | 3DES or AES management key, never an asymmetric key |
| `0x96` | OCC Auth | Biometric (YubiKey Bio) |
| `0xF9` | Attestation | YubiKey attestation signing key |

---

## 6. Algorithm Identifiers

Used in GENERAL AUTHENTICATE (P1) and GENERATE KEY PAIR (`0x80` tag inside `0xAC`).

### 6.1 Standard PIV Algorithms (NIST SP 800-73-4)

| Byte | Algorithm | Key Size | Notes |
|---|---|---|---|
| `0x03` | 3DES-ECB | 192 bits (24 bytes) | 3-key Triple DES, ECB mode. Used for 9B mutual auth and 9E card auth |
| `0x06` | RSA-1024 | 1024 bits | Deprecated; some cards still support it |
| `0x07` | RSA-2048 | 2048 bits | Standard RSA |
| `0x05` | RSA-3072 | 3072 bits | 800-73-4 |
| `0x11` | ECC P-256 | 256 bits | ECDSA / ECDH on NIST P-256 (prime256v1) |
| `0x14` | ECC P-384 | 384 bits | ECDSA / ECDH on NIST P-384 (secp384r1) |
| `0x08` | AES-128-ECB | 128 bits | Management key only (800-73-4) |
| `0x0A` | AES-192-ECB | 192 bits | Management key only (800-73-4) |
| `0x0C` | AES-256-ECB | 256 bits | Management key only (800-73-4) |

### 6.2 YubiKey Extension Algorithms

| Byte | Algorithm | Notes |
|---|---|---|
| `0x16` | RSA-4096 | YubiKey firmware >= 5.7 |
| `0xE0` | Ed25519 | YubiKey firmware >= 5.7 (EdDSA) |
| `0xE1` | X25519 | YubiKey firmware >= 5.7 (ECDH) |

### 6.3 Management Key Sizes

| ALG byte | Cipher | Key bytes | Challenge bytes |
|---|---|---|---|
| `0x03` | 3DES-ECB | 24 | 8 |
| `0x08` | AES-128-ECB | 16 | 16 |
| `0x0A` | AES-192-ECB | 24 | 16 |
| `0x0C` | AES-256-ECB | 32 | 16 |

---

## 7. GENERAL AUTHENTICATE TLV Detail

The Dynamic Authentication Template (DAT) uses outer tag `0x7C`. All GENERAL AUTHENTICATE commands wrap their payload in a `0x7C` TLV. The inner tags convey the operation type.

### 7.1 Inner Tag Reference

| Inner Tag | Name | Direction | Meaning |
|---|---|---|---|
| `0x80` | Witness | Response from card | Encrypted challenge (card proves knowledge of key) |
| `0x81` | Challenge | Host → Card | Random challenge for external or mutual auth |
| `0x82` | Response | Both | Cryptographic response to a challenge |
| `0x85` | Exponentiation | Host → Card | Public key / DH point for ECDH derivation |
| `0x86` | — | Host → Card | EC peer public key (DH input for some flows) |

### 7.2 Use Case: Sign or Decrypt (9A / 9C / 9D / 9E asymmetric keys)

The host sends the data to be processed (padded hash for signing, ciphertext for decryption) in tag `0x81`. The card returns the result in tag `0x82`.

**Command data**:
```
7C <len>
  82 00                     — empty Response tag (tells card to compute response)
  81 <input_len> <input>    — hash digest (ECDSA) or padded message (RSA) or ciphertext
```

**Response data**:
```
7C <len>
  82 <output_len> <output>  — DER-encoded ECDSA signature, or RSA result
```

For RSA signing: input is the raw PKCS#1 v1.5 padded message (card does raw RSA private-key exponentiation). For ECDSA: input is the raw SHA digest (e.g. 32 bytes for SHA-256). The card returns a DER SEQUENCE { INTEGER r, INTEGER s }.

For RSA decryption: input is the RSA ciphertext (same size as the key); output is the PKCS#1-padded plaintext (caller strips padding).

**APDU example** — ECDSA P-256 sign with 9C slot:
```
CLA INS  P1   P2
00  87   11   9C
Lc = 2 + 2 + 32 = 36 (0x24)
Data: 7C 24 82 00 81 20 <32-byte SHA-256 digest>
Le = 00
```

### 7.3 Use Case: ECDH Key Agreement (9D slot)

For key agreement, the host sends its EC public point in tag `0x85` (exponentiation tag). The card returns the shared secret point.

**Command data**:
```
7C <len>
  82 00                         — empty Response tag
  85 <point_len> <peer_pubkey>  — uncompressed EC point: 04 || X || Y
```

**Response data**:
```
7C <len>
  82 <secret_len> <shared_secret>  — raw shared secret (X coordinate of result point)
```

**APDU example** — ECDH with 9D (P-256):
```
00 87 11 9D  Lc=0x45  7C 43 82 00 85 41 04 <64 bytes XY>  Le=00
```

### 7.4 Use Case: Card Authentication Challenge/Response (9E slot)

Used to authenticate the card to the host using key 9E (typically 3DES or ECC). No PIN is required. This is a one-step external authentication where the host provides a cleartext challenge and the card encrypts it.

**Step 1 — Host sends empty challenge request**:
```
7C 02 81 00   — request challenge from card (for card auth the host may send challenge directly)
```

Alternatively (for direct external auth), the host sends the challenge:
```
7C <len>
  82 00
  81 <challenge_len> <random_challenge>
```

**Step 2 — Card responds with encrypted challenge**:
```
7C <len>
  82 <len> <encrypted_response>
```

For 3DES (key 9E): card encrypts the 8-byte challenge using 3DES-ECB. Host verifies by re-encrypting with the known key.

### 7.5 Use Case: Management Key Mutual Authentication (9B slot)

This is a two-round protocol. The card authenticates to the host (witness) and the host authenticates to the card (challenge). Both use ECB mode with no IV.

**Round 1 — Host requests witness (card proves it knows the key)**:

APDU:
```
00 87 <alg> 9B  04  7C 02 80 00  00
```
Data: `7C 02 80 00` — tag `0x7C`, length 2, tag `0x80` (Witness), length 0 (empty = request).

Card response:
```
7C <len>
  80 <n> <encrypted_nonce>   — card-generated nonce encrypted with management key
```

Where `n` = 8 (3DES) or 16 (AES).

**Round 2 — Host responds with decrypted witness + its own challenge**:

The host decrypts the `0x80` value using ECB mode (no IV), then constructs:

```
7C <len>
  80 <n> <decrypted_witness>  — proves host knows the management key
  81 <n> <host_nonce>         — host's random challenge for the card to encrypt back
```

APDU:
```
00 87 <alg> 9B  <len>  <above TLV>  00
```

Card response:
```
7C <len>
  82 <n> <encrypted_host_nonce>  — card encrypts host's nonce with management key
```

Host verifies by encrypting the original `host_nonce` with the same key and comparing against the `0x82` value. If they match, mutual authentication is complete.

### 7.6 Use Case: Get Random Challenge (for entropy)

Used by OpenSC to obtain random bytes from the card.

APDU:
```
00 87 00 9B  04  7C 02 81 00  00
```
Data: `7C 02 81 00` — request tag `0x81` (Challenge) with empty payload.

Response:
```
7C <len>
  81 <n> <random_bytes>
```

---

## 8. 3DES Specifics

### 8.1 3DES Algorithm Properties

| Property | Value |
|---|---|
| Algorithm ID | `0x03` |
| Mode | ECB (Electronic Codebook), **no IV** |
| Block size | 8 bytes |
| Key size | 24 bytes (3 × 8-byte DES keys) |
| Challenge/response size | 8 bytes (one DES block) |
| Padding | None (input must be exactly 8 bytes) |

The 24-byte key is interpreted as three 8-byte DES keys K1, K2, K3 for EDE (Encrypt–Decrypt–Encrypt) operation. The standard default management key (`01020304050607080102030405060708 01020304050607080102030405060708 01020304050607080102030405060708`) has K1=K2=K3, which degrades 3DES to single DES — this is the known factory default.

### 8.2 3DES Card Authentication Flow (Key 9E)

1. Host sends GENERAL AUTHENTICATE to card with key 9E:
   ```
   00 87 03 9E  04  7C 02 81 00  00
   ```
   Inner TLV: `7C 02 81 00` = request a challenge.

2. Card responds with `7C xx 81 08 <8-byte-random-nonce>`.

3. Host encrypts the 8-byte nonce with the 9E 3DES key using ECB mode.

4. Host sends back:
   ```
   00 87 03 9E  0C  7C 0A 82 08 <8-byte-ciphertext>  00
   ```
   Inner TLV: `7C 0A 82 08 <encrypted-nonce>`.

5. Card decrypts using its 9E key and checks match. Returns `90 00` on success.

### 8.3 3DES Mutual Authentication Flow (Key 9B)

As described in Section 7.5:

```
Round 1:
  Host → Card:  7C 02 80 00          (request witness)
  Card → Host:  7C 0A 80 08 <E(K,N)> (N = card nonce, E = 3DES-ECB encrypt)

Round 2:
  Host decrypts E(K,N) with K → gets N
  Host → Card:  7C 14 80 08 <N> 81 08 <M>   (M = host nonce, N = decrypted witness)
  Card → Host:  7C 0A 82 08 <E(K,M)>         (card encrypts host nonce)

Host verifies: E(K,M) == 3DES_ECB_Encrypt(K, M)
```

All encrypt/decrypt operations are **3DES-ECB with no IV and no padding**. The input must be exactly 8 bytes.

### 8.4 AES Management Key Differences

When using AES (alg IDs `0x08`, `0x0A`, `0x0C`), the same two-round protocol applies but:
- Challenge/nonce size = **16 bytes** (one AES block)
- Mode = **AES-ECB** (no IV, no padding)
- Key size = 16 / 24 / 32 bytes per alg ID

---

## 9. Command Chaining and Extended Length

### 9.1 Large Command Data (PUT DATA / GENERAL AUTHENTICATE)

If the command data exceeds 255 bytes, use ISO 7816-4 command chaining:

- All chained APDUs except the last use CLA = `0x10` (chain bit set).
- The final APDU uses CLA = `0x00`.
- Each APDU carries up to 255 bytes of data.

OpenSC handles this transparently via `sc_transmit_apdu`.

### 9.2 Large Response Data (GET DATA / GENERATE KEY PAIR)

When the response data exceeds 256 bytes, the card returns SW `61 xx` where `xx` is the number of remaining bytes (capped at 0xFF). The host issues GET RESPONSE (INS `0xC0`) repeatedly until SW `90 00` is received.

For extended-length capable readers and cards, use Le = `00 00 00` (extended Le = 65536) to request the entire response in one APDU.

---

## 10. Implementation Notes for pico2hsm

### 10.1 Minimum Viable Command Set

To pass OpenSC / piv-tool compatibility, implement in this order:

1. SELECT (respond with valid `0x61` template containing PIV AID)
2. GET DATA (CHUID, Discovery, card certificate objects)
3. VERIFY (PIN 0x80, query mode with Lc=0)
4. GENERAL AUTHENTICATE (management key mutual auth with 9B — required before PUT DATA)
5. PUT DATA (write certificate and data objects)
6. GENERATE KEY PAIR (9A, 9C, 9D, 9E)
7. GENERAL AUTHENTICATE (sign with 9A/9C, decrypt with 9D, card auth with 9E)
8. CHANGE REFERENCE DATA, RESET RETRY COUNTER

### 10.2 PIN Encoding

PIV PIN is always 8 bytes, right-padded with `0xFF`. Example:
```rust
fn encode_pin(pin: &[u8]) -> [u8; 8] {
    let mut buf = [0xFF_u8; 8];
    let len = pin.len().min(8);
    buf[..len].copy_from_slice(&pin[..len]);
    buf
}
```

### 10.3 Storage Namespace

Per CLAUDE.md:
- PIV key IDs: `0x80`–`0x8F` (9A→0x80, 9C→0x81, 9D→0x82, 9E→0x83, retired→0x84–0x8F)
- Object storage: separate namespace from SC-HSM objects, tagged with `owner = PIV`

### 10.4 CHUID Minimum Structure

CHUID must contain a valid FASC-N and a GUID. Minimum compliant CHUID for a test device:

```
53 <len>
  30 19 <25-byte FASC-N>     — Federal Agency Smart Credential Number
  34 10 <16-byte GUID>       — Card UUID
  35 08 32 30 33 30 30 31 30 31  — Expiration date: "20300101"
  3E 00                      — Issuer Asymmetric Signature (empty = no signature)
  FE 00                      — Error Detection Code
```

FASC-N for test use (all-zeros encoded): 9 field values all zero, BCD-encoded to 25 bytes.
GUID: any 16 random bytes.

### 10.5 Response Size Budget

Objects can be up to 12710 bytes (NIST 800-73-4 maximum). A P-384 certificate with chain easily reaches 2–4 KB. Use GET RESPONSE chaining or extended APDU Le.

The existing `Vec<u8, 4096>` response buffer in the dispatcher is adequate for most objects. For larger objects (compressed certificates), consider extended APDUs or implementing the `61 xx` / `C0` chaining mechanism.

### 10.6 Key usage and PIN policy as implemented (2026-10, audit S-10)

**Slots.** GENERATE KEY PAIR (management key) accepts 9A, 9C, 9D, 9E and
the retired key management slots 82–95; ECC P-256 (`11`) and P-384 (`14`)
only (no RSA, no Ed25519/X25519 in PIV).

**Key use per slot** (SP 800-73-4 Part 2 §3.2.4, SP 800-78-4):

| Slot | GENERAL AUTHENTICATE |
|---|---|
| 9A, 9C, 9E | Signature only: `7C { 82 00, 81 <hash> }` → `7C { 82 <DER sig> }` |
| 9D, 82–95 | Key establishment only (ECC CDH): `7C { 82 00, 85 <04‖X‖Y> }` → `7C { 82 <x-coordinate> }` |

The other operation is refused with `6A80` (a key management key does not
sign; a signature key does not agree keys).  Unlike a YubiKey, which signs
with any slot.

**PIN policy.** The Yubico tag `AA` in the `AC` template (00 default, 01
never, 02 once, 03 always) is stored with the key (encrypted key object,
`P2KP`) and enforced.  Default = SP 800-73-4 access rule of the slot:

| Slot | Default |
|---|---|
| 9A, 9D, 82–95 | PIN once per session |
| 9C | PIN always: a VERIFY right before each use |
| 9E | None |

"PIN always" is used up by the next GENERAL AUTHENTICATE of **any** slot
(VERIFY → 9A signature → 9C signature is refused).  `AA 04`/`05`
(biometric match) are refused (`6A80`).

**Touch policy.** No button: `AB 00` (default) and `AB 01` (never) are
accepted, `AB 02` (always) and `AB 03` (cached) are refused with `6A80`, so
ykman reports the error.  Metadata always reports touch "never".

**VERIFY P1=FF** (no data) resets the PIN status (SP 800-73-4 §3.2.1).

**GET METADATA (F7)** is implemented: key slots return `01` algorithm, `02`
effective PIN policy + touch `01`, `03` origin `01` (generated; IMPORT is
not implemented), `04` = `86 L <point>`; `80`/`81` return `01 FF`, `05`
default flag, `06` total/remaining retries; `9B` returns `01 03` (3DES),
`02 01 01`, `05` default flag.  Empty slots answer `6A88`.  (ykman only
issues F7 after GET VERSION reports ≥ 5.3, which this applet does not
implement — see deviations.)

**Deviations still open:** no Yubico IMPORT (`FE`), ATTEST (`F9`), GET
VERSION (`FD`) or SET PIN RETRIES; no AES management key; no command
chaining (`CLA 10`); no RSA keys.
