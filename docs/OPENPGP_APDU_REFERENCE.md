# OpenPGP Card 3.4 APDU Reference

Developer reference for implementing the OpenPGP Card Application Specification v3.4 from scratch
in Rust `no_std` firmware. Covers every APDU command, all Data Objects, algorithm attributes,
key slot semantics, and cryptographic operation data formats.

Primary specification: **OpenPGP Smart Card Application 3.4.1**
(`https://www.gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.1.pdf`)

Cross-reference implementations consulted:
- GnuPG `scd/app-openpgp.c` and `scd/iso7816.c`
- OpenSC `src/libopensc/card-openpgp.c` and `card-openpgp.h`
- SmartPGP (`github-af/SmartPGP`) — JavaCard implementation
- `polhenarejos/pico-openpgp` — another RP2040/RP2350 OpenPGP card

---

## Table of Contents

1. [Overview](#1-overview)
2. [Command Summary Table](#2-command-summary-table)
3. [Per-Command Reference](#3-per-command-reference)
4. [Data Objects (DO) Reference](#4-data-objects-do-reference)
5. [Key Slot Reference](#5-key-slot-reference)
6. [Algorithm Attributes Encoding](#6-algorithm-attributes-encoding)
7. [PSO:CDS — Signing Flow](#7-psocds--signing-flow)
8. [PSO:DECIPHER — Decrypt / ECDH Flow](#8-psodecipher--decrypt--ecdh-flow)
9. [PW1 Mode 81 vs Mode 82](#9-pw1-mode-81-vs-mode-82)
10. [Extended Capabilities DO (C0)](#10-extended-capabilities-do-c0)
11. [CHV Status Bytes DO (C4)](#11-chv-status-bytes-do-c4)
12. [Card Lifecycle — TERMINATE / ACTIVATE](#12-card-lifecycle--terminate--activate)
13. [DigestInfo Prefixes for RSA Signing](#13-digestinfo-prefixes-for-rsa-signing)
14. [Public Key Response Format](#14-public-key-response-format)
15. [pico2hsm Implementation Notes](#15-pico2hsm-implementation-notes)

---

## 1. Overview

### 1.1 Application Identifier (AID)

The full 16-byte OpenPGP AID:

```
D2 76 00 01 24 01 VV VV MM MM SS SS SS SS 00 00
                  ├──┤  ├──┤  └──────────┘
                  ver   mfr   serial number
```

| Field | Bytes | Description |
|---|---|---|
| RID | `D2 76 00 01 24` | Registered Application Provider ID |
| Application | `01` | OpenPGP application discriminator |
| Version | `VV VV` | BCD-encoded spec version: `03 04` = v3.4 |
| Manufacturer | `MM MM` | E.g., `00 06` = ZeitControl, `00 09` = Yubico |
| Serial | `SS SS SS SS` | 4-byte serial number |
| RFU | `00 00` | Reserved |

The **AID prefix** (first 6 bytes) used for SELECT matching:
```
D2 76 00 01 24 01
```

### 1.2 Card Capabilities and Lifecycle

An OpenPGP card can be in one of three lifecycle states:

| State | Description |
|---|---|
| **Initialisation** | Post-manufacture, before first personalisation |
| **Operational** | Normal state — commands processed |
| **Terminated** | Locked via TERMINATE DF; re-activatable with ACTIVATE FILE |

The card responds to SELECT AID in all states.

### 1.3 Authentication Model

Three PIN objects control access:

| Object | P2 Reference | Default | Min Len | Max Len | Retry |
|---|---|---|---|---|---|
| **PW1** (User PIN) | `0x81` / `0x82` | `123456` | 6 | 127 | 3 |
| **PW3** (Admin PIN) | `0x83` | `12345678` | 8 | 127 | 3 |
| **Reset Code** (RC) | `0x82` in RESET RETRY | — | 8 | 127 | 3 |

PIN values are UTF-8 encoded byte strings. The card enforces minimum/maximum lengths.

**PW1 has two distinct modes** — see [Section 9](#9-pw1-mode-81-vs-mode-82).

**Retry counter:** Each failed VERIFY decrements the counter. When it reaches zero, the PIN
is blocked. PW1 and RC share a conceptual counter in v1 cards; in v2+ they are independent.
PW3 counter reaching zero permanently blocks the admin PIN (requires TERMINATE + ACTIVATE).

A **VERIFY with empty data** (Lc absent, Le absent) returns the current retry count in SW:
- `0x63 CX` — X remaining retries (e.g., `0x63 C3` = 3 retries)
- `0x9000` — already verified in this session

### 1.4 Key Slot Model

Three asymmetric key slots:

| Slot | Control Ref Tag | Algo DO | Description |
|---|---|---|---|
| **SIG** | `B6` | `C1` | Signature key (used with PSO:CDS) |
| **DEC** | `B8` | `C2` | Decryption / ECDH key (used with PSO:DECIPHER) |
| **AUTH** | `A4` | `C3` | Authentication key (used with INTERNAL AUTHENTICATE) |

Each slot holds one asymmetric key at a time. Keys are generated on-card (INS `0x47`) or
imported (INS `0xDB` with appropriate key template).

---

## 2. Command Summary Table

| INS | CLA | Mnemonic | Description |
|---|---|---|---|
| `0xA4` | `0x00` | SELECT | Select OpenPGP application by AID |
| `0x20` | `0x00` | VERIFY | Verify PW1 (mode 81/82) or PW3 |
| `0x24` | `0x00` | CHANGE REFERENCE DATA | Change PW1 or PW3 |
| `0x2C` | `0x00` | RESET RETRY COUNTER | Unblock PW1 using Reset Code or PW3 |
| `0xCA` | `0x00` | GET DATA | Read a Data Object |
| `0xCB` | `0x00` | GET DATA (odd) | Read constructed/extended DO |
| `0xCC` | `0x00` | GET NEXT DATA | Read next certificate occurrence |
| `0xDA` | `0x00` | PUT DATA | Write a Data Object (even tag) |
| `0xDB` | `0x00` | PUT DATA (odd) | Write a Data Object or key (odd tag) |
| `0x2A` | `0x00` | PSO:CDS | Compute Digital Signature (`P1=9E P2=9A`) |
| `0x2A` | `0x00` | PSO:DECIPHER | Decipher / ECDH (`P1=80 P2=86`) |
| `0x2A` | `0x00` | PSO:ENCIPHER | Encipher (`P1=86 P2=80`) |
| `0x88` | `0x00` | INTERNAL AUTHENTICATE | Internal authentication with AUTH key |
| `0x47` | `0x00` | GENERATE KEY PAIR | Generate or read public key |
| `0x84` | `0x00` | GET CHALLENGE | Get random bytes from card |
| `0xC0` | `0x00` | GET RESPONSE | Retrieve remaining response data |
| `0x22` | `0x00` | MSE | Manage Security Environment (v3.4+) |
| `0xA5` | `0x00` | SELECT DATA | Select certificate occurrence |
| `0xE6` | `0x00` | TERMINATE DF | Terminate the OpenPGP application |
| `0x44` | `0x00` | ACTIVATE FILE | Re-activate / factory reset |

---

## 3. Per-Command Reference

### 3.1 SELECT

Select the OpenPGP application.

```
CLA: 00
INS: A4
P1:  04   (select by AID/name)
P2:  00   (first or only occurrence; return FCI if Le present)
Lc:  06 (or longer)
Data: D2 76 00 01 24 01  [remaining AID bytes optional]
Le:  00   (request FCI response)
```

**Response:** File Control Information (FCI) TLV:
```
6F [len]
  84 [len] <full AID>          -- application AID
  A5 [len]
    9F 6E [len] <version data> -- application version / proprietary data
```

**SW:**
- `90 00` — success
- `6A 82` — application not found (AID mismatch)
- `6E 00` — CLA not supported

**Notes:**
- Sending SELECT resets the session: all PIN verifications are cleared, active key slot
  reverts to none.
- P2=`0x0C` suppresses the FCI response (no Le needed).

---

### 3.2 VERIFY

Verify a PIN. Clears the selected PIN's verified status flag before checking.

```
CLA: 00
INS: 20
P1:  00
P2:  <pw_ref>   -- 81 (PW1 signing), 82 (PW1 other), 83 (PW3)
Lc:  <len>
Data: <PIN bytes>   -- UTF-8 encoded PIN
```

**Query form (no Lc, no data):**
```
CLA: 00  INS: 20  P1: 00  P2: <pw_ref>
```
Returns `63 CX` (X = retries remaining) or `90 00` (already verified).

**SW:**
| SW | Meaning |
|---|---|
| `90 00` | Verified successfully |
| `63 CX` | Wrong PIN, X retries remaining (e.g., `63 C2` = 2 left) |
| `69 83` | PIN blocked (counter exhausted) |
| `69 82` | Security condition not satisfied (wrong mode) |
| `67 00` | Wrong length |
| `6A 86` | Incorrect P2 (unknown reference) |

**Authentication scope:**
- P2=`0x81`: marks PW1-81 as verified for **this APDU exchange only** (signing mode; cleared after each PSO:CDS)
- P2=`0x82`: marks PW1-82 as verified for **the session** (other operations)
- P2=`0x83`: marks PW3 as verified for the session

**PIN reset (P1=0xFF):** Sending P1=`0xFF` clears the verified status without presenting a PIN.
```
CLA: 00  INS: 20  P1: FF  P2: <pw_ref>   -- no Lc/Data
```

---

### 3.3 CHANGE REFERENCE DATA

Change PW1 or PW3. Requires the old PIN followed by the new PIN.

```
CLA: 00
INS: 24
P1:  00
P2:  <pw_ref>   -- 81 (PW1), 83 (PW3)
Lc:  <old_len + new_len>
Data: <old_PIN> <new_PIN>
```

**Exchange mode (P1=01):** New PIN only (used when admin resets PW1):
```
CLA: 00  INS: 24  P1: 01  P2: 81
Lc: <new_len>
Data: <new_PW1>
```
This form requires PW3 to be verified in the session.

**SW:**
| SW | Meaning |
|---|---|
| `90 00` | Changed successfully |
| `63 CX` | Old PIN wrong, X retries remaining |
| `69 83` | PIN blocked |
| `67 00` | Wrong length (too short or split wrong) |
| `69 82` | Conditions not satisfied (for exchange mode: PW3 not verified) |

---

### 3.4 RESET RETRY COUNTER

Unblock PW1. Two forms:

**Form 1 — with Reset Code (P1=00):**
```
CLA: 00
INS: 2C
P1:  00
P2:  81   (PW1 is the only unblockable PIN)
Lc:  <rc_len + new_pw1_len>
Data: <Reset_Code> <new_PW1>
```
The Reset Code is verified; if correct, PW1 is reset to `new_PW1` and the retry counter
is restored to its maximum.

**Form 2 — with PW3 authority (P1=02):**
```
CLA: 00
INS: 2C
P1:  02
P2:  81
Lc:  <new_pw1_len>
Data: <new_PW1>
```
Requires PW3 to be verified in the session. No Reset Code needed.

**SW:**
| SW | Meaning |
|---|---|
| `90 00` | Reset successful |
| `63 CX` | Wrong Reset Code (form 1), X retries left |
| `69 83` | Reset Code blocked (form 1) |
| `69 82` | PW3 not verified (form 2) |
| `67 00` | Wrong length |

---

### 3.5 GET DATA

Read a Data Object by tag.

```
CLA: 00
INS: CA         (even GET DATA; most DOs)
P1:  <tag_high> -- high byte of 2-byte tag (00 for single-byte tags)
P2:  <tag_low>  -- low byte of tag
Le:  00         (or 00 00 for extended length)
```

For constructed DOs that require BER-TLV encoding in the command data:
```
CLA: 00
INS: CB         (odd GET DATA)
P1:  <tag_high>
P2:  <tag_low>
Lc:  02
Data: 5C 00    -- empty tag list (return all)
Le:  00 00
```

**Response:** raw value bytes for simple DOs; BER-TLV structure for constructed DOs.

**SW:**
| SW | Meaning |
|---|---|
| `90 00` | Success |
| `61 XX` | More data — use GET RESPONSE with Le=XX |
| `6A 88` | Referenced data not found (DO empty) |
| `6A 82` | File/application not found |
| `69 82` | Security status not satisfied (PIN-protected DO) |
| `6C XX` | Wrong Le; XX = correct length |

**Important DOs and their tags:** See [Section 4](#4-data-objects-do-reference).

---

### 3.6 PUT DATA

Write a Data Object.

**Even form (INS=DA)** — for most simple DOs:
```
CLA: 00
INS: DA
P1:  <tag_high>
P2:  <tag_low>
Lc:  <len>
Data: <value>
```

**Odd form (INS=DB)** — for constructed DOs and key import:
```
CLA: 00
INS: DB
P1:  <tag_high>
P2:  <tag_low>
Lc:  <len>
Data: <BER-TLV encoded value>
```

Key import uses INS=`0xDB` with the appropriate private key template tag
(`B6` for SIG, `B8` for DEC, `A4` for AUTH).

**SW:**
| SW | Meaning |
|---|---|
| `90 00` | Written successfully |
| `69 82` | Security condition not satisfied (PW3 not verified for protected DOs) |
| `67 00` | Wrong length |
| `6A 80` | Incorrect parameters in command data |
| `6A 88` | Referenced data not found |
| `65 81` | Memory failure |

**Access conditions by DO:** See [Section 4](#4-data-objects-do-reference).

---

### 3.7 PSO: COMPUTE DIGITAL SIGNATURE (CDS)

Sign a pre-hashed message. Uses the SIG key slot.

```
CLA: 00
INS: 2A
P1:  9E
P2:  9A
Lc:  <len>
Data: <DigestInfo_or_hash>   -- see Section 7
Le:  00 (or 00 00 for extended)
```

**Response:** raw signature bytes (see [Section 7](#7-psocds--signing-flow) for format).

**SW:**
| SW | Meaning |
|---|---|
| `90 00` | Signature computed |
| `69 82` | PW1 (mode 81 or 82) not verified |
| `69 85` | No key in SIG slot |
| `67 00` | Wrong Lc (data length mismatch for algorithm) |
| `61 XX` | Response too long; use GET RESPONSE |

**Prior auth:** PW1 verified with P2=`0x81` **or** P2=`0x82`. After PSO:CDS, if PW1 was
verified with mode `0x81`, the flag is **cleared** (one-shot). See [Section 9](#9-pw1-mode-81-vs-mode-82).

---

### 3.8 PSO: DECIPHER

Decrypt RSA ciphertext or perform ECDH. Uses the DEC key slot.

```
CLA: 00
INS: 2A
P1:  80
P2:  86
Lc:  <len>
Data: <padding_indicator_byte> <ciphertext_or_ecdh_data>
Le:  00
```

**Prior auth:** PW1 (mode 82) must be verified. See [Section 8](#8-psodecipher--decrypt--ecdh-flow).

**SW:** Same set as PSO:CDS with same semantics.

---

### 3.9 PSO: ENCIPHER

Symmetric encryption (AES). Not used for asymmetric operations.

```
CLA: 00
INS: 2A
P1:  86
P2:  80
Lc:  <len>
Data: <plaintext>   -- must be block-aligned (multiple of 16 bytes for AES)
Le:  00
```

**Response:** `02 <ciphertext>` — the first byte `0x02` is the mode indicator.

**Prior auth:** PW1 (mode 82).

---

### 3.10 INTERNAL AUTHENTICATE

Authenticate using the AUTH key slot. Used by SSH, TLS client auth.

```
CLA: 00
INS: 88
P1:  00
P2:  00
Lc:  <len>
Data: <challenge_or_hash>   -- typically a hash (SHA-256, etc.) of a challenge
Le:  00
```

**Response:** raw signature over the input. For RSA, a PKCS#1 v1.5 signature without DigestInfo
wrapping (the card signs the raw input). For ECDSA, raw `r || s`. For Ed25519, raw 64-byte
signature.

**Prior auth:** PW1 (mode 82) must be verified.

**SW:** Same set as PSO:CDS.

**Note:** Unlike PSO:CDS, INTERNAL AUTHENTICATE uses the **AUTH** key (slot `A4`), not the SIG
key. It does not increment the signature counter.

---

### 3.11 GENERATE ASYMMETRIC KEY PAIR

Generate a new key pair or read back the public key of an existing key.

```
CLA: 00
INS: 47
P1:  80   (generate new key — PW3 required)
  or 81   (read existing public key — no PIN required)
P2:  00
Lc:  02 (or more)
Data: <CRT_template>   -- 2-byte Control Reference Template tag
Le:  00 00             (extended length — response may be large)
```

**Control Reference Template tags** (P1=`0x80` generates; P1=`0x81` reads):

| Key Slot | CRT Template Bytes |
|---|---|
| SIG | `B6 00` |
| DEC | `B8 00` |
| AUTH | `A4 00` |

Example — generate SIG key pair:
```
00 47 80 00 02 B6 00 00 00
```
Example — read DEC public key:
```
00 47 81 00 02 B8 00 00 00
```

**Response format:** `7F 49 [len] <public_key_TLV>`

For RSA:
```
7F 49 [len]
  81 [n_len_hi n_len_lo] <N>   -- modulus
  82 [e_len] <E>               -- public exponent
```

For ECC (ECDSA/ECDH):
```
7F 49 [len]
  86 [point_len] <04 X Y>     -- uncompressed public point (04 = uncompressed prefix)
```

For Ed25519 / X25519:
```
7F 49 [len]
  86 [20]h <public_key_bytes>  -- 32 bytes, native format (no 04 prefix)
```

**SW:**
| SW | Meaning |
|---|---|
| `90 00` | Success |
| `69 82` | PW3 not verified (for generation) |
| `6A 88` | No key present (for read with P1=81) |
| `6F 00` | Key generation failed |

---

### 3.12 GET CHALLENGE

Get random bytes from the card's hardware RNG.

```
CLA: 00
INS: 84
P1:  00
P2:  00
Le:  <N>   -- number of random bytes requested (max per spec: 254 for short, more with extended)
```

**Response:** N random bytes.

**SW:**
- `90 00` — success
- `6A 81` — function not supported (if EXT_CAP_GET_CHALLENGE not set)
- `67 00` — Le too large

**Max length:** Advertised in Extended Capabilities DO (`C0`) bytes 4–5.
If the GET_CHALLENGE capability bit is not set in `C0`, this command returns `6A 81`.

---

### 3.13 GET RESPONSE

Retrieve remaining response data after a `61 XX` SW.

```
CLA: 00
INS: C0
P1:  00
P2:  00
Le:  <XX>   -- from SW2 of the preceding 61 XX response
```

**Response:** next chunk of data.

**SW:**
- `90 00` — last chunk
- `61 XX` — more data remains; repeat

---

### 3.14 SELECT DATA

Select which certificate to retrieve (for cards supporting multiple certificates per slot, v3.4+).

```
CLA: 00
INS: A5
P1:  <n>   -- 0-based occurrence index (0x00 = first, 0x01 = second, ...)
P2:  04
Lc:  06
Data: 60 04 5C 02 7F 21   -- select DO 7F21 (cardholder certificate)
```

**SW:**
- `90 00` — selected
- `6A 88` — occurrence not found

After SELECT DATA, GET DATA for tag `7F 21` returns the selected certificate.

---

### 3.15 MANAGE SECURITY ENVIRONMENT (MSE)

Available in v3.4+ when `EXT_CAP_MSE` bit is set. Allows overriding which key slot is active
for the next cryptographic operation.

```
CLA: 00
INS: 22
P1:  41   (set for security operation — computation)
  or 81   (set for verification — decryption/authentication)
P2:  B6   (SIG slot) or B8 (DEC slot) or A4 (AUTH slot)
Lc:  <len>
Data: <algorithm_reference_TLV>
```

Typical usage (select SIG key for signing):
```
00 22 41 B6 00
```

**SW:**
- `90 00` — environment set
- `69 82` — not authorized

---

### 3.16 TERMINATE DF

Locks the application. All commands except SELECT and ACTIVATE FILE are rejected.

```
CLA: 00
INS: E6
P1:  00
P2:  00
```

**Precondition:** PW3 must be verified, **or** the PW3 retry counter must be zero
(i.e., card is in a fully blocked state — allows recovery via bricking).

**SW:**
- `90 00` — terminated
- `69 82` — security condition not satisfied

---

### 3.17 ACTIVATE FILE

Re-activate (factory reset) the application after TERMINATE DF. Erases all keys and PINs,
resets retry counters, restores factory defaults.

```
CLA: 00
INS: 44
P1:  00
P2:  00   (full reset)
  or 01   (partial reset — some implementations)
```

**SW:**
- `90 00` — activated / reset
- `69 85` — conditions not satisfied (not in terminated state)

---

## 4. Data Objects (DO) Reference

All DOs are accessed via GET DATA (INS=`CA`/`CB`) using their 2-byte tag.
P1 = high byte of tag, P2 = low byte of tag.

**Access condition abbreviations:**
- `ALWAYS` — no PIN required
- `PW1-81` — PW1 verified with mode 81 (signing)
- `PW1-82` — PW1 verified with mode 82 (other operations)
- `PW3` — PW3 (admin) verified
- `NEVER` — not readable via GET DATA (internal only)

### 4.1 Simple / Primitive DOs

| Tag | Name | Read | Write | Len | Description |
|---|---|---|---|---|---|
| `00 4F` | Application Identifier (AID) | ALWAYS | NEVER | 16 | Full 16-byte AID |
| `00 5B` | Cardholder Name | ALWAYS | PW3 | 0–39 | UTF-8 name string |
| `00 5E` | Login Data | ALWAYS | PW3 | 0–254 | Arbitrary login bytes |
| `5F 2D` | Language Preference | ALWAYS | PW3 | 2–8 | ISO 639-1 code(s), e.g., `en` |
| `5F 35` | Sex | ALWAYS | PW3 | 1 | `31`=male, `32`=female, `39`=unspecified |
| `5F 50` | URL | ALWAYS | PW3 | 0–254 | UTF-8 URL string |
| `5F 52` | Historical Bytes | ALWAYS | NEVER | var | ATR historical bytes |
| `00 93` | Digital Signature Counter | ALWAYS | NEVER | 3 | Big-endian 24-bit, increments each PSO:CDS |
| `00 C0` | Extended Capabilities | ALWAYS | NEVER | 10 | Feature flags — see Section 10 |
| `00 C1` | Algorithm Attrs SIG | ALWAYS | PW3 | 6–12 | Algo attrs for SIG key slot |
| `00 C2` | Algorithm Attrs DEC | ALWAYS | PW3 | 6–12 | Algo attrs for DEC key slot |
| `00 C3` | Algorithm Attrs AUTH | ALWAYS | PW3 | 6–12 | Algo attrs for AUTH key slot |
| `00 C4` | PW Status Bytes | ALWAYS | PW3 | 7 | PIN lengths and retry counters — see Section 11 |
| `00 C5` | Key Fingerprints | ALWAYS | PW3 | 60 | Three 20-byte SHA-1 key fingerprints (SIG, DEC, AUTH) |
| `00 C6` | CA Fingerprints | ALWAYS | PW3 | 60 | Three 20-byte CA fingerprints |
| `00 C7` | Fingerprint SIG | ALWAYS | PW3 | 20 | SHA-1 fingerprint of SIG key |
| `00 C8` | Fingerprint DEC | ALWAYS | PW3 | 20 | SHA-1 fingerprint of DEC key |
| `00 C9` | Fingerprint AUTH | ALWAYS | PW3 | 20 | SHA-1 fingerprint of AUTH key |
| `00 CA` | CA Fingerprint 1 | ALWAYS | PW3 | 20 | CA fingerprint 1 |
| `00 CB` | CA Fingerprint 2 | ALWAYS | PW3 | 20 | CA fingerprint 2 |
| `00 CC` | CA Fingerprint 3 | ALWAYS | PW3 | 20 | CA fingerprint 3 |
| `00 CE` | Key Generation Date SIG | ALWAYS | PW3 | 4 | Unix timestamp (big-endian, seconds) |
| `00 CF` | Key Generation Date DEC | ALWAYS | PW3 | 4 | Unix timestamp |
| `00 D0` | Key Generation Date AUTH | ALWAYS | PW3 | 4 | Unix timestamp |
| `00 D3` | Reset Retry Counter | NEVER | PW3 | 8–127 | Write sets the Reset Code |
| `00 D5` | AES Key | NEVER | PW3 | 16/24/32 | AES key for PSO:ENCIPHER (v3+) |
| `00 D6` | UIF SIG | ALWAYS | PW3 | 2 | User Interaction Flag for SIG (button confirm) |
| `00 D7` | UIF DEC | ALWAYS | PW3 | 2 | User Interaction Flag for DEC |
| `00 D8` | UIF AUTH | ALWAYS | PW3 | 2 | User Interaction Flag for AUTH |
| `00 DE` | Key Information | ALWAYS | NEVER | 6 | Key origin/status for each slot (v3.4+) |
| `00 F9` | KDF Data Object | ALWAYS | PW3 | 0 or 90–110 | Key Derivation Function params (v3.3+) |
| `00 FA` | Algorithm Information | ALWAYS | NEVER | var | List of supported algorithm attrs (v3.4+) |

### 4.2 Constructed DOs

| Tag | Name | Read | Write | Description |
|---|---|---|---|---|
| `00 65` | Cardholder Related Data | ALWAYS | — | Constructed: contains `5B`, `5F 2D`, `5F 35` |
| `00 6E` | Application Related Data | ALWAYS | — | Constructed: AID, version, ext caps, key fingerprints, etc. |
| `00 73` | Discretionary Data Objects | ALWAYS | — | Contained within `6E`; holds `C0`–`C6`, `CD` |
| `00 7A` | Security Support Template | ALWAYS | — | Constructed: contains `93` (sig counter) |
| `7F 21` | Cardholder Certificate | PW1-82 | PW3 | X.509 certificate for SIG/DEC/AUTH key (selectable) |
| `7F 49` | Public Key Template | ALWAYS | — | Response from GENERATE KEY PAIR; `81`/`82` (RSA) or `86` (ECC) |

### 4.3 Private DOs

| Tag | Name | Read | Write | Len | Description |
|---|---|---|---|---|---|
| `01 01` | Private DO 1 | ALWAYS | PW1-82 | 0–254 | Arbitrary user data |
| `01 02` | Private DO 2 | ALWAYS | PW3 | 0–254 | Arbitrary admin data |
| `01 03` | Private DO 3 | PW1-82 | PW3 | 0–254 | PIN-protected user data |
| `01 04` | Private DO 4 | PW3 | PW3 | 0–254 | Admin-only data |

---

## 5. Key Slot Reference

### 5.1 SIG Key — Tag `B6`

- **Purpose:** OpenPGP data signing (email, document, git commit)
- **Command:** PSO:CDS (`2A 9E 9A`)
- **Auth required:** PW1 (mode 81 or 82)
- **Algo DO:** `C1`
- **Fingerprint:** bytes 0–19 of DO `C5`; also directly in DO `C7`
- **Generation date:** DO `CE` (4-byte Unix timestamp)
- **UIF:** DO `D6` — if enabled, card waits for physical button press before signing
- **Signature counter DO `93`:** increments by 1 after each successful PSO:CDS call

**SIG key import template (for PUT DATA, INS=DB, tag=B6):**
```
B6 [len]
  <private_key_TLV>     -- RSA: CRT components; ECC: private scalar
```
For RSA-CRT import (big-endian):
```
B6 [len]
  7F 48 [template_len]     -- private key reference template
    91 [len] E              -- public exponent E
    92 [len] P              -- prime P
    93 [len] Q              -- prime Q
    94 [len] Qinv           -- Q^-1 mod P
    95 [len] DP1            -- D mod (P-1)
    96 [len] DQ1            -- D mod (Q-1)
  5F 48 [key_data_len]     -- concatenated key values
    <E><P><Q><Qinv><DP1><DQ1>
```
For ECC import:
```
B6 [len]
  7F 48 [template_len]
    92 [len] <private_scalar>
  5F 48 [key_data_len]
    <private_scalar_bytes>
```

### 5.2 DEC Key — Tag `B8`

- **Purpose:** Decrypt messages (RSA PKCS#1 v1.5) or perform ECDH key agreement
- **Command:** PSO:DECIPHER (`2A 80 86`)
- **Auth required:** PW1 (mode 82)
- **Algo DO:** `C2`
- **Fingerprint:** bytes 20–39 of DO `C5`; also in DO `C8`
- **Generation date:** DO `CF`
- **UIF:** DO `D7`

For ECDH keys (X25519 or ECDH with NIST curves), the card performs key agreement using its
private key and the ephemeral public key supplied in PSO:DECIPHER.

### 5.3 AUTH Key — Tag `A4`

- **Purpose:** SSH authentication, TLS client auth
- **Command:** INTERNAL AUTHENTICATE (`88 00 00`)
- **Auth required:** PW1 (mode 82)
- **Algo DO:** `C3`
- **Fingerprint:** bytes 40–59 of DO `C5`; also in DO `C9`
- **Generation date:** DO `D0`
- **UIF:** DO `D8`

The AUTH key never increments the signature counter.

---

## 6. Algorithm Attributes Encoding

Algorithm attributes are stored in DOs `C1` (SIG), `C2` (DEC), `C3` (AUTH).
Written via PUT DATA (PW3 required). Read via GET DATA (no auth).

### 6.1 RSA

```
Byte 0:     01          -- algorithm ID: RSA
Bytes 1–2:  <n_bits>    -- modulus size in bits, big-endian (e.g., 08 00 = 2048)
Bytes 3–4:  <e_bits>    -- public exponent size in bits (e.g., 00 11 = 17 bits)
Byte 5:     <format>    -- 00=standard, 02=CRT, 03=CRT with N
```

**Exact byte arrays for supported RSA key sizes:**

| Key Size | Algorithm Attributes Bytes |
|---|---|
| RSA-2048 | `01 08 00 00 11 00` |
| RSA-3072 | `01 0C 00 00 11 00` |
| RSA-4096 | `01 10 00 00 11 00` |

Public exponent `e = 65537` → 17 bits → `00 11` in bytes 3–4.

Format byte `00` = standard (d, n); `02` = CRT (p, q, Qinv, DP1, DQ1).
CRT format (`02`) is preferred for key import.

### 6.2 ECDSA (for SIG or AUTH)

```
Byte 0:     13          -- algorithm ID: ECDSA
Bytes 1–N:  <OID>       -- DER OID value bytes (without tag 06 and length byte)
Byte N+1:   00 or FF    -- 00=no import, FF=public key import supported
```

**OID bytes for each supported NIST curve:**

| Curve | OID (DER value bytes only) | Full Attribute Bytes |
|---|---|---|
| P-256 | `2A 86 48 CE 3D 03 01 07` | `13 2A 86 48 CE 3D 03 01 07 00` |
| P-384 | `2B 81 04 00 22` | `13 2B 81 04 00 22 00` |
| P-521 | `2B 81 04 00 23` | `13 2B 81 04 00 23 00` |

The trailing `00` means key import is not supported. Change to `FF` to signal that the card
accepts imported ECC public keys.

### 6.3 ECDH (for DEC)

```
Byte 0:     12          -- algorithm ID: ECDH
Bytes 1–N:  <OID>       -- same OID encoding as ECDSA
Byte N+1:   00 or FF    -- import flag
```

**Full attribute bytes:**

| Curve | Algorithm Attributes Bytes |
|---|---|
| ECDH P-256 | `12 2A 86 48 CE 3D 03 01 07 00` |
| ECDH P-384 | `12 2B 81 04 00 22 00` |
| ECDH P-521 | `12 2B 81 04 00 23 00` |

To allow import (write `FF` as last byte):

| Curve | Algorithm Attributes (import allowed) |
|---|---|
| ECDH P-256 (import) | `12 2A 86 48 CE 3D 03 01 07 FF` |

### 6.4 EdDSA — Ed25519 (for SIG or AUTH)

Ed25519 uses algorithm ID `0x16` (EdDSA). The OID is from OpenPGP's extended ECC registry
(not the standard RFC 8410 OID `2B 65 70`; OpenPGP cards use a different OID).

```
Byte 0:     16          -- algorithm ID: EdDSA
Bytes 1–9:  2B 06 01 04 01 DA 47 0F 01   -- Ed25519 OID (OpenPGP registry)
```

**Full attribute bytes for Ed25519:**
```
16 2B 06 01 04 01 DA 47 0F 01
```

This OID (`1.3.6.1.4.1.11591.15.1`) is used by GnuPG for Ed25519 on OpenPGP cards.

**Note on RFC 8410 OID vs OpenPGP OID:**
RFC 8410 defines `1.3.101.112` (`2B 65 70`) for Ed25519, but OpenPGP card implementations
historically use the GnuPG OID above. Check what GnuPG's scdaemon actually sends when setting
the algorithm attribute — some newer implementations accept both.

### 6.5 X25519 / Curve25519 (for DEC)

X25519 (Montgomery curve, used for ECDH) uses algorithm ID `0x12` (ECDH) with the Curve25519
OpenPGP OID:

```
Byte 0:     12          -- algorithm ID: ECDH
Bytes 1–10: 2B 06 01 04 01 97 55 01 05 01   -- Curve25519 OID (OpenPGP registry)
```

**Full attribute bytes for X25519:**
```
12 2B 06 01 04 01 97 55 01 05 01
```

This OID (`1.3.6.1.4.1.3029.1.5.1`) is the Bernstein/djb Curve25519 OID used by GnuPG.

**RFC 8410 OID** for X25519 is `1.3.101.110` (`2B 65 6E`) — again, OpenPGP cards traditionally
use the djb OID above.

### 6.6 Algorithm OID Summary

| Algorithm | OID (hex value bytes) | Card Algo ID |
|---|---|---|
| P-256 (secp256r1) | `2A 86 48 CE 3D 03 01 07` | `12` or `13` |
| P-384 (secp384r1) | `2B 81 04 00 22` | `12` or `13` |
| P-521 (secp521r1) | `2B 81 04 00 23` | `12` or `13` |
| Ed25519 (OpenPGP) | `2B 06 01 04 01 DA 47 0F 01` | `16` |
| X25519 (OpenPGP) | `2B 06 01 04 01 97 55 01 05 01` | `12` |

---

## 7. PSO:CDS — Signing Flow

### 7.1 Prerequisites

1. SIG key present in slot (generated or imported).
2. Algorithm attributes DO `C1` set correctly for the key type.
3. PW1 verified (mode `81` or `82`) — see [Section 9](#9-pw1-mode-81-vs-mode-82).

No MSE command is required; the card always uses the SIG key for PSO:CDS.

### 7.2 Input Data Format

**The card does NOT hash the data.** The host must pre-hash the message and send the hash
(or DigestInfo) to the card.

#### RSA signing

The host sends a **DigestInfo** structure (PKCS#1 v1.5 encoding):
```
DigestInfo ::= SEQUENCE {
    digestAlgorithm AlgorithmIdentifier,
    digest OCTET STRING
}
```
See [Section 13](#13-digestinfo-prefixes-for-rsa-signing) for the exact byte prefixes per hash algorithm.

Example for SHA-256 (32-byte hash):
```
30 31 30 0D 06 09 60 86 48 01 86 F8 42 01 05 00 05 00 04 20 <32 hash bytes>
```

#### ECDSA signing (P-256, P-384, P-521)

Send the raw hash bytes only — **no DigestInfo wrapping**:
```
<hash_bytes>   -- e.g., 32 bytes for SHA-256 (ECDSA P-256)
```

Use a hash output length matching the curve's security strength:
- P-256: SHA-256 (32 bytes)
- P-384: SHA-384 (48 bytes)
- P-521: SHA-512 (64 bytes) — or SHA-512 truncated to 66 bytes; card may accept 64

#### Ed25519 signing

Send the raw message hash (or the full message if the card supports prehash mode):
```
<hash_bytes>   -- typically SHA-512 (64 bytes) of the message
```

GnuPG sends SHA-512(message) for Ed25519 signing. The card applies the Ed25519 algorithm
internally (which re-hashes internally per the Ed25519 spec, so this results in double-hashing).
**Implementation note:** check your host-side library's behavior — GnuPG scdaemon sends
SHA-512 of the data to PSO:CDS for Ed25519 keys.

### 7.3 APDU

```
00 2A 9E 9A [Lc] <data> 00
```
For extended length (large RSA keys, Ed25519):
```
00 2A 9E 9A 00 [Lc_hi Lc_lo] <data> 00 00
```

### 7.4 Response Signature Format

| Algorithm | Response Format |
|---|---|
| RSA-2048 | 256 raw bytes (big-endian integer, PKCS#1 v1.5 padded result) |
| RSA-3072 | 384 raw bytes |
| RSA-4096 | 512 raw bytes |
| ECDSA P-256 | 64 raw bytes: `r` (32 bytes) `||` `s` (32 bytes) |
| ECDSA P-384 | 96 raw bytes: `r` (48 bytes) `||` `s` (48 bytes) |
| ECDSA P-521 | 132 raw bytes: `r` (66 bytes) `||` `s` (66 bytes) |
| Ed25519 | 64 raw bytes: native Ed25519 signature |

**Note:** ECDSA response is raw `r || s`, **not** DER-encoded. The host must convert to DER
if required (e.g., for TLS or X.509).

### 7.5 Signature Counter Behavior

- DO `93` (3-byte big-endian, max `FF FF FF`) increments by 1 for each **successful** PSO:CDS.
- Counter is read-only; it cannot be written via PUT DATA.
- Counter does NOT increment for INTERNAL AUTHENTICATE.
- Counter survives power cycles (stored in non-volatile flash).
- At `FF FF FF`, behavior is implementation-defined (some cards wrap to zero, some block).

---

## 8. PSO:DECIPHER — Decrypt / ECDH Flow

### 8.1 Prerequisites

1. DEC key present in slot.
2. Algorithm attributes DO `C2` set correctly.
3. PW1 (mode 82) verified in current session.

### 8.2 Padding Indicator Byte

The first byte of the command data field is the **padding indicator byte**, which tells the
card how to interpret the remaining bytes:

| Value | Meaning |
|---|---|
| `00` | RSA PKCS#1 v1.5 — ciphertext follows directly |
| `02` | AES symmetric decipher |
| `A6` | ECDH — structured TLV follows (see below) |

### 8.3 RSA Decryption

```
00 2A 80 86 [Lc] 00 <RSA_ciphertext> 00
```

- `Lc` = key_size_bytes + 1 (for the `00` padding indicator)
- For RSA-2048: Lc = 257 (1 indicator + 256 ciphertext bytes)
- The ciphertext is PKCS#1 v1.5 encrypted (as produced by host-side `RSA_public_encrypt`)
- Response: decrypted plaintext (PKCS#1 padding stripped by card)

### 8.4 ECDH Key Agreement (NIST curves)

For ECDH with P-256/P-384/P-521, data is wrapped in TLV:

```
00 2A 80 86 [Lc] A6 [outer_len]
                   7F 49 [inner_len]
                     86 [point_len] 04 <X> <Y>   -- uncompressed ephemeral public point
                 00
```

- Padding indicator byte is implicit in the `A6` tag (the `A6` byte IS the indicator).
- Wait — the `A6` tag **is** the padding indicator byte (value `0xA6`) followed by TLV content.
- `04` prefix in `86` value = uncompressed point format.

Concrete example for ECDH P-256 (ephemeral pubkey = 65 bytes uncompressed):
```
00 2A 80 86 00 00 48
  A6 46
    7F 49 43
      86 41 04 <32 bytes X> <32 bytes Y>
  00 00
```

**Response:** ECDH shared secret (raw bytes, big-endian for NIST curves).

### 8.5 X25519 Key Agreement

For X25519, the public key is 32 bytes (native Curve25519 format, no `04` prefix):

```
00 2A 80 86 [Lc] A6 [outer_len]
                   7F 49 [inner_len]
                     86 [20h] <32 bytes of ephemeral X25519 public key>
                 00
```

**Response:** 32-byte ECDH shared secret (raw X25519 output).

---

## 9. PW1 Mode 81 vs Mode 82

PW1 (the user PIN) has two verification modes with different persistence:

### Mode 81 — Signing PIN (one-shot)

- **P2 = `0x81`** in VERIFY
- Authorises PSO:CDS: **one** call when PW1 status byte 1 (DO `C4`) is
  `00` (the default), **several** when it is `01`
- With `C4` = `00` the verified flag is cleared after each signature
- `C4` byte 1 is written with PUT DATA `C4` (PW3)
- This is the default mode GnuPG uses for signing

### Mode 82 — Session PIN (persistent)

- **P2 = `0x82`** in VERIFY
- Stays verified for the **entire session** (until SELECT, power cycle, or explicit reset)
- Required for PSO:DECIPHER, INTERNAL AUTHENTICATE, and other non-signing operations
- Does **not** authorise PSO:CDS (OpenPGP Card 3.4 §7.2.10; pico2hsm since 2026-10, audit S-14)

### Which commands require which mode:

| Command | PW1-81 sufficient | PW1-82 required |
|---|---|---|
| PSO:CDS | Yes (one-shot, or several with `C4` = `01`) | No — mode 82 never signs |
| PSO:DECIPHER | No | Yes |
| INTERNAL AUTHENTICATE | No | Yes |
| GET DATA (protected) | No | Yes |
| PUT DATA (PW1 writable DOs) | No | Yes |
| PSO:ENCIPHER | No | Yes |

**Implementation:**
```
// Pseudo-code for tracking verification state
struct PinState {
    pw1_81_verified: bool,  // cleared after each PSO:CDS
    pw1_82_verified: bool,  // cleared on SELECT or power cycle
    pw3_verified: bool,     // cleared on SELECT or power cycle
}
```

**Clearing on SELECT:** ISO 7816-4 requires all security state to reset on SELECT. After a
SELECT AID, all three flags must be cleared.

---

## 10. Extended Capabilities DO (C0)

10-byte DO at tag `00 C0`. Read-only. Describes card capabilities to the host.

### Byte 0 — Feature Flags

| Bit | Mask | Name | Description |
|---|---|---|---|
| 0 | `01` | KDF_DO | KDF Data Object supported (v3.3+) |
| 1 | `02` | AES | AES key for PSO:ENCIPHER supported |
| 2 | `04` | ALG_ATTR_CHANGEABLE | Algorithm attributes DOs (C1–C3) are writable |
| 3 | `08` | PRIVATE_DOs | Private DOs (`0101`–`0104`) supported |
| 4 | `10` | C4_CHANGEABLE | PW Status Bytes (C4) are writable |
| 5 | `20` | KEY_IMPORT | Key import via PUT DATA (INS=DB) supported |
| 6 | `40` | GET_CHALLENGE | GET CHALLENGE supported |
| 7 | `80` | SM | Secure Messaging supported |

### Byte 1 — Extended Feature Flags

| Bit | Mask | Name | Description |
|---|---|---|---|
| 0 | `01` | (reserved) | — |
| 1–2 | `06` | SM_ALGO | SM algorithm: `00`=3DES, `01`=AES-128, `02`=AES-256 |
| 3 | `08` | PIN_BLK2 | PIN Block 2 format supported |
| 4 | `10` | MSE | MSE command (INS=22) supported |
| 5–7 | `E0` | (reserved) | — |

### Bytes 2–3 — Max GET CHALLENGE Size

Big-endian 16-bit value: maximum bytes returnable by GET CHALLENGE per call.
Typical value: `00 FE` (254 bytes) for short APDU cards.

### Bytes 4–5 — Max Certificate Length

Big-endian 16-bit value: maximum bytes for a stored cardholder certificate (DO `7F 21`).
Typical value: `04 80` (1152 bytes) or larger.

### Bytes 6–7 — Max Special DO Size

Big-endian 16-bit value: maximum size of special DOs (e.g., private DOs).

### Bytes 8–9 — Max CC DO Size / Reserved

Implementation-specific; often `00 00` or max APDU command data size.

### Example Extended Capabilities Bytes

A card with full feature support:
```
F7 03 00 FE 04 80 00 FF 00 00
```
Decoded:
- Byte 0: `F7` = `1111 0111` = SM + GET_CHALLENGE + KEY_IMPORT + C4_CHANGEABLE + PRIVATE_DOs + ALG_ATTR_CHANGEABLE + AES (KDF bit clear)
- Byte 1: `03` = `0000 0011` = MSE + PIN_BLK2 (bits 3 and 4 set... confirm exact encoding against spec)
- Bytes 2–3: `00 FE` = 254 bytes max challenge
- Bytes 4–5: `04 80` = 1152 bytes max cert

---

## 11. CHV Status Bytes DO (C4)

7-byte DO at tag `00 C4`. Contains PIN configuration and retry counters.

```
Byte 0: <format>        -- 00 = UTF-8 PINs; 01 = block 2 format PIN padding
Byte 1: <pw1_max_len>   -- max PW1 length (e.g., 7F = 127)
Byte 2: <rc_max_len>    -- max Reset Code length (e.g., 7F = 127)
Byte 3: <pw3_max_len>   -- max PW3 length (e.g., 7F = 127)
Byte 4: <pw1_retries>   -- PW1 retry counter (3 = not blocked, 0 = blocked)
Byte 5: <rc_retries>    -- Reset Code retry counter
Byte 6: <pw3_retries>   -- PW3 retry counter
```

**Typical factory default value:**
```
00 7F 7F 7F 03 00 03
```
- Format: UTF-8 PINs
- All max lengths: 127
- PW1 retries: 3, RC: 0 (no Reset Code set), PW3 retries: 3

Writing DO `C4` (PW3 required) allows changing the format byte (to enable PIN Block 2 if
`EXT_CAP_PIN_BLK2` is set). The retry counters are read-only via PUT DATA.

---

## 12. Card Lifecycle — TERMINATE / ACTIVATE

### Normal Flow

```
[Factory] → SELECT → ACTIVATE FILE (if needed) → Operational
     Operational → TERMINATE DF → Terminated
     Terminated → ACTIVATE FILE → Factory Reset (Operational, all data wiped)
```

### TERMINATE DF (INS `E6`)

Conditions for TERMINATE to succeed:
1. PW3 verified in current session, **or**
2. PW3 retry counter has reached zero (allows recovery of blocked card)

After TERMINATE, all commands except SELECT and ACTIVATE FILE return `69 85`.

### ACTIVATE FILE (INS `44`)

- Accepted in Terminated state (and sometimes Initialisation state)
- **Erases all keys, PINs, DOs** (except possibly some manufacturer data)
- Resets retry counters to factory defaults (PW1=3, RC=0, PW3=3)
- Resets all algorithm attributes to default RSA-2048
- Returns card to Operational state with factory PIN values

**Recovery from blocked PW3:**
```
// 1. TERMINATE DF (no auth needed if PW3 counter = 0):
00 E6 00 00

// 2. ACTIVATE FILE (no auth needed):
00 44 00 00

// Card is now reset to factory state
```

---

## 13. DigestInfo Prefixes for RSA Signing

When using PSO:CDS with an RSA key, the host must prepend the DER-encoded DigestInfo
algorithm identifier to the hash bytes before sending.

The full data sent = `DigestInfo_prefix + hash_bytes`.

| Hash | Hash Length | DigestInfo Prefix (hex) | Total Lc |
|---|---|---|---|
| SHA-1 | 20 bytes | `30 21 30 09 06 05 2B 0E 03 02 1A 05 00 04 14` | 35 |
| SHA-224 | 28 bytes | `30 2D 30 0D 06 09 60 86 48 01 86 F8 42 01 0E 05 00 04 1C` | 47 |
| SHA-256 | 32 bytes | `30 31 30 0D 06 09 60 86 48 01 86 F8 42 01 05 05 00 04 20` | 51 |
| SHA-384 | 48 bytes | `30 41 30 0D 06 09 60 86 48 01 86 F8 42 01 0C 05 00 04 30` | 67 |
| SHA-512 | 64 bytes | `30 51 30 0D 06 09 60 86 48 01 86 F8 42 01 0D 05 00 04 40` | 83 |

**SHA-256 DigestInfo example (most common):**
```
30 31           -- SEQUENCE (49 bytes)
  30 0D         -- SEQUENCE (13 bytes) — AlgorithmIdentifier
    06 09       -- OID (9 bytes)
      60 86 48 01 86 F8 42 01 05   -- SHA-256 OID (2.16.840.1.101.3.4.2.1)
    05 00       -- NULL
  04 20         -- OCTET STRING (32 bytes)
    <32 bytes of SHA-256 hash>
```

For ECDSA and EdDSA keys, **do not include DigestInfo** — send raw hash bytes only.

---

## 14. Public Key Response Format

The GENERATE KEY PAIR command response (and some GET DATA responses) use the `7F 49` template.

### 14.1 RSA Public Key

```
7F 49 [len]
  81 [n_hi n_lo] <N>    -- modulus, big-endian (e.g., 256 bytes for RSA-2048)
  82 [e_len] <E>        -- public exponent (e.g., 03 bytes: 01 00 01 for 65537)
```

Length encoding: if the inner value is ≥128 bytes, use `81 <len>` or `82 <hi lo>` for the
TLV length field. RSA-2048 modulus = 256 bytes → `81 00 00 01 00` (3-byte extended length).

Wait — standard BER-TLV length encoding:
- 1–127 bytes: single byte `<len>`
- 128–255 bytes: `81 <len>`
- 256–65535 bytes: `82 <hi> <lo>`

RSA-2048 N = 256 bytes → tag `81`, length `82 01 00`.

### 14.2 ECDSA/ECDH Public Key (NIST curves)

```
7F 49 [len]
  86 [point_len] 04 <X_bytes> <Y_bytes>   -- uncompressed point, 04 prefix
```

| Curve | X len | Y len | Total point_len |
|---|---|---|---|
| P-256 | 32 | 32 | 65 (04 + 32 + 32) |
| P-384 | 48 | 48 | 97 (04 + 48 + 48) |
| P-521 | 66 | 66 | 133 (04 + 66 + 66) |

### 14.3 Ed25519 / X25519 Public Key

```
7F 49 [len]
  86 20 <32 bytes>    -- 32-byte public key (native format, no 04 prefix)
```

For Ed25519: the 32-byte compressed point (y-coordinate with sign bit in high bit).
For X25519: the 32-byte u-coordinate.

---

## 15. pico2hsm Implementation Notes

These notes capture decisions and constraints specific to implementing OpenPGP Card 3.4
in the pico2hsm project (`firmware/src/protocol/openpgp/`).

### 15.1 Storage Namespace

Per the pico2hsm multi-applet architecture, OpenPGP keys must use the reserved key ID range:

| Purpose | Key ID | Flash slot |
|---|---|---|
| SIG key | `0x90` | OpenPGP SIG slot |
| DEC key | `0x91` | OpenPGP DEC slot |
| AUTH key | `0x92` | OpenPGP AUTH slot |

All OpenPGP `KeyObject` entries must carry `owner = Owner::OpenPgp` so that SC-HSM
INITIALIZE does not wipe them.

### 15.2 Signature Counter Persistence

DO `93` must survive power cycles. Store it in flash alongside the key objects.
A 3-byte big-endian counter in a dedicated flash slot is sufficient.

### 15.3 Algorithm Support Matrix

| Algorithm | SIG | DEC | AUTH | Notes |
|---|---|---|---|---|
| RSA-2048 | Yes | Yes | Yes | Via `rsa` crate |
| RSA-3072 | Yes | Yes | Yes | Via `rsa` crate |
| RSA-4096 | Yes | Yes | Yes | Via `rsa` crate (slow keygen) |
| ECDSA P-256 | Yes | — | Yes | Via `p256` crate |
| ECDSA P-384 | Yes | — | Yes | Via `p384` crate |
| ECDSA P-521 | Yes | — | Yes | Via `p521` crate (if available) |
| ECDH P-256 | — | Yes | — | Via `p256` / `elliptic-curve` |
| ECDH P-384 | — | Yes | — | Via `p384` |
| ECDH P-521 | — | Yes | — | |
| Ed25519 | Yes | — | Yes | Via `curve25519-dalek` (`applet-openpgp-curve25519`) |
| X25519 | — | Yes | — | Via `curve25519-dalek` (`applet-openpgp-curve25519`) |

Ed25519 and X25519 are gated behind the `applet-openpgp-curve25519` feature flag.

### 15.4 Core1 Stack Headroom

OpenPGP state includes:
- `AlgorithmAttrs` per key slot (up to ~12 bytes each)
- Signature counter (3 bytes, persisted)
- PIN verification flags

These are small. The dominant stack cost is the same RSA/ECC scratch buffers used by
SC-HSM. No additional stack increase is required beyond what SC-HSM already allocated
(`CORE1_STACK: Stack<131072>`), as the two applets are never simultaneously active.

### 15.5 Session State Reset on SELECT

When `handles_aid()` matches and the applet is activated, all PIN verification flags must
be cleared. This must also happen when SC-HSM is selected after OpenPGP (inter-applet
SELECT), which the Dispatcher's `process_apdu` method handles by deactivating the prior
applet.

### 15.6 Minimum Command Set for GnuPG / OpenSC Compatibility

To pass `gpg --card-status` and `gpg --card-edit`, the following minimum set must be
functional:
1. SELECT (returns FCI with AID + `9F 6E` version)
2. GET DATA for `6E` (Application Related Data — constructed)
3. GET DATA for `65` (Cardholder Related Data)
4. GET DATA for `7A` (Security Support Template with sig counter `93`)
5. VERIFY (PW1 mode 81/82, PW3)
6. GENERATE KEY PAIR (P1=`81` — read public key; P1=`80` — generate)
7. PSO:CDS
8. PSO:DECIPHER
9. INTERNAL AUTHENTICATE
10. CHANGE REFERENCE DATA
11. GET CHALLENGE

### 15.7 Recommended Implementation Order

1. **SELECT** + **GET DATA** for `6E`, `65`, `7A`, `4F`, `C0`–`C6` → enables `gpg --card-status`
2. **VERIFY** PW1/PW3 state machine
3. **GENERATE KEY PAIR** (read existing: P1=`81`)
4. **GENERATE KEY PAIR** (generate: P1=`80`) + key fingerprint / timestamp storage
5. **PSO:CDS** for RSA and ECDSA
6. **PSO:DECIPHER** for RSA and ECDH
7. **INTERNAL AUTHENTICATE**
8. **CHANGE REFERENCE DATA**, **RESET RETRY COUNTER**
9. **PUT DATA** for writeable DOs (name, fingerprints, URL)
10. **TERMINATE DF** + **ACTIVATE FILE**
11. Ed25519/X25519 (behind `applet-openpgp-curve25519`)

---

## 16. pico2hsm key usage policy as implemented (2026-10, audit S-10)

| Rule | Behaviour |
|---|---|
| Key roles | SIG key only for PSO:CDS; DEC key only for PSO:DECIPHER; AUT key only for INTERNAL AUTHENTICATE (no MSE key redirection) |
| PW1 modes | PSO:CDS needs mode 81; DECIPHER and INTERNAL AUTHENTICATE need mode 82 |
| PW1 status (`C4` byte 1) | `00` one signature per VERIFY (default), `01` several; PUT DATA `C4` (PW3) with 1 byte (or 7, first used); other values `6A80`; persisted; extended capability `C0` bit `10` set |
| Signature counter (`93` in `7A`) | +1 per PSO:CDS, written to flash **before** the signature is returned (`6581` and no signature otherwise), survives reset, reset to 0 when a new SIG key is generated, saturates at `FFFFFF` |
| Algorithm attributes | `C1`/`C3`: ECDSA (`13`) P-256/384/521 or EdDSA (`16`) Ed25519; `C2`: ECDH (`12`) P-256/384/521 or X25519. Optional trailing format byte `00`/`FF`. Anything else (RSA, a key-agreement algorithm for a signing role, unknown curve) `6A80` |
| General feature management `7F74` | `81 01 00` (no display, button, keypad, LED, …), also inside `6E` |
| UIF `D6`/`D7`/`D8` | Not supported: GET and PUT DATA answer `6A88` (no button) |

Not implemented: key import (`DB 3FFF`), MSE, KDF-DO, reset code, RSA,
private DOs.

---

*Sources: OpenPGP Smart Card Application Specification 3.4.1 (gnupg.org), GnuPG scd/app-openpgp.c,
OpenSC src/libopensc/card-openpgp.c, SmartPGP Constants.java, pico-openpgp openpgp.c.*
