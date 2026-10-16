# APDU Quick Reference — pico2hsm

Single-page cross-applet reference for SC-HSM, PIV, and OpenPGP command handlers and test writers.
Hex values: bare uppercase in tables, `0x`-prefixed in prose.

---

## 1. INS Byte Master Table

"implemented" means the applet routes the INS to a handler; "—" means it
answers 6D00 (INS not supported). Routing: `route_with_store` /
`dispatch_with_store` in `firmware/src/protocol/<applet>/mod.rs`; GET
RESPONSE (C0) is served by the dispatcher for every applet.

| INS | Command | SC-HSM | PIV | OpenPGP | pico2hsm notes |
|---|---|---|---|---|---|
| 20 | VERIFY | implemented | implemented | implemented | P2 meaning differs per applet |
| 22 | MSE SET | implemented | — | — | SC-HSM: P1=41/F3 |
| 24 | CHANGE REFERENCE DATA | implemented | implemented | implemented | |
| 26 | SESSION PIN | implemented | — | — | SC-HSM only; CLA 00 or 80 |
| 28 | PUK AUTH | implemented | — | — | SC-HSM only |
| 2A | PSO (sign/decipher/MAC) | implemented | — | implemented | P1/P2 distinguish operation |
| 2C | RESET RETRY COUNTER | implemented | implemented | implemented | |
| 34 | WRAP KEY (alias of 72) | implemented | — | — | SC-HSM |
| 44 | ACTIVATE FILE | — | — | implemented | OpenPGP, after TERMINATE DF |
| 46 | GENERATE KEY PAIR | implemented | — | — | SC-HSM only; returns CVC |
| 47 | GENERATE KEY PAIR | — | implemented | implemented | PIV/OpenPGP; returns 7F49 pubkey |
| 48 | GENERATE SYMMETRIC KEY | implemented | — | — | SC-HSM only; AES-128/192/256 |
| 50 | INITIALIZE | implemented | — | — | SC-HSM only |
| 52 | KEY DOMAIN | implemented | — | — | P1=00 status / share import (OpenSC); P1=01–05 pico2hsm-specific |
| 54 | EXTRAS | implemented | — | — | SC-HSM only; KDF/MAC, device key, DKEK exchange, domains, store recovery, RSA pool (`SC_HSM_APDU_REFERENCE.md` §3.29) |
| 58 | LIST KEYS | implemented | — | — | P1=P2=00 only (else 6A86) |
| 60 | BIP32/SLIP-0010 HD DERIVE | implemented | — | — | SC-HSM only |
| 62 | DECIPHER / DERIVE ASYM | implemented | — | — | P1=01 with P2=00 = derive |
| 68 | SIGN | implemented | — | — | SC-HSM only; P1=key_id, P2=algo |
| 72 | WRAP KEY (EXPORT) | implemented | — | — | CardContact blob under the DKEK |
| 74 | UNWRAP KEY (IMPORT) | implemented | — | — | CardContact blob under the DKEK |
| 78 | SYMMETRIC CIPHER | implemented | — | — | SC-HSM only; AES-CBC/CTR/GCM/CMAC |
| 82 | EXTERNAL AUTHENTICATE | — | — | — | removed 2026-10 (6D00) |
| 84 | GET CHALLENGE | implemented | — | implemented | |
| 86 | GENERAL AUTHENTICATE | implemented | — | — | SC-HSM DAT challenge-sign |
| 87 | GENERAL AUTHENTICATE | — | implemented | — | PIV sign/ECDH/mutual auth |
| 88 | INTERNAL AUTHENTICATE | — | — | implemented | OpenPGP AUTH key slot |
| A4 | SELECT | implemented | implemented | implemented | |
| B0 | READ BINARY | implemented | — | — | SC-HSM virtual filesystem |
| B1 | READ BINARY ODD | implemented | — | — | SC-HSM; offset TLV in data |
| C0 | GET RESPONSE | dispatcher | dispatcher | dispatcher | chaining (`61 XX`) |
| CA | GET DATA (even) | — | — | implemented | OpenPGP DO by P1P2 tag |
| CB | GET DATA (odd) | — | implemented | — | PIV: wrapped in 5C TLV |
| D6 | UPDATE BINARY | implemented | — | — | SC-HSM; writes current EF |
| D7 | WRITE DATA | implemented | — | — | SC-HSM; TLV data to addressed EF |
| DA | PUT DATA (even) | — | — | implemented | OpenPGP DO by P1P2 tag |
| DB | PUT DATA (odd) | — | implemented | implemented | PIV data objects; OpenPGP: same handler as DA, no key import (3FFF) |
| E0 | CREATE FILE | implemented | — | — | SC-HSM only |
| E4 | DELETE FILE | implemented | — | — | SC-HSM only |
| E6 | TERMINATE DF | — | — | implemented | OpenPGP |
| F0–F2 | PROVISIONING | implemented | — | — | status incl. the running image version (F0, no PIN); production mode, OTP row lock (SO-PIN); F3 reserved (6D00) |
| F7 | GET METADATA | — | implemented | — | YubiKey extension |
| FB | RESET | — | implemented | — | YubiKey PIV reset; only while PIN and PUK are blocked |
| FE | DEBUG | `debug` builds only | — | — | `SC_HSM_APDU_REFERENCE.md` §3.30 |
| FF | SET MANAGEMENT KEY | — | implemented | — | YubiKey extension; 3DES |

Not implemented anywhere (6D00): A5 SELECT DATA, CC GET NEXT DATA, F8 GET
SERIAL, F9 ATTEST, FA SET PIN RETRIES, FD GET VERSION, PIV FE IMPORT KEY.

---

## 2. Per-Applet Command Tables

### 2.1 SC-HSM Commands (INS bytes, CLA = 00 unless noted)

| INS | P1 | P2 | Description | SW success | Key error SWs |
|---|---|---|---|---|---|
| A4 | 00/01/02/04/08/09 | 00/04/0C | Select EF/DF/AID | 9000 | 6A82 |
| B0 | FID[15:8] | FID[7:0] | Read PKCS#15 virtual EF | 9000 | 6A82, 6A80 |
| B1 | 00 | 00 | Read EF at explicit offset (TLV in data) | 9000 | 6A82, 6A80 |
| D6 | offset[15:8] | offset[7:0] | Write current EF (UPDATE BINARY) | 9000 | 6982, 6A82 |
| D7 | FID[15:8] | FID[7:0] | Write TLV data to addressed EF | 9000 | 6982, 6A80 |
| E0 | 00 | 00 | Create transparent EF (FID in data) | 9000 | 6982, 6A80 |
| E4 | 00/02 | 00 | Delete key or EF (FID in data when P1=02) | 9000 | 6982, 6A82 |
| 58 | 00 | 00 | List key container slots | 9000 | 6A86 |
| 20 | 00 | 81/82/88 | Verify User PIN / session PIN / SO-PIN | 9000 | 63CX, 6983, 6984 |
| 24 | 00/01 | 81/88 | Change User PIN or SO-PIN | 9000 | 63CX, 6983, 6700 |
| 26 | 00 | 00 | Generate one-time session PIN | 9000 | 6982 |
| 28 | 00 | 00 | PUK auth — unblock User PIN | 9000 | 63CX, 6983, 6985 |
| 2C | 00/02 | 81 | Reset retry counter (requires SO-PIN) | 9000 | 6982, 6700 |
| 50 | 00 | 00 | Initialize / re-initialize device | 9000 | 6982, 6700, 6A80 |
| 22 | 41/F3 | A4/B8/B4/03 | MSE SET: select key/algo for operation | 9000 | 6A80 |
| 46 | key_id | 00 | Generate EC/RSA key pair (returns CVC) | 9000 | 6982, 6A80, 6985 |
| 48 | key_id | 00 | Generate AES-128/192/256 symmetric key | 9000 | 6982, 6A80, 6985 |
| 72 / 34 | key_id | 92 | WRAP KEY: DKEK-wrapped CardContact blob | 9000 | 6982, 6985, 6A81, 6A86 |
| 74 | key_id | 93 | UNWRAP KEY: import a CardContact blob | 9000 | 6982, 6985, 6A80, 6A81, 6581 |
| 52 | 00–05 | domain_id | DKEK key domain (P1=00 OpenSC status / share import) | 9000 | 6982, 6A86, 6A88 |
| 60 | master_id | flags | BIP32/SLIP-0010 HD key derivation | 9000 | 6982, 6A82, 6A80 |
| 68 | key_id | algo | ECDSA / RSA sign | 9000 | 6982, 6A82, 6D00 |
| 62 | key_id | algo | ECDH / RSA decrypt (P1=01 = derive) | 9000 | 6982, 6A82, 6D00 |
| 2A | 9E | 9A | PSO sign (uses MSE key/algo) | 9000 | 6982, 6985, 6A82 |
| 2A | 80 | 86 | PSO decipher (uses MSE key/algo) | 9000 | 6982, 6985, 6A82 |
| 2A | 8E | 80 | PSO compute MAC (AES-CMAC or HMAC-SHA256) | 9000 | 6982, 6985 |
| 78 | 01/02 | 02/03/05/06 | Symmetric cipher AES-CBC/CTR/GCM/CMAC | 9000 | 6982, 6985, 6700 |
| 84 | 00 | 00 | Get challenge (random bytes, 8 stored) | 9000 | — |
| 86 | 00 | 00 | General auth DAT challenge-sign | 9000 | 6982, 6A80, 6985 |
| 54 | 01–06, 30–53 | 00 | EXTRAS: KDF/MAC, device key, DKEK exchange, domains, store recovery, RSA pool | 9000 | 6982, 6700, 6A80 |
| FE | 10–16, 20–21 | — | Debug hooks — `debug` builds only (CLA 80); 00–02 dump stub → 6A80 | 9000 | 6A80 |

### 2.2 PIV Commands (CLA = 00; `applet-piv`)

| INS | P1 | P2 | Description | SW success | Key error SWs |
|---|---|---|---|---|---|
| A4 | 04 | 00 | SELECT PIV AID | 9000 | 6A82, 6E00 |
| 20 | 00 | 80/81 | VERIFY PIN (80) or PUK (81) | 9000 | 63CX, 6983, 6A86 |
| 24 | 00 | 80/81 | CHANGE REFERENCE DATA PIN/PUK | 9000 | 63CX, 6983, 6A86 |
| 2C | 00 | 80 | RESET RETRY COUNTER (unblock PIN via PUK) | 9000 | 63CX, 6983, 6A86 |
| CB | 3F | FF | GET DATA (data = `5C` + tag) | 9000 | 6A82, 6982, 61XX |
| DB | 3F | FF | PUT DATA (data = `5C`+tag + `53`+content) | 9000 | 6982, 6A82, 6A84 |
| 87 | algo | key_ref | GENERAL AUTHENTICATE (sign/ECDH/mutual) | 9000 | 6982, 6A80, 6A88 |
| 47 | 00 | key_ref | GENERATE KEY PAIR | 9000 | 6982, 6A80, 6A86 |
| C0 | 00 | 00 | GET RESPONSE (chain `61 XX`; served by the dispatcher) | 9000 | 6A86 |
| F7 | 00 | key_ref | GET METADATA (YubiKey extension) | 9000 | 6A88 |
| FB | 00 | 00 | RESET PIV application (YubiKey extension; PIN and PUK blocked) | 9000 | 6985 |
| FF | FF | FF/FE | SET MANAGEMENT KEY (YubiKey extension; `03 9B 18` + 3DES key) | 9000 | 6982, 6A80 |

F8 GET SERIAL, F9 ATTEST, FA SET PIN RETRIES, FD GET VERSION and FE IMPORT
KEY are not implemented (6D00).

### 2.3 OpenPGP Commands (CLA = 00; `applet-openpgp`)

| INS | P1 | P2 | Description | SW success | Key error SWs |
|---|---|---|---|---|---|
| A4 | 04 | 00 | SELECT OpenPGP AID | 9000 | 6A82, 6E00 |
| 20 | 00/FF | 81/82/83 | VERIFY PW1 (81=sign, 82=other) / PW3 | 9000 | 63CX, 6983, 6A86 |
| 24 | 00/01 | 81/83 | CHANGE REFERENCE DATA PW1 or PW3 | 9000 | 63CX, 6983, 6700 |
| 2C | 00/02 | 81 | RESET RETRY COUNTER (Reset Code or PW3) | 9000 | 63CX, 6983, 6982 |
| CA | tag[15:8] | tag[7:0] | GET DATA (even) — simple/primitive DOs | 9000 | 6A88, 6982, 61XX |
| DA | tag[15:8] | tag[7:0] | PUT DATA (even) — write simple DO | 9000 | 6982, 6A80, 6A88 |
| DB | tag[15:8] | tag[7:0] | PUT DATA (odd) — same DOs as DA; key import (3FFF) not implemented | 9000 | 6982, 6A80 |
| 2A | 9E | 9A | PSO:CDS — compute digital signature | 9000 | 6982, 6985, 6700 |
| 2A | 80 | 86 | PSO:DECIPHER — ECDH (NIST curves, X25519) | 9000 | 6982, 6985 |
| 88 | 00 | 00 | INTERNAL AUTHENTICATE (AUTH key) | 9000 | 6982, 6985 |
| 47 | 80/81 | 00 | GENERATE KEY PAIR / read public key | 9000 | 6982, 6A88, 6F00 |
| 84 | 00 | 00 | GET CHALLENGE | 9000 | 6A81, 6700 |
| C0 | 00 | 00 | GET RESPONSE (chain `61 XX`) | 9000 | — |
| E6 | 00 | 00 | TERMINATE DF | 9000 | 6982 |
| 44 | 00 | 00 | ACTIVATE FILE (factory reset) | 9000 | 6985 |

Not implemented (6D00): CB GET DATA odd, CC GET NEXT DATA, 22 MSE, A5
SELECT DATA, PSO:ENCIPHER (P1=86).

---

## 3. Data Object / TLV Tag Reference

### 3.1 SC-HSM Tags

#### Command-level TLV tags

| Tag | Context | Description |
|---|---|---|
| 53 | WRITE DATA | Data payload; BER-TLV length encoding |
| 54 | WRITE DATA, READ BINARY ODD | Offset (2 bytes) or FID+offset (4 bytes) |
| 62 | SELECT FCP response | File Control Parameters outer tag |
| 6F | SELECT FCI response | File Control Information outer tag |
| 7C | GENERAL AUTHENTICATE | Dynamic Authentication Template (DAT) |
| 80 | MSE SET, INITIALIZE | Algorithm identifier; or INITIALIZE options bitmask |
| 81 | MSE SET, INITIALIZE, CHANGE PIN, DAT | Key reference; User PIN; or DAT host challenge |
| 82 | INITIALIZE, CHANGE PIN, DAT | Init code (SO-PIN); new PIN; or DAT card response |
| 84 | MSE SET | Key reference (1-byte key slot ID) |
| 85 | 7F49 public key template | EC group order |
| 86 | 7F49 public key template | EC public point (`04 || X || Y`) |
| 87 | 7F49 public key template | EC cofactor |
| 91 | INITIALIZE | User PIN retry counter (1 byte) |
| 92 | INITIALIZE | DKEK share count (1 byte) |
| 93 | INITIALIZE | PUK (8–16 bytes) |
| 42 | GENERATE KEY PAIR | Key reference label; outer CA reference in CVC |
| 5F 29 | GENERATE KEY PAIR | Certificate Profile Identifier |
| 5F 20 | GENERATE KEY PAIR | Certificate Holder Reference (CHR) |
| 5F 37 | GENERATE KEY PAIR | CVC signature (dummy zeros) |
| 7F 21 | GENERATE KEY PAIR | CVC outer wrapper |
| 7F 4E | GENERATE KEY PAIR | Certificate Body |
| 7F 49 | GENERATE KEY PAIR | Public Key template |
| 9F 6E | SELECT AID FCI | Card OS version (4 bytes, e.g. `20 00 00 00`) |

#### SC-HSM Virtual File ID Reference

| File ID | Description |
|---|---|
| 3F00 | MF (Master File / root DF) |
| 5015 | DF.CIA |
| 2F00 | EF.DIR (application directory) |
| 2F02 | EF.C_DevAut (device certificate stub) |
| 2F03 | EF.TokenInfo (written by sc-hsm-tool) |
| 5031 | EF.ODF (Object Directory File) |
| 5032 | EF.TokenInfo (PKCS#15) |
| C000 | EF.AODF (Authentication Object DF) |
| C100 | EF.PrKDF (empty; LIST KEYS used instead) |
| C200 | EF.PuKDF (empty) |
| C4xx | PRKD for key slot xx |
| CCxx | Key container presence flag for slot xx |
| CExx | EE certificate EF for key slot xx |

### 3.2 PIV Data Object Tags

GET DATA / PUT DATA wrap the object tag in a `5C` TLV: `5C <len> <tag_bytes>`.
Responses and writes use outer tag `53` (content wrapper).

#### Mandatory Objects

| Tag | Object Name | Read | Write |
|---|---|---|---|
| 5F C1 07 | Card Capability Container (CCC) | Free | Mgmt key |
| 5F C1 02 | Cardholder Unique Identifier (CHUID) | Free | Mgmt key |
| 5F C1 05 | X.509 Cert for PIV Authentication (9A) | Free | Mgmt key |
| 5F C1 0A | X.509 Cert for Digital Signature (9C) | Free | Mgmt key |
| 5F C1 0B | X.509 Cert for Key Management (9D) | Free | Mgmt key |
| 5F C1 01 | X.509 Cert for Card Authentication (9E) | Free | Mgmt key |
| 5F C1 03 | Cardholder Fingerprints | PIN | Mgmt key |
| 5F C1 09 | Printed Information | PIN | Mgmt key |
| 5F C1 08 | Cardholder Facial Images | PIN | Mgmt key |
| 5F C1 06 | Security Object | Free | Mgmt key |
| 7E | Discovery Object | Free | Mgmt key |
| 5F C1 0C | Key History Object | Free | Mgmt key |
| 5F C1 21 | Cardholder Iris Images | PIN | Mgmt key |

#### Retired Key Management Certificates

| Tag range | Objects |
|---|---|
| 5F C1 0D – 5F C1 20 | Retired Key Management Certs 1–20 |

#### Certificate Object Internal Layout (inside `53` wrapper)

| Tag | Content |
|---|---|
| 70 | DER-encoded X.509 certificate |
| 71 | Cert info byte: `00`=uncompressed, `01`=gzip |
| FE | Error Detection Code (mandatory, `FE 00`) |

#### PIV Key Slot Reference

| Key Ref | Name | PIN Policy | Algorithms |
|---|---|---|---|
| 9A | PIV Authentication | Once/session | RSA-2048/3072, P-256/P-384 |
| 9B | Card Management | Mgmt key (mutual auth) | 3DES, AES-128/192/256 |
| 9C | Digital Signature | Every use (PIN Always) | RSA-2048/3072, P-256/P-384 |
| 9D | Key Management | Once/session | RSA-2048/3072, P-256/P-384 |
| 9E | Card Authentication | Never | 3DES, P-256/P-384 |
| 82–95 | Retired KM 1–20 | Once/session | RSA-2048/3072, P-256/P-384 |
| F9 | Attestation | — | (YubiKey, read-only) |

### 3.3 OpenPGP Data Object Tags

GET DATA uses `CA` (even) with P1=tag_hi, P2=tag_lo (no wrapping needed).
GET DATA (odd) uses `CB` with data `5C 00`.
PUT DATA uses `DA` (even) / `DB` (odd) with P1=tag_hi, P2=tag_lo.

#### Simple / Primitive DOs

| Tag | Name | Read | Write |
|---|---|---|---|
| 00 4F | Application Identifier | ALWAYS | NEVER |
| 00 5B | Cardholder Name | ALWAYS | PW3 |
| 00 5E | Login Data | ALWAYS | PW3 |
| 5F 2D | Language Preference | ALWAYS | PW3 |
| 5F 35 | Sex | ALWAYS | PW3 |
| 5F 50 | URL | ALWAYS | PW3 |
| 5F 52 | Historical Bytes | ALWAYS | NEVER |
| 00 93 | Digital Signature Counter (3 bytes, BE) | ALWAYS | NEVER |
| 00 C0 | Extended Capabilities (10 bytes) | ALWAYS | NEVER |
| 00 C1 | Algorithm Attrs SIG | ALWAYS | PW3 |
| 00 C2 | Algorithm Attrs DEC | ALWAYS | PW3 |
| 00 C3 | Algorithm Attrs AUTH | ALWAYS | PW3 |
| 00 C4 | PW Status Bytes (7 bytes) | ALWAYS | PW3 |
| 00 C5 | Key Fingerprints (60 bytes, SIG+DEC+AUTH) | ALWAYS | PW3 |
| 00 C6 | CA Fingerprints (60 bytes) | ALWAYS | PW3 |
| 00 C7 | Fingerprint SIG (20 bytes) | ALWAYS | PW3 |
| 00 C8 | Fingerprint DEC (20 bytes) | ALWAYS | PW3 |
| 00 C9 | Fingerprint AUTH (20 bytes) | ALWAYS | PW3 |
| 00 CE | Key Generation Date SIG (4 bytes, Unix BE) | ALWAYS | PW3 |
| 00 CF | Key Generation Date DEC (4 bytes) | ALWAYS | PW3 |
| 00 D0 | Key Generation Date AUTH (4 bytes) | ALWAYS | PW3 |
| 00 D3 | Reset Retry Counter | NEVER | PW3 |
| 00 D5 | AES Key (16/24/32 bytes) | NEVER | PW3 |
| 00 D6 | UIF SIG (2 bytes) | ALWAYS | PW3 |
| 00 D7 | UIF DEC (2 bytes) | ALWAYS | PW3 |
| 00 D8 | UIF AUTH (2 bytes) | ALWAYS | PW3 |
| 00 DE | Key Information (6 bytes, v3.4+) | ALWAYS | NEVER |
| 00 F9 | KDF Data Object | ALWAYS | PW3 |
| 00 FA | Algorithm Information | ALWAYS | NEVER |

#### Constructed DOs

| Tag | Name | Read | Description |
|---|---|---|---|
| 00 65 | Cardholder Related Data | ALWAYS | Contains `5B`, `5F 2D`, `5F 35` |
| 00 6E | Application Related Data | ALWAYS | AID, version, ext caps, fingerprints |
| 00 73 | Discretionary Data Objects | ALWAYS | Contained within `6E` |
| 00 7A | Security Support Template | ALWAYS | Contains `93` (sig counter) |
| 7F 21 | Cardholder Certificate | PW1-82 | X.509 for SIG/DEC/AUTH (selectable) |
| 7F 49 | Public Key Template | ALWAYS | GENERATE KEY PAIR response |

#### Private DOs

| Tag | Read | Write |
|---|---|---|
| 01 01 | ALWAYS | PW1-82 |
| 01 02 | ALWAYS | PW3 |
| 01 03 | PW1-82 | PW3 |
| 01 04 | PW3 | PW3 |

#### OpenPGP Key Slot Reference

| Slot | CRT Tag | Algo DO | Command | Auth Required |
|---|---|---|---|---|
| SIG | B6 | C1 | PSO:CDS (`2A 9E 9A`) | PW1 mode 81 (one-shot) or 82 |
| DEC | B8 | C2 | PSO:DECIPHER (`2A 80 86`) | PW1 mode 82 |
| AUTH | A4 | C3 | INTERNAL AUTH (`88 00 00`) | PW1 mode 82 |

---

## 4. AID Reference

| Applet | AID (hex) | SELECT matching | Feature flag |
|---|---|---|---|
| SC-HSM | E8 2B 06 01 04 01 81 C3 1F 02 01 | Exact 11-byte match | always on |
| PIV | A0 00 00 03 08 00 00 10 00 01 00 | Exact 11-byte match or 5-byte RID prefix | `applet-piv` |
| OpenPGP | D2 76 00 01 24 01 [VV VV MM MM SS SS SS SS 00 00] | 6-byte prefix `D2 76 00 01 24 01` | `applet-openpgp` |

**SELECT FCI outer tag:**

| Applet | FCI outer tag | AID inner tag | Version inner tag |
|---|---|---|---|
| SC-HSM | `6F` | `84` (DF name, not `4F`) | `A5` → `9F 6E` (4 bytes, e.g. `20 00 00 00`) |
| PIV | `61` | `4F` (AID / PIX) | `50` (label "PIV") |
| OpenPGP | `6F` | `84` | `A5` → `9F 6E` |

---

## 5. Algorithm / Mechanism Reference

### 5.1 Cross-Applet Algorithm IDs

| Algorithm | SC-HSM algo_ref | PIV algo ID | OpenPGP algo ID / attr byte |
|---|---|---|---|
| P-256 ECDSA | 13 (sign, pre-hashed) | 11 | `13` + OID `2A 86 48 CE 3D 03 01 07` |
| P-256 ECDH | 23 (decipher) / 80 (generic) | 11 | `12` + OID `2A 86 48 CE 3D 03 01 07` |
| P-384 ECDSA | 15 (sign, pre-hashed) | 14 | `13` + OID `2B 81 04 00 22` |
| P-384 ECDH | 25 (decipher) | 14 | `12` + OID `2B 81 04 00 22` |
| P-521 ECDSA | 17 (sign, pre-hashed) | — | `13` + OID `2B 81 04 00 23` |
| P-521 ECDH | 27 (decipher) | — | `12` + OID `2B 81 04 00 23` |
| secp256k1 ECDSA | 19 (sign) | — | — |
| secp256k1 ECDH | 29 (decipher) | — | — |
| Ed25519 | — | E0 (YubiKey ext) | `16` + OID `2B 06 01 04 01 DA 47 0F 01` |
| X25519 ECDH | — | E1 (YubiKey ext) | `12` + OID `2B 06 01 04 01 97 55 01 05 01` |
| RSA-2048 | 05 (keygen), 20 (raw sign), 21 (decrypt) | 07 | `01 08 00 00 11 00` |
| RSA-4096 | 07 (keygen), 20 (raw sign), 21 (decrypt) | 16 (YubiKey ext) | `01 10 00 00 11 00` |
| AES-128 | 82 (keygen); CBC/CTR/GCM via INS 78 | 08 (mgmt key ECB) | `00 D5` DO write (16 bytes) |
| AES-192 | 83 (keygen) | 0A (mgmt key ECB) | `00 D5` DO write (24 bytes) |
| AES-256 | 84 (keygen) | 0C (mgmt key ECB) | `00 D5` DO write (32 bytes) |
| 3DES | — | 03 (mgmt key / 9E card auth) | — |

### 5.2 SC-HSM Sign Algorithm Bytes (INS 68 P2 / INS 2A P2)

| P2 | Operation | Input |
|---|---|---|
| 13 | ECDSA P-256, pre-hashed | 32-byte SHA-256 digest |
| 15 | ECDSA P-384, pre-hashed | 48-byte SHA-384 digest |
| 17 | ECDSA P-521, pre-hashed | 64-byte SHA-512 digest |
| 19 | ECDSA K-256, pre-hashed | 32-byte SHA-256 digest |
| 20 | RSA raw (PKCS#1-padded by host) | 256 or 512 bytes |
| 31 | RSA PKCS#1v1.5 + SHA-256 (card hashes) | raw message |
| 32 | RSA PKCS#1v1.5 + SHA-384 (card hashes) | raw message |
| 33 | RSA PKCS#1v1.5 + SHA-512 (card hashes) | raw message |
| 34 | RSA-PSS + SHA-256, pre-hashed | 32-byte digest |
| 40 | RSA-PSS + SHA-256, pre-hashed | 32-byte digest |
| 70 | ECDSA EC-RAW, pre-hashed (generic) | any digest |
| 71 | ECDSA + SHA-1 (card hashes) | raw message |
| 72 | ECDSA + SHA-224 (card hashes) | raw message |
| 73 | ECDSA + SHA-256 (card hashes) | raw message |
| 74 | ECDSA + SHA-384 (card hashes) | raw message |
| 75 | ECDSA + SHA-512 (card hashes) | raw message |

### 5.3 SC-HSM Decipher Algorithm Bytes (INS 62 P2)

| P2 | Operation | Input | Response |
|---|---|---|---|
| 21 | RSA decrypt PKCS#1 or OAEP | RSA ciphertext | raw `c^d mod n` |
| 22 | RSA decrypt OAEP variant | same as 21 | same |
| 23 | ECDH P-256 | `04 \|\| Qx \|\| Qy` (65 bytes) | raw X-coord (32 bytes) |
| 25 | ECDH P-384 | `04 \|\| Qx \|\| Qy` (97 bytes) | raw X-coord (48 bytes) |
| 27 | ECDH P-521 | `04 \|\| Qx \|\| Qy` (133 bytes) | raw X-coord (66 bytes) |
| 29 | ECDH K-256 | `04 \|\| Qx \|\| Qy` (65 bytes) | raw X-coord (32 bytes) |
| 80 | ECDH generic (OpenSC path) | peer public point | `04 \|\| X-coord` (OpenSC strips prefix) |

### 5.4 OpenPGP Algorithm Attributes Full Byte Arrays

| Slot | Algorithm | Full Attribute Bytes |
|---|---|---|
| SIG/AUTH | RSA-2048 | `01 08 00 00 11 00` |
| SIG/AUTH | RSA-4096 | `01 10 00 00 11 00` |
| SIG/AUTH | ECDSA P-256 | `13 2A 86 48 CE 3D 03 01 07 00` |
| SIG/AUTH | ECDSA P-384 | `13 2B 81 04 00 22 00` |
| SIG/AUTH | ECDSA P-521 | `13 2B 81 04 00 23 00` |
| SIG/AUTH | Ed25519 | `16 2B 06 01 04 01 DA 47 0F 01` |
| DEC | ECDH P-256 | `12 2A 86 48 CE 3D 03 01 07 00` |
| DEC | ECDH P-384 | `12 2B 81 04 00 22 00` |
| DEC | ECDH P-521 | `12 2B 81 04 00 23 00` |
| DEC | X25519 | `12 2B 06 01 04 01 97 55 01 05 01` |

---

## 6. Status Word Reference

| SW | ISO 7816-4 meaning | pico2hsm usage |
|---|---|---|
| 9000 | Success | Success |
| 61XX | More data available | GET RESPONSE required; XX = bytes remaining |
| 63CX | Counter with value X | PIN/PUK wrong; X = retries remaining |
| 6700 | Wrong length | PIN too short/long; wrong data length |
| 6982 | Security status not satisfied | No PIN/SO-PIN/PW session active |
| 6983 | Authentication method blocked | PIN/PUK retry counter = 0 |
| 6984 | Referenced data invalidated | PIN not initialized (no hash stored) |
| 6985 | Conditions of use not satisfied | No challenge; MSE not set; slot full |
| 6A80 | Incorrect parameters in data | Malformed TLV; unknown P1/P2 |
| 6A81 | Function not supported | GET CHALLENGE cap not set |
| 6A82 | File or application not found | Key not in store; EF not found |
| 6A84 | Not enough memory | PIV object storage full |
| 6A86 | Incorrect P1/P2 | Bad key reference or algorithm |
| 6A88 | Referenced data not found | Key slot empty; DO not written |
| 6C XX | Wrong Le | XX = correct expected length |
| 6D00 | INS not supported | Command not implemented; stub |
| 6E00 | CLA not supported | Wrong CLA byte |
| 6F00 | No precise diagnosis | Key generation failed (OpenPGP) |

---

## 7. Key Storage Namespace

All three applets share one flash keystore. The `owner` tag prevents cross-applet wipe.

| Key ID range | Owner applet |
|---|---|
| 00 (reserved) | SC-HSM sentinel (device auth) |
| 01–7F | SC-HSM |
| 80–8F | PIV (9A→80, 9C→81, 9D→82, 9E→83, retired→84–8F) |
| 90–92 | OpenPGP (SIG→90, DEC→91, AUTH→92) |
| FF | Invalid — rejected by all commands |
