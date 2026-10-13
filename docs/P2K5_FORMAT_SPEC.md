# P2K5 Flash Storage Format Specification

**Status**: Design document (not yet implemented)
**Date**: 2026-04-12
**Supersedes**: P2K4 format (no backwards compatibility maintained)
**Upgrade path**: Re-INITIALIZE required after firmware update. All P2K2/P2K3/P2K4 read paths are removed.

> **Note (2026-10-12):** this spec predates [STORAGE_V2.md](STORAGE_V2.md), the
> 2.0 keystore design. Its references to the WAL assume a write-ahead log the
> firmware never used; 2.0 removes it. Check STORAGE_V2 before implementing
> anything here.

## 1. Overview

P2K5 restructures the on-flash key object format to separate encrypted and
unencrypted data within each sector. Key changes from P2K4:

- Public key material moves from the encrypted payload to cleartext metadata.
- The BLAKE2s-256 hash of the private key is **removed** from the sector header.
- AES-256-GCM encrypts **only** the private key; all cleartext metadata fields
  are bound as GCM Additional Authenticated Data (AAD).
- All key types, including RSA-4096, fit in a single 4 KiB sector.
- An encrypted config block at KeyId 0xFD stores reversible device policy flags.

## 2. Sector Layout

Each key object occupies exactly one 4 KiB (4096-byte) sector. The sector is
divided into three regions: unencrypted header, encrypted private key, and
GCM authentication overhead.

```
Offset  Size   Field                Description
------  -----  -------------------  -------------------------------------------
0x000   4      sector_magic         b"P2HM" (unchanged from P2K4)
0x004   4      blob_magic           b"P2K5"
0x008   4      key_id               u32 LE (partition|applet|reserved|proto_ref)
0x00C   1      key_type             KeyType discriminant (0x01-0x10)
0x00D   1      algorithm            AlgorithmId discriminant
0x00E   1      key_flags            access conditions (bit 0=SIGN, 1=DECRYPT,
                                     2=DERIVE, 3=NO_EXPORT)
0x00F   1      key_domain           domain tag (0 = default)
0x010   4      use_count            u32 BE, monotonic usage counter
0x014   4      generation           u32 BE, monotonic generation counter
0x018   1      flags                sector flags bitfield (see below)
0x019   1      seq_no               rollback detection (0-255, wrapping)
0x01A   2      enc_len              u16 LE, encrypted payload length in bytes
0x01C   2      pub_len              u16 LE, public key length (0 if none)
0x01E   2      reserved_0           must be 0x0000
0x020   4      crc32                CRC32 of header[0x00..0x20] (excl. crc32
                                     field) || ciphertext || tag || nonce ||
                                     public_key
0x024   N      public_key           uncompressed EC point or RSA modulus+exp
                                     (N = pub_len; 0 for symmetric/EF)
0x024+N 12     nonce                AES-256-GCM nonce (random per write)
0x030+N E      ciphertext           AES-256-GCM ciphertext (E = enc_len)
0x030+N+E 16   tag                  AES-256-GCM authentication tag
                                     (remaining bytes to 0xFFF are 0xFF)
```

### 2.1 Header Size

The fixed header occupies bytes 0x000 through 0x023 (36 bytes). The variable
portion begins at 0x024 with the public key.

### 2.2 Flags Bitfield (offset 0x18)

```
Bit  Name             Meaning
---  ---------------  ---------------------------------------------------------
 0   has_private      Sector contains encrypted private key material (enc_len>0)
 1   has_encrypted    Sector contains an encrypted payload (keys, config, or EF)
 2   ef_file          Sector is an EF file record (data encrypted for integrity)
 3   has_public       Sector contains a public key in cleartext
 4-7 reserved         Must be 0
```

Typical flag combinations:
- `0x0B` (bits 0,1,3) — asymmetric key with private and public components
- `0x02` (bit 1)      — encrypted config block (no private key, no public key)
- `0x06` (bits 1,2)   — EF file record (data encrypted for tamper resistance)
- `0x03` (bits 0,1)   — symmetric key or Ed25519/X25519 (private only, no pub)

### 2.3 Endianness

All multi-byte integers are **little-endian** except:
- `use_count` and `generation` are **big-endian** (consistent with DKEK
  exchange format).

## 3. Unencrypted Metadata Fields

The following fields are stored in cleartext and are always readable without
decryption. They are authenticated by inclusion in the GCM AAD.

| Field | Offset | Size | Description |
|---|---|---|---|
| sector_magic | 0x00 | 4 | b"P2HM" — identifies a valid sector |
| blob_magic | 0x04 | 4 | b"P2K5" — format version |
| key_id | 0x08 | 4 | Full structured key identifier |
| key_type | 0x0C | 1 | Algorithm family (RSA/EC/AES/Generic) |
| algorithm | 0x0D | 1 | Specific algorithm (e.g. ECDSA-P256 = 0x13) |
| key_flags | 0x0E | 1 | Access conditions |
| key_domain | 0x0F | 1 | Domain separation tag |
| use_count | 0x10 | 4 | Operation counter |
| generation | 0x14 | 4 | Write generation counter |
| flags | 0x18 | 1 | Sector type flags |
| seq_no | 0x19 | 1 | Rollback detection counter |
| enc_len | 0x1A | 2 | Encrypted payload size |
| pub_len | 0x1C | 2 | Public key size |
| reserved_0 | 0x1E | 2 | Reserved, zero |
| crc32 | 0x20 | 4 | Integrity check over entire sector content |
| public_key | 0x24 | N | Public key material (cleartext) |

**Public key contents by key type:**

| Key Type | pub_len | Contents |
|---|---|---|
| EcPrivateP256 | 65 | Uncompressed SEC1 point (04 \|\| X \|\| Y) |
| EcPrivateP384 | 97 | Uncompressed SEC1 point |
| EcPrivateP521 | 133 | Uncompressed SEC1 point |
| EcPrivateK256 | 65 | Uncompressed SEC1 point |
| EcPrivateBrainpoolP256 | 65 | Uncompressed SEC1 point |
| EcPrivateBrainpoolP384 | 97 | Uncompressed SEC1 point |
| EcPrivateBrainpoolP512 | 129 | Uncompressed SEC1 point |
| Ed25519 | 32 | Compressed Edwards point |
| X25519 | 32 | Montgomery u-coordinate |
| RsaPrivate2048 | 260 | mod_len(2 BE) \|\| modulus(256) \|\| exponent(<=4) |
| RsaPrivate3072 | 388 | mod_len(2 BE) \|\| modulus(384) \|\| exponent(<=4) |
| RsaPrivate4096 | 516 | mod_len(2 BE) \|\| modulus(512) \|\| exponent(<=4) |
| Aes128/192/256 | 0 | No public component |
| Bip32Master | 0 | No public component |
| EfFile | 0 | No public component |

## 4. Encrypted Section

### 4.1 What Is Encrypted

Only the private key material is encrypted. The encrypted payload contains:

```
Offset (relative)  Size  Field
-----------------  ----  --------------------------------
0                  N     private_key (raw scalar / DER)
```

There is no additional framing inside the encrypted blob. The `enc_len` field
in the header specifies the exact plaintext length; GCM handles arbitrary
lengths without padding.

### 4.2 KEK Derivation

The per-key Key Encryption Key is derived identically to P2K4:

```
KEK = HKDF-SHA256(
    ikm  = SMK,                                    // Storage Master Key (32 bytes)
    salt = [],                                      // empty
    info = b"pico2hsm-keyobj-v1" || [proto_ref],    // 19 bytes
    len  = 32                                       // AES-256 key
)
```

`proto_ref` is the low byte (bits 7-0) of `key_id`.

### 4.3 GCM Parameters

- **Algorithm**: AES-256-GCM
- **Nonce**: 12 bytes, randomly generated per write, stored at offset 0x024+pub_len
- **Plaintext**: private key bytes only (enc_len bytes)
- **AAD**: header bytes 0x000 through 0x023 (36 bytes) concatenated with the
  public key bytes (pub_len bytes). Total AAD = 36 + pub_len bytes.
- **Tag**: 16 bytes, stored immediately after ciphertext

```
AAD = header[0x00..0x24] || public_key[0..pub_len]
```

This binding means any modification to the cleartext metadata (key_type,
algorithm, flags, public key, etc.) will cause GCM tag verification to fail
on decryption.

### 4.4 CRC32 Coverage

The CRC32 at offset 0x20 covers:

```
header[0x00..0x20]   (32 bytes, excluding the crc32 field itself)
  || public_key      (pub_len bytes)
  || nonce           (12 bytes)
  || ciphertext      (enc_len bytes)
  || tag             (16 bytes)
```

This provides a fast pre-decryption integrity check (catches bit errors,
partial writes, corruption) without needing the SMK.

## 5. EF File Records

Elementary File (EF) entries (e.g., EF.C.DevAut certificates, CE certificates,
PRKD descriptors) use the same sector format as key objects, with GCM
encryption for tamper resistance. Although EF data is not secret (certificates
are public by nature), encrypting it prevents an attacker with flash access
from substituting forged certificates or modifying metadata without detection.

```
flags        = 0x06           (bits 1,2: has_encrypted + ef_file)
enc_len      = D              (EF data length)
pub_len      = 0              (no public key)
key_type     = 0x10           (EfFile discriminant)
algorithm    = 0x00           (not applicable)
key_flags    = 0x00
```

The EF file data is encrypted with AES-256-GCM using a per-slot KEK derived
from the SMK, identical to the key object KEK derivation:

```
KEK_ef = HKDF-SHA256(ikm=SMK, salt=[], info=b"pico2hsm-keyobj-v1" || [proto_ref], len=32)
```

The sector layout follows the standard P2K5 pattern:

```
Offset  Size   Field
------  -----  -------------------
0x000   36     Fixed header (flags=0x06, enc_len=D, pub_len=0)
0x024   12     Nonce (random per write)
0x030   D      Ciphertext (AES-256-GCM encrypted EF data)
0x030+D 16     GCM authentication tag
               Remaining bytes to 0xFFF are 0xFF
```

The GCM AAD is the 36-byte fixed header (no public key for EF records):

```
AAD = header[0x00..0x24]
```

This binding means any modification to the header metadata (key_id, key_type,
flags) will cause GCM tag verification to fail on decryption. The CRC32 at
offset 0x20 provides a fast pre-decryption corruption check (identical to
key object sectors).

Maximum EF file data size = 4096 - 36 - 12 - 16 = 4032 bytes. This exceeds
the largest expected EF file (RSA-4096 CE certificate at ~1200 bytes).

## 6. Changes from P2K4

### 6.1 Public Key Moved to Cleartext

In P2K4, both the private and public keys are inside the GCM-encrypted blob:

```
P2K4: header(21) || ENC(priv_key || pub_len(2) || pub_key) || tag(16) || nonce(12)
```

In P2K5, only the private key is encrypted. The public key is in the cleartext
metadata region, authenticated by inclusion in the GCM AAD:

```
P2K5: header(36) || public_key(N) || nonce(12) || ENC(priv_key) || tag(16)
```

**Rationale**: Public keys are not secret. Moving them to cleartext:
- Enables key inventory operations without decryption
- Reduces the encrypted payload size, improving GCM performance
- Allows RSA-4096 to fit in a single sector (see below)

Note: EF file data (certificates, PRKDs) is encrypted for tamper resistance
even though the data is not secret. See §5 and §10.4.

### 6.2 BLAKE2s Hash Removed

P2K4 stores a BLAKE2s-256 hash of the decrypted private key plaintext in the
sector header (bytes 18-49 of ObjectHeader). P2K5 removes this field entirely.

**Rationale**: The BLAKE2s hash is a **privacy leak**. An attacker with a flash
dump can compute BLAKE2s of candidate private keys and compare against the
stored hash, enabling offline brute-force verification of key guesses. While
this is impractical for high-entropy keys (EC scalars, RSA primes), it is a
real concern for:

- Symmetric keys derived from passwords
- BIP32 master seeds with low entropy
- Keys imported from other systems with unknown entropy

The GCM authentication tag already provides integrity verification after
decryption. The CRC32 provides pre-decryption corruption detection. The
BLAKE2s hash adds no security value beyond these two mechanisms and creates
an unnecessary oracle.

### 6.3 Single-Sector RSA-4096

In P2K4, RSA-4096 keys may require 2 sectors:

```
P2K4 RSA-4096:
  header(21) + priv_key(~2350) + pub_len(2) + pub_key(~516) + tag(16) + nonce(12)
  = ~2917 bytes encrypted payload → needs header(50) + 2917 = 2967 bytes
  With page-aligned rounding, may exceed 4096.
```

In P2K5, only the private key is encrypted:

```
P2K5 RSA-4096:
  header(36) + pub_key(516) + nonce(12) + priv_key_enc(~2350) + tag(16)
  = 2930 bytes total → fits in one 4096-byte sector
```

This simplifies the storage manager (no multi-sector allocation, no
sector_count > 1 handling for data sectors).

### 6.4 Header Structure Changes

| Aspect | P2K4 | P2K5 |
|---|---|---|
| Blob magic | b"P2K4" (inside encrypted blob) | b"P2K5" (in sector header) |
| Header size | 50 bytes (ObjectHeader) | 36 bytes (fixed) + pub_len (variable) |
| BLAKE2s in header | 32 bytes | Removed |
| Public key | Inside encrypted blob | Cleartext, AAD-bound |
| sector_count | 1 or 2 | Always 1 |
| Encrypted payload | priv + pub + pub_len | priv only |

### 6.5 Blob Magic vs Sector Magic

P2K4 uses `SECTOR_MAGIC` (b"P2HM") at the sector level and `KEY_MAGIC`
(b"P2K4") inside the encrypted blob. P2K5 places `blob_magic` (b"P2K5") in
the cleartext sector header at offset 0x04, so the format version is
identifiable without decryption. `SECTOR_MAGIC` (b"P2HM") remains at
offset 0x00.

## 7. Encrypted Config Block

### 7.1 Purpose

The encrypted config block stores device policy flags that must survive
power cycles but remain reversible (unlike OTP fuses). It is stored as a
standard P2K5 sector at **KeyId 0x000000FD** (proto_ref = 0xFD, partition 0,
SC-HSM applet).

### 7.2 Flash Format

```
sector_magic   = b"P2HM"
blob_magic     = b"P2K5"
key_id         = 0x000000FD
key_type       = 0x04 (Generic)
algorithm      = 0x00
key_flags      = 0x00
key_domain     = 0x00
use_count      = 0x00000000
generation     = <monotonic, incremented on each config write>
flags          = 0x02 (bit 1: has_encrypted)
seq_no         = <monotonic>
enc_len        = 16
pub_len        = 0
```

The 16-byte config plaintext is encrypted with AES-256-GCM using the standard
per-key KEK derived from the SMK with proto_ref = 0xFD:

```
KEK_config = HKDF-SHA256(ikm=SMK, salt=[], info=b"pico2hsm-keyobj-v1" || [0xFD], len=32)
```

### 7.3 Config Block Plaintext Layout

```
Offset  Size  Field           Description
------  ----  --------------  -------------------------------------------
0x00    1     flags_0         Primary policy flags (see below)
0x01    1     flags_1         Reserved, must be 0x00
0x02    2     config_version  u16 LE, monotonic config counter
0x04    4     reserved_1      Must be 0x00000000
0x08    8     reserved_2      Must be 0x0000000000000000
```

Total: 16 bytes.

### 7.4 flags_0 Bitfield

```
Bit  Name                   Description
---  ---------------------  -----------------------------------------------
 0   peer_enrolled          At least one peer public key has been enrolled
 1   dkek_exchange_locked   Unauthenticated DKEK exchange permanently
                            disabled (requires SO-PIN re-INITIALIZE to clear)
 2   pin_always_required    No session PIN mode allowed; PIN must be
                            verified before every crypto operation
 3   key_export_disabled    Global export disable — overrides per-key
                            key_flags bit 3 (NO_EXPORT); prevents all
                            DKEK-wrapped key export
 4-7 reserved               Must be 0
```

### 7.5 Operational Semantics

**Creation**: The config block is created during INITIALIZE with all flags
cleared (0x00) and config_version = 0.

**Read**: The firmware reads and decrypts the config block at boot (after SMK
derivation). If the sector is absent or corrupt, the device **fails closed**:
all flags are treated as most-restrictive (peer_enrolled = true,
dkek_exchange_locked = true, etc.). This prevents an attacker with flash
write access from bypassing policy by erasing the config sector. A fresh
INITIALIZE (which requires SO-PIN) creates a new config block with open
policy.

**Write**: Each config modification increments `config_version` (u16 LE,
wrapping at 65535 back to 0) and `generation` (u32 BE in the sector header).
The sector is erased and rewritten atomically via the WAL (never implemented; see the note at the top).

**INITIALIZE**: Erases the config block along with all key material. A fresh
config block with all flags cleared is written. This requires SO-PIN
authentication, making it the authorized mechanism to reverse any policy flag.

**ENROLL_PEER (P1=0x3D)**: Sets `peer_enrolled` (bit 0) after successfully
storing a peer's public key. This flag is sticky until INITIALIZE.

**DKEK exchange guard**: Before accepting an unauthenticated DKEK import:
1. Read config block.
2. If `peer_enrolled` is set, verify that the corresponding peer public key
   exists in the keystore.
3. If the peer public key is missing (flash erasure attack), refuse the
   exchange with SW 0x6985 (conditions of use not satisfied).

## 8. Upgrade Path

**No backwards compatibility is maintained.** All P2K2, P2K3, and P2K4 read
paths are removed from the codebase. The firmware reads and writes P2K5 only.

After a firmware update from any prior version, the user must re-INITIALIZE
the device. The storage scanner rejects any sector where `blob_magic` (offset
0x04) is not `b"P2K5"` — such sectors are treated as blank/corrupt.

Firmware downgrade also requires re-INITIALIZE, since older firmware cannot
parse P2K5 sectors.

## 9. Size Examples

### 9.1 EC P-256 Key

```
Fixed header:           36 bytes
Public key (uncomp.):   65 bytes
Nonce:                  12 bytes
Encrypted private key:  32 bytes
GCM tag:                16 bytes
─────────────────────────────────
Total:                 161 bytes  (of 4096 sector)
```

### 9.2 EC P-384 Key

```
Fixed header:           36 bytes
Public key (uncomp.):   97 bytes
Nonce:                  12 bytes
Encrypted private key:  48 bytes
GCM tag:                16 bytes
─────────────────────────────────
Total:                 209 bytes
```

### 9.3 EC P-521 Key

```
Fixed header:           36 bytes
Public key (uncomp.):  133 bytes
Nonce:                  12 bytes
Encrypted private key:  66 bytes
GCM tag:                16 bytes
─────────────────────────────────
Total:                 263 bytes
```

### 9.4 Ed25519 Key

```
Fixed header:           36 bytes
Public key:             32 bytes
Nonce:                  12 bytes
Encrypted private key:  32 bytes
GCM tag:                16 bytes
─────────────────────────────────
Total:                 128 bytes
```

### 9.5 RSA-2048 Key

```
Fixed header:           36 bytes
Public key:            260 bytes  (2 + 256 modulus + 2-4 exponent)
Nonce:                  12 bytes
Encrypted private key:~1192 bytes  (PKCS#1 DER)
GCM tag:                16 bytes
─────────────────────────────────
Total:               ~1516 bytes
```

### 9.6 RSA-4096 Key

```
Fixed header:           36 bytes
Public key:            516 bytes  (2 + 512 modulus + 2-4 exponent)
Nonce:                  12 bytes
Encrypted private key:~2350 bytes  (PKCS#1 DER)
GCM tag:                16 bytes
─────────────────────────────────
Total:               ~2930 bytes  (fits in one 4096-byte sector)
```

### 9.7 AES-256 Symmetric Key

```
Fixed header:           36 bytes
Public key:              0 bytes
Nonce:                  12 bytes
Encrypted key:          32 bytes
GCM tag:                16 bytes
─────────────────────────────────
Total:                  96 bytes
```

### 9.8 BIP32 Master Key

```
Fixed header:           36 bytes
Public key:              0 bytes
Nonce:                  12 bytes
Encrypted key:          64 bytes  (32 seed + 32 chain code)
GCM tag:                16 bytes
─────────────────────────────────
Total:                 128 bytes
```

### 9.9 EF File Record (e.g., 2 KB certificate)

```
Fixed header:           36 bytes
Nonce:                  12 bytes
Encrypted EF data:    2048 bytes
GCM tag:                16 bytes
─────────────────────────────────
Total:                2112 bytes
```

### 9.10 Encrypted Config Block

```
Fixed header:           36 bytes
Public key:              0 bytes
Nonce:                  12 bytes
Encrypted config:       16 bytes
GCM tag:                16 bytes
─────────────────────────────────
Total:                  80 bytes
```

## 10. Security Analysis

### 10.1 Attacker Model: Flash Dump Access

An attacker who obtains a physical dump of the flash chips (e.g., desoldered
SPI flash, JTAG access before lockdown, cold boot attack on powered device)
can read all sector data.

**What the attacker CAN learn:**

- Key inventory: how many keys exist, their KeyIds, and slot assignments
- Key types and algorithms: which curves, RSA sizes, or symmetric algorithms
  are in use
- Public keys: all EC public points and RSA moduli (these are mathematically
  public by definition)
- Key metadata: use counts, generation numbers, domain tags, access flags
- Config block ciphertext (but not its contents)
- EF file ciphertext (but not its contents — certificates are encrypted)
- Sector allocation and directory structure

**What the attacker CANNOT learn:**

- Private key material (EC scalars, RSA CRT parameters, symmetric key bytes)
  -- protected by AES-256-GCM under SMK-derived KEK
- PIN hashes (stored in separate PIN slot mechanism, also encrypted)
- Config block contents (encrypted with SMK-derived KEK)
- EF file contents: certificates, device authentication data — encrypted
  with per-slot KEK for tamper resistance (not secrecy)
- The Storage Master Key (derived from device-unique keys + PIN, never stored
  in flash)

### 10.2 Why BLAKE2s Removal Matters

The P2K4 BLAKE2s-256 hash of the private key plaintext is stored in the
sector header in cleartext. This creates an offline verification oracle:

1. Attacker dumps flash and extracts the BLAKE2s hash from the sector header.
2. Attacker guesses a candidate private key.
3. Attacker computes BLAKE2s(candidate) and compares to the stored hash.
4. Match confirms the guess; mismatch eliminates it.

This is equivalent to an unsalted password hash. While 256-bit EC scalars
have sufficient entropy to resist brute force, the attack is meaningful for:

- **Low-entropy symmetric keys**: AES keys derived from user passwords via
  weak KDFs, or imported from systems with poor entropy sources.
- **BIP32 seeds**: 12-word or 24-word BIP39 mnemonics have 128-256 bits of
  entropy, but the search space is structured (dictionary words), and
  specialized hardware (GPU clusters) can evaluate billions of BLAKE2s
  hashes per second.
- **Imported keys**: Keys imported via DKEK exchange may have unknown
  entropy characteristics.

Removing the BLAKE2s hash eliminates this oracle entirely. The GCM
authentication tag cannot be used as a substitute oracle because verifying
it requires the KEK (derived from the SMK, which requires the device key
and user PIN).

### 10.3 GCM AAD Binding Prevents Metadata Tampering

All cleartext metadata fields are included in the GCM AAD:

```
AAD = header[0x00..0x24] || public_key[0..pub_len]
```

This means an attacker who modifies any cleartext field (e.g., changing
`key_type` from EC to RSA, or substituting a different public key) will
cause GCM tag verification to fail when the firmware attempts decryption.

Specific attacks prevented:

- **Algorithm confusion**: Changing `key_type` or `algorithm` to cause the
  firmware to misinterpret the decrypted private key bytes (e.g., treating
  an EC scalar as an AES key).
- **Key ID substitution**: Swapping `key_id` to make one key slot point to
  another's encrypted material. The KEK derivation uses `proto_ref` from
  the `key_id`, so a mismatched key_id will also produce a wrong KEK,
  providing double protection.
- **Public key substitution**: Replacing the public key with an attacker-
  controlled key while keeping the same encrypted private key. The AAD
  binding detects this.
- **Flag manipulation**: Clearing `key_flags` bit 3 (NO_EXPORT) to enable
  export of a key that was marked non-exportable.
- **Rollback of metadata**: Replaying an older sector (lower generation or
  use_count) is detected by both seq_no checking and the AAD binding (if
  the values differ from the original write).

### 10.4 EF File Encryption Prevents Certificate Substitution

EF file records (CE certificates, PRKD descriptors, EF.C.DevAut) contain
data that is public by nature — certificates are meant to be read by
relying parties. However, encrypting EF files with GCM provides tamper
resistance that CRC32 alone cannot:

**Attack scenario without EF encryption:**

1. Attacker gains physical access to the device's flash.
2. Attacker locates the CE certificate sector for key slot 01 (EF 0xCE01).
3. Attacker replaces the certificate with a forged one binding the same
   key ID to a different identity or a rogue public key.
4. Attacker recomputes the CRC32 for the modified sector.
5. A relying party reads the forged certificate and trusts the wrong identity.

**Defense with EF encryption:**

1. The CE certificate is encrypted with AES-256-GCM under a per-slot KEK
   derived from the SMK.
2. The attacker cannot forge a valid ciphertext without the SMK.
3. Any modification to the ciphertext or header causes GCM tag verification
   to fail on decryption.
4. The firmware returns an error rather than serving tampered data.

**Why encryption rather than HMAC:**

Using the same GCM encryption path for all sector types (keys, config, EF
files) unifies the code path and eliminates an entire class of bugs where
different integrity mechanisms diverge. The performance cost is minimal: a
typical CE certificate is ~300-700 bytes, and AES-256-GCM on Cortex-M33
processes this in under 1 ms. The tradeoff is that EF reads now require
the SMK to be available (which it always is after boot), but this is the
same requirement that key reads already have.

**Note on public key visibility:** Public keys remain in cleartext in the
sector header (the `public_key` field at offset 0x24) for key object
sectors. This is deliberate — public keys are mathematically public and
need to be readable for key inventory operations. EF files do not have a
`public_key` field (pub_len = 0); their entire payload is in the encrypted
region.

### 10.5 Config Block Prevents Peer Pubkey Erasure Attack

**Attack scenario without config block:**

1. Device A and Device B are enrolled as peers (each stores the other's
   public key for authenticated DKEK exchange).
2. Attacker gains physical access to Device A's flash.
3. Attacker erases the sector containing Device B's peer public key.
4. Attacker presents a rogue Device C to Device A for DKEK exchange.
5. Device A, having lost Device B's key, accepts Device C as a new peer.
6. Attacker extracts keys via Device C.

**Defense with config block:**

1. When Device B's peer key is enrolled, the `peer_enrolled` flag (bit 0)
   is set in the config block.
2. The config block is encrypted with the SMK-derived KEK. The attacker
   cannot clear the flag without knowing the SMK.
3. On DKEK exchange, the firmware checks: if `peer_enrolled` is set, a
   valid peer public key must exist in the keystore.
4. If the peer key sector was erased, the check fails and the exchange is
   refused (SW 0x6985).
5. The only way to clear `peer_enrolled` is via INITIALIZE, which requires
   SO-PIN authentication and erases all keys — defeating the attack.

**Why encryption is necessary:** If the config block were stored in cleartext
(even with CRC32 integrity), the attacker could erase it entirely. On boot,
the firmware would see no config block and default to open policy (all flags
cleared). Encryption ensures the attacker cannot forge a valid config block
without the SMK, and erasure is detectable because `peer_enrolled` was set
in the encrypted config that the firmware cached in RAM at boot.

### 10.6 Remaining Attack Surface

- **Side-channel attacks**: GCM encryption/decryption on Cortex-M33 without
  hardware AES may leak timing information. Mitigated by constant-time
  library implementations but not formally verified.
- **Fault injection**: Voltage glitching during GCM tag verification could
  bypass authentication. Mitigated by RP2350 glitch detector (when properly
  configured) and redundant checks.
- **SMK compromise**: If the attacker obtains the SMK (e.g., via JTAG before
  lockdown, or by compromising the device key derivation), all flash
  encryption is broken. Mitigated by secure boot, JTAG disable via OTP,
  and device-unique key material.
