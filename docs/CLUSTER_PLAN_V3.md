# pico2hsm Domains and Multi-Way Sync: Design Plan V3

*Supersedes the domain, enrollment and sync parts of `CLUSTER_PLAN_V2.md`. The V2 DKEK exchange (§1) is kept and generalised. Date: 2026-10-11. Status: approved by the owner on 2026-10-11 (§12). P0 is merged and verified on hardware (single device, 2026-10-11). P1 is merged and verified on hardware; the format decisions it made are folded into §4, §6 and §8 below and listed in §11a. P2 (enrollment) is implemented on `feat/p2-enrollment` (host tests pass; hardware run pending); its decisions are in §4.4, §5.2, §6.4, §8 and §11b.*

---

## 0. Summary

A **domain** is a set of pico2hsm devices that share one DKEK. Devices join a domain through an authenticated enrollment. The new device may be enrolled against any existing member, so a device enrolled through another one is trusted by every member. Once in a domain, members keep their SC-HSM key sets in sync over any link: a USB hub, a LAN, a WAN, or files carried by hand. Each synced object is a signed, versioned record. Deletions are signed tombstones. Every device checks every record itself, so the daemon and the network are only couriers and are not trusted.

The design keeps **SmartCard-HSM / OpenSC compatibility**:
- The DKEK is still made from `sc-hsm-tool` shares.
- Wrapped keys use the CardContact wrap format, so `sc-hsm-tool --unwrap-key` and a real SmartCard-HSM can import them (§3).
- Sync metadata travels next to the standard blob, never inside it.

The production daemon is a new `pico2hsm-syncd` crate in the `pico2hsm-tool` repository (§10). The Python daemon in `tools/python` becomes the test harness and reference.

### Decisions this plan relies on

| Decision | Source |
|---|---|
| The device has no button; designs needing physical presence are excluded | Owner, 2026-10-11 (BOOTSEL shares an SPI line) |
| Rollback protection (S-15) is out of scope; disabling picoboot is future engineering | Owner, 2026-10-11 |
| The device must stay compatible with SmartCard-HSM / OpenSC | Owner, 2026-10-11 |
| The target is homelab first, small business next | Owner |

---

## 1. Where things stand (firmware at `fix/reset-deadlock-and-zeroize`)

| Piece | State |
|---|---|
| DKEK from shares (`KEY DOMAIN` P1=00, raw 32-byte share) | Works with `sc-hsm-tool --import-dkek-share`. Needs no PIN (A-01). The DKEK is persisted at key ref 0xFD and never overwritten while it is set. |
| Device identity | A P-256 key generated from the TRNG by SC-HSM INITIALIZE, at key reference 0xFE (corrected in P2, §4.2). Readable with `0x54/P1=30`. |
| Device-to-device DKEK transfer (`0x54/P1=35–38`) | Mutually authenticated. Uses ephemeral ECDH, signatures over a challenge from the target, and AES-GCM with AAD = the target's static key. Needs the SO-PIN on both devices. |
| Peer enrollment (`0x54/P1=3D`) | **One** peer slot (0xFC). *P1: replaced by a single-use pinned peer (§4.4); a 0xFC record migrates to it at boot.* |
| Generation counter | `u64` held **in RAM only**; it is reset on every boot. *P1: the persisted Lamport counter (§6.1).* |
| `GET_KEY_MANIFEST` (`0x54/P1=39`) | At most 32 entries; needs the user PIN. *P1: paged, no cap, optional object IDs (§8).* |
| `GET_STATE_HASH` (`0x54/P1=3A`) | A SHA-256 root over the keys; no on-device signature. |
| WRAP / UNWRAP (`0x72` / `0x74`) | **CardContact key blob** (P0, `feat/p0-cardcontact-wrap`): KCV = SHA-256(DKEK)[0..8], AES-256-CBC + AES-CMAC under SHA-256(DKEK‖counter) keys; EC P-256/384/521 and secp256k1, RSA (CRT out; CRT and plain in), AES; algorithm list in the blob's field. Known-answer tests against an independent Python reference and against pico-hsm's own `kek.c`. The old pico2hsm v2/v3 blobs still UNWRAP (deprecated, one release). KEY DOMAIN status/KCV follow OpenSC. Layout: `SC_HSM_APDU_REFERENCE.md` §3.32. |
| Tombstones | Designed in V2 §2d but not implemented. |
| Per-key policy (algorithm list 0x91, use counter 0x90) | In progress on branch `feat/key-usage-policy`. |
| Host side | Python daemon and library in `tools/python` (TCP/TLS, USB auto-sync, health checks). Rust `pico2hsm-tool` is a CLI and library with no sync code yet. |

## 2. Goals, non-goals, threat model

**Goals**
1. Enroll a new device into an existing domain securely, against the original device or any member.
2. Keep SC-HSM keys, and their certificates and PKCS#15 descriptors, in sync across any number of members.
3. Make deletion permanent: no resurrection after a partition, and no resurrection by a member coming back from long downtime.
4. Work over short-haul links (same host, LAN) and long-haul links (WAN, intermittent, store-and-forward).
5. Stay interoperable with `sc-hsm-tool` / OpenSC and real SmartCard-HSMs for DKEK shares and wrapped keys.

**Non-goals for this plan**
- Rollback protection (S-15, on hold).
- Quorum or M-of-N approval of operations. This is a later small-business feature; see §12.
- Quorum approval inside PIV/OpenPGP (P6 covers their sync; see §12a).
- Syncing PINs, retry counters, device identity or OTP state. These are always per-device.
- DKEK rotation inside a domain. Rotation means migrating to a new domain (§9).

**Threat model**

| Actor | Assumed capability | What the design guarantees |
|---|---|---|
| Network or relay (including a compromised daemon) | Reads, drops, reorders, replays and injects messages | It can delay or block sync. It cannot forge, alter or resurrect objects, learn key material, or enroll a device. |
| Someone with USB access, no PINs | Sends any APDU | Can read public metadata (§7.4). Cannot export key material, mint records, enroll devices or delete. |
| Holder of the user PIN | Uses keys | Can create and delete keys on the device it holds; those changes sync domain-wide. |
| Holder of the SO-PIN | Administers the device | Can enroll and revoke members. |
| Compromised member device | Holds the DKEK and a member key | Can mint records and tombstones until revoked. Mitigations: revocation and the optional delete grace period (§6.4). |
| Physical attacker with flash access | Out of scope | See S-15. |

## 3. Compatibility layer: build this first

Everything else depends on this layer, and it is also the main gap against the owner's compatibility requirement.

1. **CardContact wrap format for WRAP KEY (0x72) and UNWRAP KEY (0x74).**
   - Implement the SmartCard-HSM key-backup blob:
     - KCV = the first 8 bytes of SHA-256(DKEK) (confirmed: pico-hsm `kek.c` `dkek_kcv`);
     - key type;
     - key OID, allowed-algorithm list and access conditions, as length-prefixed fields;
     - AES-256-CBC encryption (IV = 0, 8-byte random prefix) with K_enc = SHA-256(DKEK ‖ 00000001);
     - AES-CMAC with K_mac = SHA-256(DKEK ‖ 00000002).
   - **Verify the exact layout against OpenSC `src/tools/sc-hsm-tool.c` (wrap and unwrap) and the CardContact documentation before coding.** Add known-answer tests from blobs produced by `sc-hsm-tool` and, if one is available, a real SmartCard-HSM.
   - The current pico2hsm-format blobs (version 0x02) stay importable for one release, with an UNWRAP compatibility path, then they are dropped. WRAP only produces the CardContact format.
   - The per-key policy from S-10 (allowed algorithms, use counter where the format allows it) travels in the blob's own fields, so backup and restore keeps the policy.
2. **KCV everywhere.** Use CardContact's KCV, the first 8 bytes of SHA-256(DKEK), in `KEY DOMAIN` responses and status, so `sc-hsm-tool` prints a check value the owner can compare across devices.
3. **DKEK shares.** The current behaviour stays: `sc-hsm-tool` decrypts the password-protected share file on the host and sends the raw 32-byte share. Shares combine by XOR (pico-hsm `import_dkek_share`), which the firmware already did. The KEY DOMAIN response had its first two bytes swapped and P1=00 without data (the status query) was refused; both fixed in P0.

**Acceptance test:**
1. Create shares with `sc-hsm-tool --create-dkek-share`.
2. Initialise two pico2hsm devices from them and check that the KCVs match.
3. Wrap a key on device A with `sc-hsm-tool --wrap-key` and unwrap it on device B with `--unwrap-key`.
4. Do the same with blobs taken from, and sent to, a real SmartCard-HSM if one is available.

## 4. Domain identity and membership

### 4.1 Domain key
Every member derives the same **domain signing key** from the DKEK:

```
okm       = HKDF-SHA256(ikm = DKEK, salt = "pico2hsm-domain-v1", info = "sign", L = 48)
d_domain  = OS2IP(okm) mod n            # P-256 order n; d = 0 is refused (p = 2^-256)
Q_domain  = d_domain · G                # 65-byte uncompressed SEC1
domain_id = SHA-256(Q_domain)[0..16]
```

*As implemented in P1:* reducing 48 bytes mod n is the `hash_to_field` reduction of RFC 9380 §5.2 (L = 48 for P-256) with HKDF-Expand as the expander, so no retry loop is needed and every member gets the same key. Firmware: `firmware/src/domain/key.rs`; independent reference: `tools/python/pico2hsm/domain.py`; known answers: `firmware/tests/vectors/domain_v1.txt`.

- Any member can issue domain signatures. Anyone holding `Q_domain` can verify them.
- `domain_id` names the domain. Devices with different DKEKs can never agree on it by accident.
- The domain key never leaves a device. It is re-derived after each boot, as the DKEK is.

### 4.2 Member identity
Each device's member key is its identity key at key reference 0xFE (`GET_DEVICE_PUBLIC_KEY`, `0x54/P1=30`). *Corrected in P2:* that key is **generated from the TRNG by SC-HSM INITIALIZE**, not derived from OTP. (`derive_static_private_key`, `HKDF(otp_identity, "pico2hsm-noise-static-v1")`, exists in `security/dkek.rs` but nothing calls it.) So a re-INITIALIZEd device has a new member key and a new member ID. Binding a member to the physical device needs an OTP-derived identity; that is an open item tied to the provisioned-mode (OTP) work, which is on hold (§12, decision 8).

### 4.3 Member certificate
A member certificate is a fixed-format record of 187 bytes; X.509 is not needed:

```
MemberCert {
  version        u8      = 1
  domain_id      [16]
  member_id      [16]    // SHA-256(member_pub)[0..16]
  member_pub     [65]    // uncompressed P-256
  sponsor_id     [16]    // member ID of the issuer; = member_id when self-issued
  issued_lamport u64 BE  // the issuer's Lamport counter, see §6.1
  flags          u8      // bit0 = may sponsor others (default on, §12.3)
  sig_domain     [64]    // ECDSA-P256(d_domain), r||s, over
                         // SHA-256("pico2hsm-member-cert-v1" || all preceding fields)
}
```

Because the certificate is signed with the **domain** key, a device enrolled through B is accepted by A without A ever having seen B's enrollment.

**Member IDs instead of serials (P1 decision).** The draft used a sponsor-assigned `member_serial u32`. Two devices that form a domain independently from the same shares (§5.1, §5.3) would both give themselves serial 1, and a sponsor-plus-counter serial needs coordination a partitioned domain does not have. A member is therefore named by `member_id = SHA-256(member_pub)[0..16]`: derived, collision-free at 128 bits, the same in every certificate issued for that device (so a re-issue or a second sponsor never creates a second identity), and checkable by anyone who holds the certificate. Everything that said `member_serial` now carries the 16-byte `member_id` (§6.1, §6.3, §6.4, §8). The signature input begins with a context string so that no other message the domain key signs can be replayed as a certificate.

### 4.4 Member list on the device
- Replace the single peer slot 0xFC with a **member list**: up to 32 entries, one keystore object per slot in the domain namespace (`KeyId` partition 0xD0, applet 0x10, kind 0x01, slot), filled densely from slot 0. An entry is 197 bytes: `version(1) = 1 | status(1) (0 active, 1 revoked) | revoked_lamport(8 BE) | MemberCert(187)`. (One object for the whole list would exceed the keystore's 2400-byte object limit.)
- Revoked members stay in the list, marked as tombstoned (§6.4).
- *P2:* stored entries are version 2, 277 bytes: the version-1 layout (version byte 2) followed by `revoker_id(16) | revocation sig(64)` (zeros while active). A revoked entry therefore carries its whole revocation record, and GET_MEMBERS v2 hands it to hosts. Version-1 entries written by P1 still load. Entries are never removed: a revoked one counts toward the 32-entry cap until P5 compaction. A full list refuses new members with `6A84`.
- *P2, which certificate wins:* certificates for one member are ranked sponsor-issued above self-issued, then by higher `issued_lamport`, then by larger encoding. Of two revocations of one member, the one with the lowest `(revoked_lamport, revoker_id, sig)` is kept. Every device applies the same order, so the lists converge whatever order things arrive in.
- `ENROLL_PEER_PUBKEY` (P1=3D) remains for operator-pinned bootstrap only (§5.2). It now **pins** the peer for one exchange (record `KeyId` 0xD010_0200): SOURCE spends the pin before it releases the encrypted DKEK (step 3), TARGET before it installs it (step 4); failed steps keep it. A peer enrolled in the old permanent slot 0xFC is moved into the pin at boot and 0xFC is erased (the reference stays reserved).
- **Self certificate.** A device that holds the DKEK and has no member list issues its own certificate (sponsor = itself, may sponsor, `issued_lamport` = a freshly advanced counter): when the last share is imported, when an exchange installs the DKEK, and at boot for a device that held a DKEK before this firmware. With member IDs (§4.3) two devices formed independently never clash; P2's sponsor-issued certificate for a joiner replaces the joiner's self certificate by member ID.
- SC-HSM INITIALIZE wipes the whole domain namespace (member list, sidecars, pin) together with the DKEK; the Lamport counter is never reset.

## 5. Enrollment

### 5.1 First device: forming the domain
- **Option A:** `sc-hsm-tool --initialize --dkek-shares N`, then `--import-dkek-share` ×N. This is the standard path and keeps the shares as the offline backup.
- **Option B:** `pico2hsm-tool domain create` generates the DKEK on the device and requires the operator to export N shares in the `sc-hsm-tool` share-file format before the domain becomes usable. The firmware support for this would be new.

Either way, the device then issues its own member certificate (self-sponsored, §4.4) and reports `domain_id` and the KCV.

### 5.2 Joining a device (sponsor S, joiner J)
1. The operator authenticates with the SO-PIN on both devices.
2. Each daemon reads its device's member key. The operator compares a **short authentication string** (SAS). Both CLIs display it.
   - This is the out-of-band check that replaces a button.
   - For long-haul enrollment, read the string over the phone.
   - *As built in P2:* the SAS is eight decimal digits, ordered with the sponsor first: `h = SHA-256("pico2hsm-sas-v1" ‖ S_pub ‖ J_pub [‖ N_S ‖ N_J])`, `SAS = OS2IP(h[0..8]) mod 10^8`, shown as `1234 5678`.
     - **Local mode** (both devices on one host): no nonces. The host reads both keys itself.
     - **Remote mode:** eight digits alone would let a relay grind keys (≈2^27 work) until both sides' strings match. So the sponsor first sends `commit = SHA-256("pico2hsm-sas-commit-v1" ‖ S_pub ‖ N_S)`. The joiner answers with `J_pub ‖ N_J`. The sponsor then reveals `N_S`, and the joiner checks it against the commitment. A relay must commit before it learns the other side's nonce, so it gets one guess at 10^-8, as in Bluetooth numeric comparison.
     - Reference: `tools/python/pico2hsm/domain.py` (`sas`, `sas_commit`). Vectors: `firmware/tests/vectors/enrollment_v1.txt`. Host code: `pico2hsm-proto::sas`.
3. Each device pins the other device's key for this one exchange (P1=3D, single use).
4. The V2 exchange (P1=35–38) carries the DKEK. Nothing changes here except that step 3 replaces the permanent peer slot.
5. J derives `Q_domain` and checks that it matches the `domain_id` S announced. The KCV gives the same check.
6. S issues J's `MemberCert` (ISSUE_MEMBER_CERT, P1=45) and the record is synced to everyone.
   - *P2 binding:* S certifies only an operator-verified key. That is either the peer S sent its DKEK to in an exchange completed **in this card session**, or the peer currently pinned with P1=3D (the §5.3 path). Step 3 of the exchange records the first in RAM (session state, cleared at session end and by INITIALIZE). The second is the persisted pin. The certificate spends whichever it used.
   - S's own certificate must be active and have the may-sponsor flag. A revoked member is never certified (`6984`).
   - The Lamport counter is advanced on flash before anything changes. The certificate is stored in S's list and returned.
7. J pulls the member list and then the full object set (§7).
   - *P2:* J imports S's list with IMPORT_MEMBER_CERT (P1=49) and IMPORT_REVOCATION (P1=4A). Neither needs a PIN; the device checks the domain signature (§12.1). S imports J's back.
   - J certified itself when the DKEK arrived (§4.4). S's certificate outranks that one, so it replaces it.
   - `pico2hsm-tool domain enroll` does steps 1–7. It runs in local mode (two readers, one PC/SC session each) or remote mode (`--remote`, five pasted or file messages), and `domain sync-members` repeats step 7 between any two members.

### 5.3 Fallback joining through shares
A device can also join from the DKEK shares alone (standard `sc-hsm-tool` import). It then derives the same domain key and asks any member for a member certificate. That request still needs SO authentication on the member and the short-string check. This path is how a domain is recovered when no member is reachable.

*P2:* such a device certifies itself, as the first device did. Members formed this way import each other's self certificates directly: they are signed with the same domain key. A member can also certify it by pinning its key (P1=3D) and issuing (P1=45); the sponsor-issued certificate then replaces the self certificate everywhere.

### 5.4 A-01 once domains exist
After a device holds a DKEK and a member certificate, raw share import stays refused, as it is today: the DKEK is never replaced. The open window, right after an SO-authorised INITIALIZE, is unchanged for compatibility. Documented mitigations:
- compare the KCV after import;
- do the import in one sitting;
- optional: `pico2hsm-tool` runs INITIALIZE and the share imports in a single card session.

> **Session binding (verified on hardware, 2026-10-11).** The V2 exchange state (P1=35–38) lives in the card session. It is cleared when the host session ends (card power cycle, USB reset), like the SO-PIN. The daemon must keep one PC/SC connection per device for all four steps. Separate `opensc-tool` invocations do not work.

## 6. Object model

### 6.1 Versions
- Each device keeps a **persisted Lamport counter** (`u64`), which replaces the RAM-only generation counter. It is written before the change it numbers.
  - *P1:* it is a second record kind in the retry-counter log on internal flash (16-byte record `'L' | id 1 | value u64 LE | CRC-32 bound to the sector sequence`), carried over on sector rotation like the credential states, written through the core1→core0 FlashOp channel. `put_lamport` refuses a lower value. A command whose counter record cannot be written is refused with 6581 and changes nothing.
  - Numbered commands (P1): GENERATE KEY PAIR, GENERATE KEY, UNWRAP/IMPORT KEY, DELETE FILE, WRITE DATA, UPDATE BINARY — when the user PIN or SO-PIN is verified (unauthenticated APDUs cannot wear the log); the self certificate (§4.4). A refused command leaves a gap, which is harmless. INITIALIZE does not reset it.
- On any local change: `counter = max(counter, highest version seen) + 1`.
- Version = (counter, member_id); the member ID breaks ties (byte-wise comparison).
- Wall-clock time is never used for ordering. Only the daemon uses it, for garbage-collection timers.

### 6.2 Global object ID
- **Asymmetric keys:** the intrinsic CKA_ID OpenSC computes (`sc_pkcs15init_select_intrinsic_id`, `pkcs15-id-style = mozilla` from `pkcs15.profile`): **SHA-1 of the X coordinate** for EC keys and **SHA-1 of the modulus** for RSA, 20 bytes. *(Corrected in P1: the draft said SHA-256 truncated to 20 bytes, which is not what OpenSC 0.25 does. The ID is only a name; record integrity comes from signatures, and only a member could try to collide two IDs.)* It is computed from the public key on demand and never stored, so existing keys need no migration.
- **Symmetric keys and standalone files (CD/DCOD descriptors, CA certificates, data objects: prefixes C8, C9, CA, CD, CF):** a random 16-byte ID assigned when the object is created (GENERATE KEY, UNWRAP of an AES key, first write of the EF) and kept in the object's sidecar (§6.5). Objects from before P1 get theirs lazily, the first time an authenticated command needs it (`GET_KEY_MANIFEST` v2). A key's PRKD (C4) and EE certificate (CE) travel with the key and have no ID of their own.
- The one-byte SC-HSM key reference stays local to each device: an importing device picks any free slot and keeps CKA_ID and label in the PKCS#15 descriptor. Two members that each create "slot 3" never collide.
- **CKA_ID across devices:** an OpenSC-written PRKD (with a caller's `--id`, or the intrinsic ID) is an EF that travels with the key and is served as written. For a key without one, the PRKD the firmware synthesises now carries the intrinsic ID instead of the slot number, so the CKA_ID no longer depends on the slot.

### 6.3 Sync record
```
SyncRecord {
  version        u8 = 1
  domain_id      [16]
  object_id      [20]
  kind           u8       // 1 = key (with certificate/CD/PRKD), 2 = file/EF, 3 = member cert
  obj_version    (u64 lamport, [16] member_id)
  origin_id      [16]     // member ID of the member that minted this version
  meta_len u16, meta      // label, PKCS#15 descriptors, policy summary (public)
  blob_len u16, blob      // CardContact wrapped key (kind 1) or plain file content (kind 2)
  sig_member     [64]     // ECDSA(origin member key) over SHA-256(all preceding fields)
}
```

**Import rules, enforced on the device:**
- `domain_id` must match.
- The origin must be a member and not revoked as of this version.
- The signature must verify.
- The version must be higher than the one held for `object_id`.
- No tombstone may outrank it (§6.4).
- The blob must unwrap under the DKEK.

Imports are idempotent. Equal versions with equal hashes are a no-op. Equal versions with different hashes cannot happen from honest members; such a record is refused and logged.

### 6.4 Tombstones
```
Tombstone {
  version u8 = 1, domain_id [16], object_id [20],
  del_version   (u64, [16])   // must be higher than the version it deletes
  origin_id     [16]
  sig_member    [64]
}
```

**Rules:**
- **Delete wins:** a tombstone beats every record whose version is lower than it.
- The object can come back only as a *new* record with a higher version. That happens only through an explicit re-create on some member.
- **Member revocation** is a tombstone of kind 3. It needs the SO-PIN on the issuing member. A revoked member's records with versions above its revocation are refused everywhere.
  - *As built in P2:* a revocation is a 121-byte record signed with the domain key. Layout: `version(1)=1 | domain_id(16) | member_id(16) | revoker_id(16) | revoked_lamport(8 BE) | sig(64)`. The signature is over `SHA-256("pico2hsm-member-revoke-v1" ‖ the 57 bytes before it)`.
  - REVOKE_MEMBER (P1=46) needs the SO-PIN, and the revoking device's own certificate must be active with the may-sponsor flag. A device never revokes itself. The Lamport counter is advanced first, and `revoked_lamport` is the new value.
  - Other members take the revocation through IMPORT_REVOCATION (P1=4A), without a PIN. It is sent with the revoked member's certificate when that member is not listed yet, so the list can go on refusing it. A device accepts the revocation of itself (it then reports it in DOMAIN_STATUS flag `20` and can no longer sponsor or revoke).
  - **Permanence (owner decision 8, §12):** a revocation is permanent for that member key within the domain. ISSUE_MEMBER_CERT and IMPORT_MEMBER_CERT refuse a revoked member ID (`6984`), whatever the certificate's `issued_lamport`. The way back for that key is a new domain.
  - Re-INITIALIZE generates a new device key (§4.2), so the device then comes back as a **new** member. That needs the full enrollment: a sponsor's SO-PIN and the operator's SAS check, which are the real gate. The old member ID stays revoked. Binding revocation to the physical device needs the OTP-derived identity (open item, §4.2).
  - Certificates whose sponsor is listed as revoked with `issued_lamport` above the sponsor's `revoked_lamport` are refused, the §6.4 rule applied to certificates. Certificates accepted before a revocation stay.
  - **Meaning for P3:** a revoked member's records (and tombstones) with a version (`lamport`, `member_id`) whose Lamport value is above its `revoked_lamport` are refused on import everywhere. Those at or below it stay valid, because they were minted while the member was trusted. A revoked member's existing objects are therefore kept until some member supersedes or deletes them.
  - **Limit, stated plainly:** the domain key is derivable by every DKEK holder. A domain signature proves "a DKEK holder signed this", not which member did. So a compromised device that still holds the DKEK can mint certificates and revocations. Revocation stops honest members from enrolling through it or accepting its member-signed records (P3). Recovering from a compromised DKEK holder is a domain migration (§9).
- **Retention:** the daemon tracks which members have acknowledged each tombstone (`GET_STATE` per member).
  - A tombstone may be compacted once every non-revoked member has acknowledged it **and** a TTL (default 90 days) has passed.
  - A member that has been silent longer than the TTL is **fenced**. Its daemon must run a full pull before it may push, and records it minted with versions below the fence are refused. This is what stops a long-dead device from resurrecting deleted keys.
- **Optional, small-business:** a *delete grace period*. The tombstone is applied immediately, but the wrapped key is kept for N hours, during which an SO can mint a countermanding record. This limits the damage a compromised member's mass delete can do.

### 6.5 Where sync state lives on the device
- Each synced key gains a small sidecar object in the keystore: object_id, version, origin and the record hash, about 64 bytes.
  - *P1 layout (144 bytes, `KeyId` = the object's partition, applet 0x10, the object's 16-bit local ID):* `version(1)=1 | kind(1) (1 key, 2 file) | id_len(1) | flags(1) | object_id(20, zero-padded) | version(8 BE) | origin member ID(16) | record hash(32) | sig_member(64)`. P1 fills only the first 24 bytes; the rest is reserved for P3, so the format need not change. P1 writes sidecars only for objects with a random ID; asymmetric keys get theirs in P3, when they are first versioned.
- The signed record is reconstructed when it is exported (§7.4), so wrapped blobs are not stored twice.
  - **Snag:** the origin's signature must be kept, because only the origin can produce it. So the sidecar also stores `sig_member`, making it about 130 bytes.
- Tombstones and member certificates are keystore objects in their own `KeyId` namespace (new applet ID 0x10 = domain). That needs no format change: the A/B directory and blob encryption already handle it.

## 7. Anti-entropy sync

### 7.1 State summary
- The device keeps a two-level hash tree: 256 buckets keyed by the first byte of `object_id`. Each bucket hash is SHA-256 over its sorted (object_id, version, record_hash) entries, tombstones included. The root is SHA-256 over the bucket hashes.
- `GET_STATE` returns `domain_id ‖ lamport ‖ root ‖ sig_member(…)`, signed on the device as V2 §2e asked for.

### 7.2 Protocol between two peers, transport-agnostic
1. Exchange signed `GET_STATE` results. If the roots are equal, stop.
2. Exchange the 256 bucket hashes, about 8 KB, and find the buckets that differ.
3. For each differing bucket, exchange (object_id, version) lists.
4. For every object where the peer is newer, fetch its record or tombstone and import it on the device.
5. Repeat until the roots match. Both directions run independently.

Each step is idempotent, so an interrupted sync simply runs again. Over N members, pairwise sync spreads changes like gossip; no coordinator is needed.

### 7.3 Transports, all carrying the same messages
| Link | Transport |
|---|---|
| Same host (several devices on one USB hub) | The daemon talks to each device over PC/SC directly |
| LAN / WAN | TCP with mutual TLS (rustls); each daemon's TLS key is bound to its device by `SIGN_ENROLLMENT` (V2 §5) |
| Both ends behind NAT | Outbound connections to a dumb relay that forwards TLS ciphertext and holds no secrets (V2 §6 Model C) |
| Intermittent or air-gapped | **Bundles:** a file holding the sender's signed state, then records and tombstones. Carry it by any means (USB stick, email, git); the receiver imports it and writes a reply bundle. |

All payloads are signed and the keys inside them are wrapped, so transport security only adds confidentiality of metadata and protection against denial of service. Integrity never depends on it.

### 7.4 What each operation needs
| Operation | Authentication | Why |
|---|---|---|
| `GET_STATE`, bucket hashes, (id, version) lists | none | Public metadata. Optionally require the user PIN with a domain setting; this would need an unattended daemon to hold the PIN. |
| Export a sync record or tombstone | none | The blob is wrapped under the DKEK, which only members hold. This is a deliberate departure from SC-HSM WRAP (0x72), which needs the PIN. 0x72 itself is unchanged. |
| Import a record or tombstone | none (the device checks the member signature) | The authority is the origin member's signature, minted while a PIN-authenticated user made the change on that device. The daemon never holds a PIN. |
| Mint a record (local create, import or change) | user PIN | Happens as part of the normal key operation on the originating device |
| Mint a key tombstone | user PIN | Part of DELETE |
| Issue or revoke a member certificate | SO-PIN | Enrollment |

The decision behind importing without a PIN (open question Q1): a fully unattended daemon is only possible if imports are authorised by signatures rather than PINs. The cost is that USB access is enough to *apply* validly signed changes, which already came from a member, and nothing more.

## 8. Firmware APDU surface (vendor, `INS 0x54`)

| P1 | Name | Auth |
|---|---|---|
| 40 | DOMAIN_STATUS: domain_id, KCV, Q_domain, own member ID, lamport, mode (P1, layout in `SC_HSM_APDU_REFERENCE.md` §3.29) | none |
| 41 | GET_STATE (signed root) | none |
| 42 | GET_BUCKETS / GET_BUCKET(n) | none |
| 43 | EXPORT_RECORD(object_id), returns a SyncRecord or Tombstone | none |
| 44 | IMPORT_RECORD (chained or extended APDU) | signature checked on the device |
| 45 | ISSUE_MEMBER_CERT(member_pub [, flags]) (P2): returns the 187-byte certificate | SO-PIN; the key must be the peer of an exchange this device completed in this session, or the pinned peer (spent); own certificate active with may-sponsor |
| 46 | REVOKE_MEMBER(member_id) (P2): returns the 121-byte revocation | SO-PIN; own certificate active with may-sponsor; never itself |
| 47 | GET_MEMBERS (P1; paged, P2 = first slot; data `02` = version-2 entries with revocations, P2) | none |
| 48 | DOMAIN_CREATE (optional Option B: generate DKEK, export shares) | SO-PIN, right after INITIALIZE |
| 49 | IMPORT_MEMBER_CERT(cert) (P2) | none; domain signature checked on the device |
| 4A | IMPORT_REVOCATION(revocation [‖ cert]) (P2; 308 bytes needs an extended APDU) | none; domain signature checked on the device |
| 3A/3C/39/34 | Legacy V1 and V2 calls | Kept for one release, then removed |

All of these must be bounds-checked (V2 §8). Responses use the dispatcher's GET RESPONSE chaining and stay within `MAX_RESPONSE_DATA`. Large buffers must stay off the core1 stack (CLAUDE.md, core1 stack pitfall).

## 9. DKEK rotation = domain migration
The CardContact format ties each blob to one DKEK, so rotation is a migration:
1. Form a new domain (new shares) on one device.
2. Enroll the other devices into it.
3. On each key's home device, re-wrap it into the new domain: a new record in the new domain, with a tombstone in the old one.
4. Retire the old domain by revoking all its members.

`pico2hsm-tool domain migrate` automates this. The V2 epoch field (§2c) and the per-device "effective DKEK" (§2b) are **dropped**. Both break blob compatibility, and migration covers the same need.

## 10. Production daemon (`pico2hsm-tool` repository)

The workspace grows to:

```
crates/
  libpico2hsm/       existing: PC/SC transport and SC-HSM ops; add the domain/sync APDUs (§8)
  pico2hsm-proto/    new: SyncRecord / Tombstone / MemberCert / bundle codecs, no I/O,
                     fuzz targets, test vectors shared with the firmware tests
  pico2hsm-syncd/    new: the daemon
  pico2hsm-cli/      existing: add `domain create|status|enroll|revoke|migrate`,
                     `sync now|status`, `bundle export|import`
```

**Daemon design:**
- **Runtime:** tokio. PC/SC calls run on one dedicated blocking thread per device (pcsc handles are not `Send` everywhere), with timeouts. Devices are detected with `SCardGetStatusChange`.
- **State:** devices are the source of truth. The daemon keeps only a cache (peer addresses, last-seen roots, tombstone acknowledgements, fencing timers) in `~/.local/state/pico2hsm/` with mode 0700/0600 and atomic writes. Losing the cache costs one full resync, never correctness. That is why V2 §2f's HMAC'd state file is no longer critical; it is kept as cheap hardening.
- **Peers:**
  - Configured in TOML.
  - mTLS via rustls, with TLS keys pinned through `SIGN_ENROLLMENT`.
  - Connection limits, frame cap (64 KB), idle timeouts, rate limits (V2 §8 checklist).
  - Message structs zeroized where they hold blobs.
- **Modes:**
  - `serve` (systemd user unit, launchd agent);
  - `sync-once` for cron;
  - `bundle` for air-gapped links.
- **Observability:**
  - structured logs;
  - `pico2hsm-cli sync status`, showing per-peer root, lag and fenced members;
  - optional Prometheus text endpoint, local-only.
- **Platforms:** Linux first, then macOS and Windows; CI already builds all three.
- **Python daemon:** frozen as the reference implementation and test harness. It is removed from user docs once `pico2hsm-syncd` reaches parity.

## 11. Implementation phases (each ends with host tests plus a hardware run)

| Phase | Firmware | Host | Done when |
|---|---|---|---|
| **P0 Compatibility** — done; hardware-verified on one device (full suite plus `sc-hsm-tool` interop) and across two (`test_10::test_wrapped_key_moves_between_devices`: wrap on A, unwrap on B, B's signature verifies against A's public key) | CardContact wrap format and KCV (§3); compatibility UNWRAP for v0x02/v0x03 | Known-answer vectors in `firmware/tests/vectors/` (Python reference + pico-hsm) for `pico2hsm-proto` to reuse | `sc-hsm-tool` wrap/unwrap round trip across two devices (`tests/hw/test_11_dkek_roundtrip.py::TestCardContactInterop` covers one device) |
| **P1 Foundations** — done; full suite 349/0 and `test_18_domain` 6/6 on one device; two devices after the V2 exchange report the same domain_id and KCV with distinct member IDs (`test_10` 8/8) | Persisted Lamport counter; global IDs and PKCS#15 CKA_ID kept on import; domain key; member list replacing 0xFC; DOMAIN_STATUS | libpico2hsm APDUs; `domain status`; `pico2hsm-proto` (MemberCert, DOMAIN_STATUS decode, shared vectors) | Two devices from the same shares report the same domain_id |
| **P2 Enrollment** — implemented on `feat/p2-enrollment` (host tests pass; hardware run pending, `tests/hw/test_19_enrollment.py`) | ISSUE/REVOKE member cert; IMPORT cert/revocation; GET_MEMBERS v2; single-use pinned peer for the existing exchange | `domain enroll` (local and remote) with the short string; `domain revoke`, `members`, `sync-members` | Enroll C through B, then A accepts C's certificate (host test `a_member_enrolled_through_b_is_accepted_by_a`); A accepting C's *records* follows in P3 |
| **P3 Records** | Sidecars, EXPORT/IMPORT_RECORD, tombstones, signed GET_STATE, buckets | proto codecs and fuzzing | Create, delete and re-create converge across 3 devices on one host |
| **P4 Daemon** | (none) | `pico2hsm-syncd` USB mode, then TCP/mTLS, then bundles | 3 devices, one on another host, one sync by bundle only, all converge; partition and heal tests |
| **P5 Hardening** | Fencing and TTL enforcement; delete grace period | Relay (Model C), metrics, packaging | Chaos tests (kill mid-sync, reorder, replay); external review |
| **P6 PIV/OpenPGP** | Per-applet sync opt-in; slot/role records; per-device exclusions (§12a) | `domain applet-sync`; overwrite reporting | `ykman` / `gpg --card-status` show the same keys on every member; signing works on any member |

P0 is useful on its own, since it delivers the compatibility goal, and can ship before the rest.

### 11a. P1 as built (2026-10-11)

| Item | Decision |
|---|---|
| Lamport counter | Record kind `'L'` in the retry-counter log (§6.1); 6581 and no change when it cannot be written; read by `0x34`/`0x3C`/`0x3A`/`0x40`. |
| Member identity | 16-byte `member_id = SHA-256(member_pub)[0..16]` instead of `member_serial` (§4.3); versions tie-break on it. |
| Asymmetric object ID | OpenSC's intrinsic CKA_ID: SHA-1(x) / SHA-1(n), computed, not stored (§6.2). |
| Random object IDs | 16 bytes in a 144-byte sidecar, at creation; lazily for older objects (§6.2, §6.5). |
| Domain key | HKDF-SHA256 → 48 bytes → mod n (RFC 9380 reduction), vectors shared with the host tool (§4.1). |
| Member list | 32 slot objects of 197 bytes, partition 0xD0 / applet 0x10 (§4.4). |
| Pinned peer | Single use, spent before the DKEK is released or installed; 0xFC migrates (§4.4). |
| Self certificate | Issued when the DKEK appears and no list exists; also at boot for older DKEK holders (§4.4). |
| GET_KEY_MANIFEST | Paged by P2 (first key ref); data `02` adds the object ID per entry (64-byte entries). |
| Core1 stack | New worst SC-HSM path ≈ 85 KB (manifest v2 with lazy sidecar), below the PIV PUT DATA worst case (≈ 89 KB). |

### 11b. P2 as built (2026-10-11)

| Item | Decision |
|---|---|
| Issue binding | ISSUE_MEMBER_CERT certifies only the peer this device sent its DKEK to in this card session (recorded by exchange step 3, RAM only), or the currently pinned peer (§5.3). Either is spent. Never an arbitrary key, never itself. |
| Who may administer | A member whose own certificate is active and has may-sponsor issues and revokes. Default on (§12.3); `--no-sponsor` clears it. |
| Certificate ranking | Sponsor-issued > self-issued, then higher `issued_lamport`, then larger encoding. Duplicates and outranked certificates get `6A89`. |
| Revocation | 121-byte domain-signed record. Permanent per member key (decision 8). The earliest revocation wins. A revoked entry stays and counts toward the cap. |
| Imports | No PIN (§12.1). Every import feeds `lamport_seen`. |
| Capacity | 32 entries, revoked included. Full: `6A84`, refused before the counter moves. |
| Member list format | Version-2 entries (277 bytes); GET_MEMBERS v1 still serves 197-byte entries. |
| SAS | Eight digits, ordered sponsor first; committed nonces in remote mode (§5.2). |
| Remote mode | Implemented: five one-line messages (`pico2hsm-enroll-v1:`), pasted or through `--msg-dir`. |
| Core1 stack | Worst new path ≈ 86 KB (ISSUE through a pinned peer: `consume_pinned_peer` 9 KB frame; IMPORT_REVOCATION ≈ 85 KB), below the PIV PUT DATA worst case (≈ 89 KB). |

## 12. Owner decisions (2026-10-11)

1. **Signature-authorised import without a PIN:** yes. The daemon runs unattended (§7.4).
2. **State, bucket and id lists readable without a PIN:** yes, with a domain flag to tighten it later.
3. **Sponsoring:** controlled by the "may sponsor" flag in the member certificate, default on.
4. **Tombstone TTL and fencing period:** 90 days.
5. **Delete grace period:** yes, built in P5 (§6.4).
6. **Real SmartCard-HSM:** a passive member through manual `sc-hsm-tool` import is enough.
7. **PIV and OpenPGP sync:** **in scope**, as phase P6 (§12a). Distributed PIV/OpenPGP identities that work on any member are a capability no other product offers.
8. **Revocation is permanent (2026-10-11).** A revoked member ID can never be re-added to the domain, neither by an older certificate nor by a newly issued one. ISSUE_MEMBER_CERT and IMPORT refuse it (`6984`). The way back is a new domain. Because INITIALIZE generates a new device key (§4.2), a re-initialised device is a new member, and it gets in only through a sponsor's SO-PIN and the SAS check. Tying revocation to the physical device needs an OTP-derived identity, which is an open item held with the OTP / provisioned-mode work (OTP writes are on hold).

### 12a. PIV / OpenPGP sync (P6)

**What syncs.**
- PIV: slot keys (9A/9C/9D/9E/82–95) and data objects (certificates, CHUID, CCC, discovery, key history).
- OpenPGP: SIG/DEC/AUT keys and their algorithm attributes, fingerprints, generation times, cardholder data, URL, the cardholder certificate, and the C4 policy.

**What never syncs (per-device).**
- PINs, PUK, reset code, retry counters and PIN/PUK lockout.
- The PIV management key. It is per-device by default; a domain option can share it.
- The OpenPGP signature counter (DO 93); each card counts its own.
- Session state.
- Device-unique identifiers: the PIV GUID in the CHUID stays per-device unless "clone identity" is set, and the OpenPGP AID serial number is per-device.

**How it fits the object model.**
- `object_id = H("piv" ‖ slot)` or `H("openpgp" ‖ role)`, so the slot or role is the identity.
- Newest version wins per slot or role, with tombstones for cleared slots.
- Keys travel as DKEK-wrapped blobs inside SyncRecords. Neither spec defines a wrap format, so this is a vendor extension.

**Spec tension: an explicit opt-in.**
- Users of PIV and OpenPGP cards expect generated keys never to leave the card. Here they leave only wrapped under the domain DKEK and only to enrolled members; the domain as a whole is the token.
- Sync is enabled per applet with a domain setting (`domain applet-sync piv|openpgp on`), which needs the SO-PIN plus that applet's admin credential (the PIV management key, or OpenPGP PW3).
- Keys generated while sync is off stay device-bound and are never exported, matching the NO_EXPORT semantics.
- Hosts can see the difference: PIV metadata (Yubico `F7` origin) and OpenPGP key information (DO DE) report "imported" for keys received through sync.

**Conflicts.** Two members regenerating the same slot concurrently: the higher version wins and the loser's key is replaced everywhere. The daemon reports the overwrite, because a certificate issued for the losing key becomes invalid. The CLI warns before regenerating a synced slot.

## 13. What carries over from V2

| V2 item | V3 status |
|---|---|
| §1 5-step DKEK exchange | **Kept**, with the peer pinned for one exchange instead of a permanent 0xFC slot |
| §2a salted wrap_hash | Replaced by the record hash in signed records (no confirmable plaintext hash) |
| §2b per-device effective DKEK | **Dropped** (breaks compatibility) |
| §2c epoch in wrapped blob | **Dropped**; rotation is domain migration (§9) |
| §2d tombstones | **Kept**, redefined (§6.4), with member-acknowledged retention and fencing |
| §2e signed state attestation | **Kept** (GET_STATE signed on the device) |
| §2f HMAC'd state file | Downgraded to hardening; daemon state is a rebuildable cache |
| §5 mTLS enrollment, SIGN_ENROLLMENT | **Kept** for transport authentication |
| §6 NAT models | **Kept**, plus bundles for store-and-forward |
| §7 N ≤ 2 limit | **Lifted**; gossip anti-entropy works for any N. Quorum is still deferred. |
