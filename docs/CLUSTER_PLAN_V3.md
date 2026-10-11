# pico2hsm Domains and Multi-Way Sync: Design Plan V3

*Supersedes the domain, enrollment and sync parts of `CLUSTER_PLAN_V2.md`. The V2 DKEK exchange (§1) is kept and generalised. Date: 2026-10-11. Status: approved by the owner on 2026-10-11 (§12). P0 is merged and verified on hardware (single device, 2026-10-11). P1 is implemented on `feat/p1-foundations` (host tests pass; hardware run pending); the format decisions it made are folded into §4, §6 and §8 below and listed in §11a.*

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
| Device identity | A static P-256 key derived from the OTP identity key (`HKDF(otp_identity, "pico2hsm-noise-static-v1")`). Readable with `0x54/P1=30`. |
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
Each device's member key is the existing static identity key, `HKDF(otp_identity, "pico2hsm-noise-static-v1")`. On an unprovisioned debug board it comes from the development identity, and the device reports that it is in development mode.

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
2. Each daemon reads its device's member key. The operator compares a **short authentication string** of six words or digits derived from SHA-256(S_pub ‖ J_pub). Both CLIs display it.
   - This is the out-of-band check that replaces a button.
   - For long-haul enrollment, read the string over the phone.
3. Each device pins the other device's key for this one exchange (P1=3D, single use).
4. The V2 exchange (P1=35–38) carries the DKEK. Nothing changes here except that step 3 replaces the permanent peer slot.
5. J derives `Q_domain` and checks that it matches the `domain_id` S announced. The KCV gives the same check.
6. S issues J's `MemberCert` (new APDU) and the record is synced to everyone.
7. J pulls the member list and then the full object set (§7).

### 5.3 Fallback joining through shares
A device can also join from the DKEK shares alone (standard `sc-hsm-tool` import). It then derives the same domain key and asks any member for a member certificate. That request still needs SO authentication on the member and the short-string check. This path is how a domain is recovered when no member is reachable.

### 5.4 A-01 once domains exist
After a device holds a DKEK and a member certificate, raw share import stays refused, as it is today: the DKEK is never replaced. The open window, right after an SO-authorised INITIALIZE, is unchanged for compatibility. Documented mitigations:
- compare the KCV after import;
- do the import in one sitting;
- optional: `pico2hsm-tool` runs INITIALIZE and the share imports in a single card session.

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
| 45 | ISSUE_MEMBER_CERT(member_pub, flags) | SO-PIN, plus a pinned peer from the enrollment just completed |
| 46 | REVOKE_MEMBER(member_id) | SO-PIN |
| 47 | GET_MEMBERS (P1; paged, P2 = first slot) | none |
| 48 | DOMAIN_CREATE (optional Option B: generate DKEK, export shares) | SO-PIN, right after INITIALIZE |
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
| **P0 Compatibility** — done; single-device hardware run passed (full suite 343/0 plus the `sc-hsm-tool` interop test); two-device run pending | CardContact wrap format and KCV (§3); compatibility UNWRAP for v0x02/v0x03 | Known-answer vectors in `firmware/tests/vectors/` (Python reference + pico-hsm) for `pico2hsm-proto` to reuse | `sc-hsm-tool` wrap/unwrap round trip across two devices (`tests/hw/test_11_dkek_roundtrip.py::TestCardContactInterop` covers one device) |
| **P1 Foundations** — implemented on `feat/p1-foundations` (host tests pass); hardware run pending | Persisted Lamport counter; global IDs and PKCS#15 CKA_ID kept on import; domain key; member list replacing 0xFC; DOMAIN_STATUS | libpico2hsm APDUs; `domain status`; `pico2hsm-proto` (MemberCert, DOMAIN_STATUS decode, shared vectors) | Two devices from the same shares report the same domain_id |
| **P2 Enrollment** | ISSUE/REVOKE member cert; single-use pinned peer for the existing exchange | `domain enroll` with the short string; `domain revoke` | Enroll C through B, then A accepts C's records |
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

## 12. Owner decisions (2026-10-11)

1. **Signature-authorised import without a PIN:** yes. The daemon runs unattended (§7.4).
2. **State, bucket and id lists readable without a PIN:** yes, with a domain flag to tighten it later.
3. **Sponsoring:** controlled by the "may sponsor" flag in the member certificate, default on.
4. **Tombstone TTL and fencing period:** 90 days.
5. **Delete grace period:** yes, built in P5 (§6.4).
6. **Real SmartCard-HSM:** a passive member through manual `sc-hsm-tool` import is enough.
7. **PIV and OpenPGP sync:** **in scope**, as phase P6 (§12a). Distributed PIV/OpenPGP identities that work on any member are a capability no other product offers.

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
