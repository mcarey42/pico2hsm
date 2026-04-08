# pico2hsm Multi-HSM Cluster — Design & Implementation Plan V2

*Second iteration incorporating penetration test, protocol hardening review, network sync design, and implementation security review.*
*Supersedes `CLUSTER_PLAN.md`. Date: 2026-04-08*

---

## What Changed from V1

The second review pass found critical errors in V1's Phase 0 security fix specifications — the fixes as written would either silently fail to compile, break GCM decryption, or leave the protocol fully replayable. All three Phase 0 fixes are interdependent in non-obvious ways detailed in §3 below.

Key scope change: **V1 targets N=1 and N=2 only.** Quorum-gated multi-node (N=3+) is explicitly a V2 feature. The protocol is designed to support it, but the complexity and attack surface of quorum logic in daemon-land is deferred.

---

## 1. Revised DKEK Exchange Protocol

### Previous (broken) 4-step sequence

V1 had the relay forward unauthenticated ephemeral keys — the HSMs trusted the relay entirely, and AAD used only 16 bytes of the source pubkey.

### Revised 5-step sequence with all fixes applied

```
Source HSM            Daemon A (relay)        Daemon B (relay)        Target HSM
─────────────────────────────────────────────────────────────────────────────────

Step 1: Initiate
Source ──NOISE_INITIATE──▶ A
A ──NOISE_INITIATE_FWD──▶ B ──NOISE_INITIATE_FWD(src_static_pub)──▶ Target

Step 2: Target challenge + signed ephemeral
Target generates: ephem_T_priv, ephem_T_pub, challenge[32]
Target signs:     Sig_T = RFC6979_ECDSA(static_T_priv, SHA256(ephem_T_pub ‖ challenge))
Target ──(ephem_T_pub ‖ challenge ‖ Sig_T)──▶ B ──▶ A ──▶ Source

Step 3: Source verifies and responds
Source verifies Sig_T against enrolled target static pubkey.  ABORT if invalid.
Source generates: ephem_S_priv, ephem_S_pub
Source signs:     Sig_S = RFC6979_ECDSA(static_S_priv, SHA256(ephem_S_pub ‖ challenge))
Source ──(ephem_S_pub ‖ Sig_S)──▶ A ──▶ B ──▶ Target

Step 4: Target verifies and both derive session key
Target verifies Sig_S against enrolled source static pubkey.  ABORT if invalid.
Target stores challenge in flash ring buffer (reject if already seen).

session_key = HKDF-SHA256(
    ikm  = ECDH(ephem_T_priv, ephem_S_pub),
    salt = [],
    info = "pico2hsm-dkek-v2" ‖ ephem_S_pub(65) ‖ ephem_T_pub(65) ‖ challenge(32)
)

Source computes identically:
session_key = HKDF-SHA256(
    ikm  = ECDH(ephem_S_priv, ephem_T_pub),
    salt = [],
    info = "pico2hsm-dkek-v2" ‖ ephem_S_pub(65) ‖ ephem_T_pub(65) ‖ challenge(32)
)

AAD = target_static_pub(65)   [target knows its own pubkey; source has it enrolled]

Source encrypts:
encrypted_dkek = nonce(12) ‖ AES-256-GCM(session_key, nonce, DKEK, AAD) ‖ tag(16)

Source ──encrypted_dkek(60)──▶ A ──▶ B ──▶ Target

Step 5: Target decrypts
Target decrypts with its session_key, AAD = own_static_pub(65).
On success: store DKEK, increment generation counter, send ACK.
On failure: send NACK, log incident.
```

### Why each element is required

| Element | Omitting it breaks |
|---|---|
| Challenge from target | Replay: captured `ephem_S_pub ‖ Sig_S` is reusable forever |
| Challenge in HKDF info | Relay can reuse old `ephem_S_pub` with a new session |
| Both `ephem_pub` values in HKDF info | Channel binding: relay substituting its own ephemeral key derives a different session_key — GCM fails |
| `Sig_S` includes challenge | Fix 1 and Fix 2 are independent without this binding; neither closes its vulnerability alone |
| RFC 6979 (deterministic ECDSA) | Random-k ECDSA with RNG repeat → static private key fully extracted from two signatures |
| AAD = `target_static_pub(65)` | GCM ciphertext is decryptable by any device sharing the session key; target identity is unbound |
| On-device signature verification | Relay-side verification is trivially bypassed by a compromised relay |

### Residual limitation

A legitimately enrolled HSM that acts as a relay (insider threat) can still terminate both legs of the exchange. This requires physical compromise of an enrolled device. Mitigating this requires full Noise_XX with device-to-device channel binding, deferred to V2.

---

## 2. Additional Security Fixes (from pen test)

### 2a. wrap_hash: add per-device salt

**Problem:** `wrap_hash = SHA-256(key_ref ‖ algo ‖ flags ‖ raw_key_material)` — with all non-secret fields known, an attacker who suspects a specific key value (low-entropy symmetric keys, common key patterns) can confirm their guess offline. Identical keys in two slots produce identical wrap_hash, leaking key reuse.

**Fix:** `wrap_hash = SHA-256(device_salt ‖ key_ref ‖ algo ‖ flags ‖ raw_key_material)` where `device_salt` is a 32-byte random value generated at `INITIALIZE` time and stored in flash. This binds the commitment to the specific device, making cross-device comparison and brute-force infeasible.

### 2b. DKEK per-device binding

**Problem:** If the DKEK is stolen from one node (via physical attack, firmware exploit, or future protocol weakness), all DKEK-wrapped blobs across the entire cluster are decryptable.

**Fix:** Nodes store an `effective_DKEK` derived from the shared DKEK and their own device identity:

```
effective_DKEK = HKDF-SHA256(ikm=shared_DKEK, info="pico2hsm-device-dkek-v1" ‖ device_static_pub)
```

`wrap()` and `unwrap()` use `effective_DKEK`. During key export for sync, the source re-wraps under the shared DKEK (a transit form used only in the relay channel); the target re-wraps under its own `effective_DKEK` on import. This operation happens inside the HSM via EXPORT/IMPORT APDUs and the relay never sees plaintext key material.

### 2c. Wrapped blob epoch binding

**Problem:** Captured DKEK-wrapped blobs are valid indefinitely. A future DKEK compromise enables retroactive decryption.

**Fix:** Include a `dkek_epoch: u16` in the wrapped blob AAD (AES-GCM context or as a plaintext prefix):

```
wrapped = dkek_epoch(2) ‖ KCV(8) ‖ IV(16) ‖ AES-256-CBC(effective_DKEK, material)
```

`DKEK_ROTATE` APDU increments the epoch and re-wraps all keys. Import rejects blobs from prior epochs unless migration mode is explicitly activated. Epoch is stored in flash alongside the DKEK state.

### 2d. Tombstone specification (complete)

V1 sketched tombstones without specifying the signed payload. Full specification:

```
TombstoneRecord {
    key_id:             u32,
    deleted_at_gen:     u64,     // device generation at deletion time
    state_root_at_del:  [u8;32], // state root immediately before deletion
    dkek_epoch:         u16,     // DKEK epoch at deletion time
    sig:                [u8;64], // RFC6979 ECDSA over SHA256 of all preceding fields
    signer_pubkey:      [u8;65], // static pubkey of the deleting node
}
```

Tombstone precedence rule: a tombstone with any `deleted_at_gen` takes precedence over a live record with `generation_born < deleted_at_gen`. Only a new key with `generation_born > deleted_at_gen` supersedes it (i.e., the key slot was intentionally reused after deletion).

HSMs must return tombstones in `GET_KEY_MANIFEST` responses. The daemon propagates tombstones to all nodes during sync. Tombstones persist for `tombstone_ttl` (default 30 days) after all cluster members have acknowledged them.

### 2e. HSM-signed generation attestation

**Problem:** Quorum counting and generation comparison happen entirely in daemon-land. A compromised daemon can lie about cluster size (report N=1 to achieve quorum alone) or fabricate generation values.

**Fix (V1 scope — simple):** Each `GET_STATE_HASH` response is: `generation(8) ‖ state_root(32) ‖ Sig_device_static(generation ‖ state_root)(64)`. The peer daemon verifies the signature against the enrolled device pubkey before trusting the state root comparison.

**Fix (V2 scope — full):** HSMs store an enrolled membership list in flash (set of enrolled device pubkeys, HMAC'd by a key derived from the device key). Quorum proof = collection of signed `(op_id, state_root, generation)` tuples, one per member. HSMs verify the collection on-device before committing writes.

### 2f. State file integrity

**Problem:** `state.json` is world-readable by default and carries no integrity protection. A local attacker can roll back generation counters or swap device fingerprints.

**Fix:** (1) Create `~/.pico2hsm/` with `mode=0o700`; create all files with `mode=0o600`. (2) HMAC-protect `state.json` using a key requested from the local HSM: `state_hmac_key = HKDF-SHA256(device_identity_key, "pico2hsm-state-hmac-v1")`. Daemon requests this key via a `GET_STATE_HMAC_KEY` vendor APDU on startup; verifies HMAC on load; updates HMAC on save. File without valid HMAC is treated as corrupted (not silently accepted).

---

## 3. Revised Protocol Security Properties

After all fixes in §1 and §2:

| Property | Status | Condition |
|---|---|---|
| Forward secrecy | ✓ | Ephemeral key per session; static key compromise doesn't reveal past sessions |
| Mutual authentication | ✓ | Both HSMs verify RFC6979 signatures on-device |
| Replay protection | ✓ | Challenge from target bound into HKDF info and both signatures |
| Relay MitM by unenrolled relay | ✓ | Signatures fail — relay has no enrolled static key |
| Relay MitM by enrolled relay | ✗ | Insider threat; requires full Noise_XX for V2 |
| DKEK isolation per node | ✓ | With §2b effective_DKEK |
| Key deletion permanence | ✓ | With §2d tombstone protocol |
| State integrity | ✓ | With §2e HSM-signed attestations and §2f file HMAC |
| Blob longevity | ✓ | With §2c epoch binding |

---

## 4. Network Sync — Explicit Message Sequences

### 4a. Initial DKEK sync (B has no DKEK)

```
B connects to A (TLS client → TLS server, mTLS with enrolled certs).
B→A: DEV_PUBKEY(0x05)  | B_HSM_static_pubkey(65)
A→B: DEV_PUBKEY(0x05)  | A_HSM_static_pubkey(65)
[Revised 5-step DKEK exchange — see §1]
B→A: ACK(0xFF)
```

DKEK is in B's HSM volatile RAM. Not persisted; full exchange repeats after B power-cycle.

### 4b. Key manifest sync (DKEK established, B missing keys)

```
B→A: MANIFEST_REQ(0x10)    | 0 bytes
A→B: MANIFEST_RESP(0x11)   | compact manifest: [key_ref(1) ‖ wrap_hash(32) ‖ ts(8) ‖ deleted(1)] × N
B computes local manifest, diffs.

For each key in push set:
  B→A: KEY_BLOB_REQ(0x12a)  | key_ref(4)
  A→B: KEY_BLOB(0x12)       | key_ref(4) ‖ wrapped_blob(var)
  B imports via IMPORT_KEY APDU.
  B→A: ACK(0xFF)            | key_ref(4)

For each tombstone in delete set:
  A→B: TOMBSTONE(0x20)      | TombstoneRecord(fixed 167 bytes)
  B deletes, verifies tombstone sig, ACKs.

B→A: SYNC_COMPLETE(0x13)   | state_root(32)   [B's computed root after sync]
A→B: SYNC_COMPLETE(0x13)   | state_root(32)   [A's root — must match]
```

If roots mismatch: both sides log an error; retry after 30s.

### 4c. Incremental sync (B reconnects, stale)

Same as 4b — manifest diff identifies only what has changed. Already-synced keys are not retransferred. No resume state needed; the diff is the recovery mechanism. Operations are idempotent.

### 4d. GET_STATE_HASH verification (lightweight periodic check)

```
A→B: STATE_HASH_REQ(0x14)  | 0 bytes
B→A: STATE_HASH_RESP(0x15) | generation(8) ‖ state_root(32) ‖ Sig_B_static(64)
A verifies Sig_B_static, compares state_root to its own.
If match: log "cluster in sync at generation N".
If mismatch: trigger manifest sync (§4b).
```

Periodic interval: 30s by default.

---

## 5. mTLS Enrollment Ceremony

**Replace TOFU.** The first TLS connection must not be unauthenticated.

**HSM-attested enrollment ceremony:**

1. Each daemon generates a persistent TLS X.509 keypair at first launch; stores as `daemon.crt` / `daemon.key` (mode 0o600). The cert's Subject contains `cluster_id` and `node_name`.
2. Daemon requests the local HSM to sign the TLS cert fingerprint:

   ```
   enrollment_sig = RFC6979_ECDSA(device_static_priv, SHA256(tls_cert_fingerprint ‖ cluster_id))
   ```

   This is a new vendor APDU: `SIGN_ENROLLMENT` (INS=0xB9).

3. Enrollment between two nodes: operator runs `pico2hsm-admin enroll-peer --peer <host>` on both nodes simultaneously (or shares out-of-band). Each daemon sends its `tls_cert_fingerprint(32) ‖ enrollment_sig(64)`.

4. The receiving daemon calls `GET_DEVICE_PUBKEY` on its local HSM to get the peer's device pubkey (which the operator enrolled previously), verifies `enrollment_sig`, and pins the TLS fingerprint.

5. **Out-of-band step:** The operator exchanges two 16-byte hex strings (SHA-256 fingerprint prefixes) over a phone call or secure channel. This replaces reading full certificates. No PKI, no CA, no certificates to distribute.

**Result:** TLS fingerprint is cryptographically bound to a physical HSM device. Network-position attack requires compromising both the network AND an enrolled HSM.

---

## 6. NAT Traversal

**Model A — both publicly reachable:** Direct TCP, A listens on 7890, B connects. Default.

**Model B — one behind NAT:** The NATted node connects outbound. Protocol roles (primary/secondary) are independent of TCP client/server roles — add `ROLE_ANNOUNCE(0x22)` message at session open.

**Model C — both behind NAT:** Optional dumb relay proxy. Both daemons connect outbound to the relay. Relay identifies sessions by `cluster_id` and forwards `P2H1`-framed mTLS ciphertext between the two connections. Relay holds zero secrets, sees only ciphertext. Can be deployed on any $5/month VPS in ~200 lines of Rust/Go.

**V1 ships:** Models A and B only. Model C is V2.

---

## 7. V1 Scope: N=1 and N=2

Quorum-gated multi-node (N≥3) is deferred. Reasons:

- Quorum logic in daemon-land is untrustworthy without HSM-attested membership lists (§2e V2 fix)
- The attack surface for split-brain and partition scenarios is disproportionate for typical 2-device deployments
- The protocol is designed to support N=3+ without breaking changes; just the quorum logic is deferred

**V1 cluster topology:**
- **N=1:** Standalone — full DKEK/key functionality, no sync
- **N=2:** Primary + one hot standby — sync on USB connect or TCP reconnect; failover is manual operator action

The epoch counter (§2c), tombstone protocol (§2d), and signed attestation (§2e) are still implemented in V1 because retrofitting them later is harder than including them now.

---

## 8. Implementation Security Checklist

### Python daemon

| Issue | Fix | Severity |
|---|---|---|
| `state.json` world-readable | `os.makedirs(0o700)`, `os.open(mode=0o600)` | High |
| `_recv_framed` 4 GB allocation | Enforce `MAX_FRAME_SIZE = 65536` | High |
| Import blob forwarded without validation | Check min/max length, format prefix before APDU | High |
| pyscard APDU blocks on disconnect | Wrap in `ThreadPoolExecutor` with 30s timeout | High |
| Infinite frame stream DoS | Rate limit 100 msg/min + idle timeout 30s + max 3 conn/IP | High |
| `openssl` subprocess | Replace with `cryptography` library `x509.CertificateBuilder` | Medium |
| `DeviceState(**d)` from JSON | Explicit field/type validation before unpacking | Medium |
| Manifest duplicate key_ref | Reject, don't silently deduplicate | Medium |
| Manifest with >256 entries | Enforce `MAX_MANIFEST_ENTRIES = 256` | Medium |
| TOCTOU on tmp file save | Use unique temp path (not fixed `.tmp`) | Low |
| `bytearray` for blob buffers | Overwrite after use (`buf[:] = b'\x00' * len(buf)`) | Low |

### Rust daemon

| Issue | Fix | Severity |
|---|---|---|
| `std::sync::RwLock` in async | Use `tokio::sync::RwLock`; never hold guard across `.await` | High |
| `daemon.key` world-readable | `OpenOptionsExt::mode(0o600)`; verify on startup | High |
| `spawn_blocking` panic | Always `.await` JoinHandle, match `Err(JoinError)` | Medium |
| Concurrent state file write | `tempfile::NamedTempFile::persist()` (atomic rename) | Medium |
| Wrapped blobs in memory | `Zeroizing<Vec<u8>>` for all blob buffers | Medium |

### Firmware (new APDU surface)

| Issue | Fix | Severity |
|---|---|---|
| TLV parser on `GET_KEY_MANIFEST` response | Full bounds checking: cursor + len ≤ buf_len before every read | High |
| RFC 6979 signing | Confirm `p256::SigningKey::sign_prehash` uses deterministic k | Critical |
| Challenge ring buffer eviction | Size to `max_cluster_nodes × expected_exchanges_per_epoch`; never evict before expiry | High |
| UART on embedded controller | Challenge-response auth using HSM static key before accepting relay commands | High |

---

## 9. Revised Implementation Phases

### Phase 0 — Protocol Security (must precede all cluster features)

- [ ] Implement revised 5-step DKEK exchange (§1) in firmware
  - [ ] `NOISE_INITIATE_FWD` step (relay sends source static pubkey to target)
  - [ ] Target generates challenge, signs `(ephem_T_pub ‖ challenge)` with RFC6979 ECDSA
  - [ ] Source verifies target sig, signs `(ephem_S_pub ‖ challenge)` with RFC6979 ECDSA
  - [ ] Both sides include `ephem_S_pub ‖ ephem_T_pub ‖ challenge` in HKDF info
  - [ ] AAD = `target_static_pub(65)` on both sides
  - [ ] On-device signature verification in firmware (not relay-side)
- [ ] Challenge replay cache in flash (sized appropriately, no forced eviction)
- [ ] Confirm RFC 6979 deterministic k in `p256::SigningKey`
- [ ] Fix AAD: both sides use `target_static_pub(65)`

### Phase 1 — Firmware additions

- [ ] Upgrade generation counter to `u64`
- [ ] `device_salt: [u8; 32]` generated at `INITIALIZE`, stored in flash
- [ ] `wrap_hash = SHA-256(device_salt ‖ key_ref ‖ algo ‖ flags ‖ raw_key_material)`
- [ ] `timestamp_ms: u64` field in `KeyObject` (daemon-assigned, stored opaque)
- [ ] `dkek_epoch: u16` field in `DkekManager` and wrapped blob format
- [ ] `GET_KEY_MANIFEST` APDU (INS=0xCA, P1=0x01)
- [ ] `GET_STATE_HASH` APDU (INS=0xB8) with RFC6979 signature
- [ ] `SIGN_ENROLLMENT` APDU (INS=0xB9) for mTLS cert binding
- [ ] Tombstone record format + storage in flash
- [ ] `IMPORT KEY` accepts optional `timestamp_ms` in TLV

### Phase 2 — Python daemon extension (see CLUSTER_PLAN.md §9 for detail)

Phases as in V1, plus:
- [ ] `state.json` file permission hardening (0o600)
- [ ] `MAX_FRAME_SIZE = 65536` enforcement in `_recv_framed`
- [ ] Blob validation before APDU forwarding
- [ ] APDU call timeouts via `ThreadPoolExecutor`
- [ ] mTLS with HSM-attested enrollment ceremony
- [ ] Rate limiting + DoS protection on TCP listener

### Phase 3 — `pico2hsm-proto` shared library (as in V1)

Plus: tombstone codec, enrollment message codec, epoch field in all state types.

### Phase 4 — Rust daemon (as in V1)

Plus: all implementation security checklist items from §8.

### Phase 5 — Embedded controller (as in V1)

Plus: UART challenge-response authentication.

---

## 10. Open Questions (updated from V1)

1. **`DKEK_ROTATE` APDU**: What triggers epoch increment — operator command only, or automatic after N operations? What's the re-wrap procedure for all 254 keys?

2. **Tombstone TTL**: 30 days default. What if a node is offline longer than TTL? Force full sync (wipe + reimport) or allow expired tombstones via operator override?

3. **`GET_STATE_HMAC_KEY` APDU**: Should this derive from the device identity key (OTP-locked) or from the current DKEK? Using the device key means state HMAC survives DKEK rotation; using the DKEK means state HMAC is invalidated on rotation (forcing re-read from a live device).

4. **Enrolled membership list in HSM flash**: Format and capacity — a 5-node cluster needs 5 × 65 bytes = 325 bytes. This fits comfortably but needs a reserved flash sector.

5. **Model C relay proxy**: Implement in Rust alongside the daemon (extra binary in the same crate), or a separate minimal project?

6. **`SIGN_ENROLLMENT` APDU timing**: Should the HSM sign only once at formation time, or re-sign on every daemon restart? Re-signing is more secure (cert rotation) but requires the HSM to be present at daemon startup.
