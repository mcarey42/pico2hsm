# pico2hsm Multi-HSM Cluster — Design & Implementation Plan

> **Superseded by [CLUSTER_PLAN_V2.md](CLUSTER_PLAN_V2.md) and
> [CLUSTER_PLAN_V3.md](CLUSTER_PLAN_V3.md).** Kept for history.

*Synthesized from four concurrent architecture, security, Python, and Rust design reviews.*
*Date: 2026-04-08*

---

## 1. Goals

| Goal | Description |
|---|---|
| **Redundancy** | N HSMs share one DKEK; any device can wrap/unwrap keys |
| **Generational sync** | Each key carries a logical timestamp; a rejoining node catches up |
| **Proof of sync** | Any node can prove its key set matches the cluster's canonical state |
| **Python daemon** | Extend the existing `tools/python/pico2hsm/` daemon |
| **Rust daemon** | New `pico2hsm-daemon` binary, wire-compatible with Python |
| **Embedded controller** | RP2350-based headless cluster controller (no Linux host required) |

---

## 2. Cluster Topology

**Static primary, hot secondaries, coordinator-mediated.**

- One device is **primary** (designated at cluster formation, stored in `StatePersistence`).
- All others are **secondaries**.
- The daemon on the host is the **coordinator** — devices never communicate directly.
- Primary promotion is a manual operator action or automatic after a configurable timeout.
- Realistic cluster size: **2–5 nodes**. Full-state comparison is cheap at this scale; gossip protocols are unnecessary overhead.
- No leader election (Raft/Paxos is overkill for USB-attached physical devices).

---

## 3. Generational Model

### The clock problem

The RP2350 has no RTC and no battery-backed clock. Wall-clock timestamps are unreliable on-device. **Devices must never be trusted to generate meaningful timestamps.**

### Resolution: daemon-stamped logical timestamps

- **Device side**: Each device maintains a `u64` monotonic **generation counter** (upgrade from the current `u32`). Incremented on every state-mutating APDU (key generate, key import, key delete, DKEK change). Stored in flash alongside each key. This is the device's authoritative version order.
- **Daemon side**: The Python/Rust daemon assigns a **Hybrid Logical Clock (HLC)** value — `(wall_clock_ms: u64, logical: u16, node_id: u8)` — to each sync event. The HLC value is written into the key metadata via the `IMPORT KEY` APDU (new field in the APDU data).
- **Key timestamp semantics**: the `timestamp_ms` field in a `KeyEntry` is the HLC value at the time the key was created or last modified, **as recorded by the coordinating daemon**. It is opaque to the device — the device stores and returns it but does not interpret it.

This gives total ordering without requiring devices to have clocks.

---

## 4. Key State Representation

Each key for sync purposes is a **KeyEntry**:

```
KeyEntry {
    key_ref:        u8,         // SC-HSM key reference (1–254)
    algo:           u8,         // SC-HSM algorithm identifier
    key_flags:      u8,         // exportable, sign-only, etc.
    timestamp_ms:   u64,        // daemon-assigned HLC (opaque on device)
    pubkey_hash:    [u8; 32],   // SHA-256 of DER-encoded public key
    wrap_hash:      [u8; 32],   // SHA-256(key_ref || algo || flags || raw_key_material)
                                //   computed on-device before DKEK wrap; never leaves as plaintext
    deleted:        bool,       // tombstone flag
    generation_del: u64,        // device generation when deleted (0 if alive)
}
```

### Tombstones

Deleted keys become **tombstones** — they retain their `key_ref` and hashes but set `deleted = true` and `generation_del`. Tombstones persist in the manifest until all cluster members have acknowledged the deletion. This prevents a stale secondary from resurrecting a deliberately destroyed key.

**Tombstone precedence rule**: A tombstone with any `generation_del` takes precedence over a live record with a lower `generation_born`. Only a record with `generation_born > generation_del` (a new key generated in the same slot after deletion) supersedes a tombstone.

---

## 5. State Hash / Proof of Sync

### Construction

**Flat Merkle-compatible hash** over all 254 key slots:

1. For each key_ref 0–253 (including empty slots):
   - **Alive key**: `leaf[i] = SHA-256(key_ref || algo || key_flags || timestamp_ms || pubkey_hash || wrap_hash || 0x00)`
   - **Tombstone**: `leaf[i] = SHA-256(key_ref || 0xFF || 0x00 || generation_del_be64 || [0;32] || [0;32] || 0x01)`
   - **Empty slot**: `leaf[i] = SHA-256(0xFF || key_ref || [0;63])`

2. **State root**: `SHA-256(leaf[0] || leaf[1] || ... || leaf[253])`

3. Two nodes are **in sync** iff their state roots match.

### Compact manifest

For diff computation, the daemon requests a compact manifest from each device: `(key_ref, algo, flags, timestamp_ms, pubkey_hash, wrap_hash, deleted)` — 76 bytes per entry, under 20 KB for 254 keys. This is sent in response to `GET_KEY_MANIFEST`.

### Full Merkle tree

The flat hash is sufficient for 254 keys (254 × 32 = 8 KB proof). Upgrade to a binary Merkle tree (8 levels, 256-byte partial proofs) only if the key count exceeds 1024.

---

## 6. New Firmware APDUs

Minimal new APDU surface — only what is strictly required:

| INS | Name | P1/P2 | Data In | Data Out |
|---|---|---|---|---|
| `0xCA` | `GET_KEY_MANIFEST` | `P1=0x01, P2=0x00` | — | TLV list of `KeyEntry` records (see §5) |
| `0xB8` | `GET_STATE_HASH` | `0x00/0x00` | — | `generation(8) \|\| state_root(32) \|\| key_count(2)` = 42 bytes |

`GET_GENERATION` (existing) upgrades from `u32` → `u64` response. Keep backward compatibility: if response is 4 bytes, treat as `u32`; if 8 bytes, treat as `u64`.

`IMPORT KEY` (existing, `INS=0x58`) gains an optional `timestamp_ms` field in its TLV data — if present, firmware stores it with the key. If absent, firmware stores `0` (legacy import).

### Firmware storage change

Each persisted key object gains two new fields:
- `timestamp_ms: u64` — daemon-assigned HLC timestamp
- `wrap_hash: [u8; 32]` — SHA-256 commitment over raw key material (computed at key generation/import, before DKEK wrapping)

These are stored in the `KeyObject` struct in flash. The `wrap_hash` is computed on-device from the raw private key bytes before the DKEK wraps them; it never leaves the device in plaintext.

---

## 7. Sync Protocol

**Anti-entropy, pull-based, coordinator-mediated.**

When the daemon detects divergent state roots between two devices:

1. **Inventory exchange**: Call `GET_KEY_MANIFEST` on both. Receives compact manifest (key_ref, wrap_hash, timestamp_ms, deleted, generation).

2. **Diff** (computed on daemon):
   - Keys on primary, missing on secondary → **push set**
   - Keys with matching `key_ref` but different `wrap_hash` → **conflict** (primary wins; secondary version is exported for backup before overwrite)
   - Keys tombstoned on primary, alive on secondary → **delete set**
   - Keys on secondary, not on primary → **orphan set** (log and alert; operator decides)

3. **Resolution**:
   - **Push**: `EXPORT KEY` on primary → DKEK-wrapped blob → `IMPORT KEY` on secondary
   - **Delete**: `DELETE KEY` on secondary + record tombstone
   - **Conflict**: export secondary version to backup file, then push primary's version
   - **Orphan**: default = reject (export + alert); configurable to import into primary

4. **Verify**: After sync, call `GET_STATE_HASH` on both. Roots must match. If not, retry once then escalate to operator.

### Quorum model

- **Reads** (unwrap, sign): any node, no quorum check
- **Writes** (key generate, import, delete): `ceil(N/2 + 1)` nodes must be reachable before the write is committed
- **Catchup**: eventual consistency — the daemon syncs divergent nodes on next connect

---

## 8. Security Requirements

*These must be resolved before cluster sync ships.*

### CRITICAL — HSMs do not authenticate each other

The current relay protocol has no mutual authentication between HSMs. The HSMs trust the relay to deliver the correct ephemeral pubkeys. A compromised relay can execute a MITM attack on the DKEK exchange.

**Fix**: Each HSM signs its ephemeral pubkey with its static private key before sending. The peer verifies the signature against the enrolled static pubkey. This binds the ephemeral exchange to verified device identities without requiring a new protocol round.

```
New NOISE_INITIATE response: ephem_pub(65) || Sig_static(ephem_pub || nonce)(64)
```

### HIGH — No replay protection in DKEK exchange

Ephemeral keypairs provide probabilistic replay resistance, but there is no nonce or counter in the current protocol. A replay of the full 4-step exchange would cause the target to re-import the same DKEK.

**Fix**: Target generates a random 32-byte challenge and includes it in its `NOISE_INITIATE` response. Source includes the challenge in the HKDF info string (`info = EXCHANGE_INFO || challenge`). Challenge is stored in a small flash ring buffer (8 entries, FIFO eviction) to detect replay within the device's memory window.

### HIGH — Tombstoning not implemented

Without a tombstone protocol, deleting a key on the primary and then syncing a stale secondary **resurrects the deleted key**. This is a security regression — a key deleted for compromise reasons returns.

**Fix**: Implement the tombstone representation described in §4. Tombstone records are returned by `GET_KEY_MANIFEST` and propagated by the sync protocol. Tombstones take precedence over live records with lower generation numbers.

### MEDIUM — Anonymous TLS is malleable to active attackers

The current `CERT_NONE` TLS protects passive eavesdropping only. An active on-path attacker can MITM the TLS session.

**Fix**: Each daemon generates a persistent X.509 identity certificate at first run (`daemon.crt` / `daemon.key` in the config directory). Peer daemons enroll each other's certificate fingerprint during cluster formation. Use mutual TLS (`CERT_REQUIRED`) with certificate fingerprint pinning (TOFU model). No CA infrastructure required.

### LOW — AAD truncation

Current AAD uses only `source_static_pub[:16]` (first 16 bytes of a 65-byte uncompressed point). Fix: use the full 65-byte pubkey as AAD. GCM AAD has no size constraint.

### Embedded controller hardening

If using an RP2350 as the cluster controller:
- Enrolled peer pubkeys stored in flash with SHA-256 HMAC integrity check (keyed by device key)
- Challenge replay cache in a dedicated flash sector with wear-leveling
- Use OTP rows as one-way epoch counter (not per-key — OTP is limited, use for epoch boundaries only)
- Watchdog on sync operations: reset on stall rather than leaving partial state
- Wall-clock timestamps are advisory only; logical counters are authoritative

---

## 9. Python Daemon — Implementation Plan

**Stay with threads.** pyscard is synchronous C FFI; asyncio wrapping adds complexity with no throughput benefit. The existing model is correct.

### Phase 1 — Key Manifest (foundation)

**New file: `manifest.py`**

```python
@dataclass
class KeyManifestEntry:
    key_ref: int          # u8
    algo: int             # u8
    key_flags: int        # u8
    timestamp_ms: int     # u64 (daemon HLC)
    pubkey_hash: bytes    # 32 bytes
    wrap_hash: bytes      # 32 bytes
    deleted: bool
    generation_del: int   # u64, 0 if alive

def parse_key_manifest(apdu_response: bytes) -> list[KeyManifestEntry]: ...
def compute_entry_hash(entry: KeyManifestEntry) -> bytes: ...
    # SHA-256(key_ref_u8 || algo_u8 || flags_u8 || timestamp_be64 || pubkey_hash || wrap_hash || deleted_u8)
def compute_state_root(entries: list[KeyManifestEntry]) -> bytes: ...
    # Sort all 254 slots, hash each, concat, SHA-256
```

**Changed: `protocol.py`** — add `build_get_key_manifest()` and `build_get_state_hash()`.

**Changed: `device.py`** — add `get_key_manifest() -> list[KeyManifestEntry]` and `get_state_hash() -> tuple[int, bytes]`.

### Phase 2 — Cluster State + Diff

**New file: `cluster.py`**

```python
@dataclass
class ClusterState:
    device_id: str
    state_root: bytes
    manifest: list[KeyManifestEntry]
    captured_at: float

@dataclass
class SyncPlan:
    missing_on_secondary: list[int]    # key_refs to push
    conflicts: list[int]               # key_refs with divergent wrap_hash
    tombstone_on_secondary: list[int]  # key_refs to delete
    orphans: list[int]                 # secondary-only keys

def diff_manifests(primary: list[KeyManifestEntry],
                   secondary: list[KeyManifestEntry]) -> SyncPlan: ...
```

**Changed: `state.py`** — `StatePersistence` gains `last_state_root: dict[str, str]` and `last_manifest: dict[str, list]`.

### Phase 3 — Key Sync Protocol

**Changed: `key_transfer.py`** (implement fully):

```python
def export_key_from_device(device: Pico2HSM, key_ref: int) -> bytes: ...
    # EXPORT KEY APDU (INS=0x34, P1=key_ref) → DKEK-wrapped blob
def import_key_to_device(device: Pico2HSM, key_ref: int,
                         wrapped_blob: bytes, timestamp_ms: int) -> None: ...
    # IMPORT KEY APDU (INS=0x58) with timestamp in TLV data
def sync_keys(primary: Pico2HSM, secondary: Pico2HSM, plan: SyncPlan) -> SyncResult: ...
    # Precondition: both devices share same DKEK (handled by DkekExchange first)
```

**Changed: `sync.py`** — `SyncManager` gains:
```python
def full_sync(primary: Pico2HSM, secondary: Pico2HSM) -> SyncResult: ...
    # 1. Ensure DKEK sync (existing DkekExchange)
    # 2. Get manifests
    # 3. Diff
    # 4. Transfer keys
    # 5. Verify state roots match
def verify_sync(devices: list[Pico2HSM]) -> dict[str, bytes]: ...
    # Returns {device_id: state_root}; caller checks all roots equal
```

### Phase 4 — Mutual TLS

**New file: `tls.py`**:
```python
def ensure_daemon_identity(config_dir: Path) -> tuple[Path, Path]: ...
    # Generates RSA-2048 self-signed X.509 on first run; returns (cert_path, key_path)
def create_mtls_server_context(cert, key, trusted_peer_certs: list[Path]) -> ssl.SSLContext: ...
def create_mtls_client_context(cert, key, server_cert: Path) -> ssl.SSLContext: ...
```

**Dependency**: `cryptography` library (for cert generation).

### Phase 5 — Complete Daemon Stubs

**Changed: `daemon.py`**:
- `_on_usb_connect_event()`: enumerate readers, find new Pico2HSM, compare state root with primary, trigger `full_sync` if divergent.
- `_handle_tcp_connection()`: complete the key-blob relay with new framing message types:
  - `MSG_MANIFEST_REQ = 0x10`
  - `MSG_MANIFEST_RESP = 0x11`
  - `MSG_KEY_BLOB = 0x12`
  - `MSG_SYNC_COMPLETE = 0x13`
- `_periodic_health_check()` thread: every 60s, fetch manifests from all connected devices, log state roots, update `StatePersistence`.

### Phase 6 — CLI (`hsm_daemon.py`)

Unix domain socket at `/run/pico2hsm/ctl.sock` for CLI-to-daemon IPC (JSON request → JSON response).

| Subcommand | Action |
|---|---|
| `start` | Fork daemon, write PID file |
| `stop` | SIGTERM to PID |
| `status` | Print device list, state roots, sync status |
| `sync <device>` | Trigger manual full sync for named device |
| `verify-sync` | Fetch all manifests, print roots, report match/mismatch |
| `export-state` | Dump `StatePersistence` JSON to stdout |
| `enroll-peer <name> <addr> <cert>` | Add peer daemon to config |

Uses `argparse` (no new dependency needed).

### Python implementation order

1. `manifest.py` + `protocol.py` builder → unit-testable immediately
2. Firmware `GET_KEY_MANIFEST` APDU + timestamp field in keystore
3. `cluster.py` state root + diff
4. `key_transfer.py` fully implemented
5. `sync.py` `full_sync` + `verify_sync`
6. `tls.py` + mTLS plumbing (parallel to 4–5)
7. `daemon.py` stub completion
8. `hsm_daemon.py` CLI

---

## 10. Rust Daemon — Implementation Plan

### Crate workspace

```
pico2hsm-cluster/
├── pico2hsm-proto/              # no_std-compatible shared library
│   ├── src/
│   │   ├── apdu.rs              # ClusterApdu enum, APDU builders
│   │   ├── frame.rs             # Wire framing (P2H1 magic)
│   │   ├── manifest.rs          # KeyEntry, KeyManifest, ClusterStateRoot
│   │   └── lib.rs
│   └── Cargo.toml               # default-features = false; features = ["std", "alloc"]
├── pico2hsm-daemon/             # tokio binary
└── pico2hsm-embedded-controller/  # Embassy no_std firmware
```

### Design decisions

| Decision | Choice | Rationale |
|---|---|---|
| Async runtime | **Tokio** | Largest ecosystem, tokio-console for debugging, mature timers/signals |
| USB/CCID | **`pcsc` crate** | pcscd already handles enumeration + CCID; rusb would fight pcscd for ownership |
| TLS | **`rustls` + `rcgen`** | No OpenSSL dep, compiles everywhere, `rcgen` generates self-signed certs |
| State | **`serde_json` flat file** | Small state, debuggable, diffable; no need for embedded DB |
| CLI | **`clap` derive API** | Standard, ergonomic |

### Key types (`pico2hsm-proto`)

```rust
pub struct KeyEntry {
    pub key_ref:      u8,
    pub algo:         u8,
    pub key_flags:    u8,
    pub timestamp_ms: u64,
    pub pubkey_hash:  [u8; 32],
    pub wrap_hash:    [u8; 32],
    pub deleted:      bool,
    pub generation_del: u64,
}

pub struct KeyManifest {
    // std: Vec<KeyEntry>, no_std: heapless::Vec<KeyEntry, 128>
    pub entries: KeyEntryVec,
}

pub struct ClusterStateRoot(pub [u8; 32]);

impl KeyManifest {
    /// Sort by key_ref, hash each entry, concat hashes, SHA-256.
    pub fn state_root(&self) -> ClusterStateRoot { ... }
}

pub struct Frame {
    pub msg_type: u8,
    // std: Vec<u8>, no_std: heapless::Vec<u8, 4096>
    pub payload: PayloadVec,
}
```

### Async task structure

```
tokio::main
├─ device_monitor_task       — polls pcsc::Context::list_readers() every 2s
│                              → DeviceEvent::{Attached(reader), Detached(reader)}
│                              → mpsc to relay_engine_task
├─ tcp_listener_task         — TLS accept loop
│                              → spawns per_peer_task for each connection
├─ per_peer_task[N]          — reads frames from one TCP peer
│                              → dispatches to relay_engine_task or sync_engine_task
├─ relay_engine_task         — executes 4-step DKEK relay
│                              → APDU calls via spawn_blocking(pcsc)
└─ sync_engine_task          — periodic (30s): compare state roots, trigger key catchup
```

**Shared state**: `Arc<RwLock<ClusterState>>` — read-heavy (status queries), rarely written (sync events).

```rust
pub struct ClusterState {
    pub devices: HashMap<DeviceId, DeviceInfo>,
    pub peers:   HashMap<PeerFingerprint, PeerInfo>,
    pub primary: Option<DeviceId>,
}

pub struct DeviceInfo {
    pub reader_name: String,
    pub pubkey:      [u8; 65],
    pub generation:  u64,
    pub manifest:    KeyManifest,
    pub state_root:  ClusterStateRoot,
    pub last_seen:   Instant,
}
```

---

## 11. Embedded Controller — Implementation Plan

### Hardware

**Raspberry Pi Pico 2** (or any RP2350 board). Acts as a standalone cluster controller — no Linux host required for local USB sync.

### Design decisions

| Decision | Choice | Rationale |
|---|---|---|
| Device links | **UART** (not USB host) | Embassy has no production USB host CCID class driver; UART is reliable now |
| Core usage | **Core0 only** | No heavy crypto; core1 reserved for future USB host or display |
| Network uplink | **UART/CDC to a host daemon** | RP2350 has no Ethernet/WiFi; Pico W variant is a future firmware target |
| State storage | **`heapless` collections, static alloc** | 520 KB available (separate firmware, full budget); ~106 KB total state for 4 HSMs |
| Hash | **`sha2` crate** | Already in the dependency tree, proven no_std |

### Memory budget (4 HSMs, 128 keys max each)

| Item | Size |
|---|---|
| Per-HSM state (pubkey + 128-key manifest) | ~6 KB × 4 = 24 KB |
| APDU buffers (2 × 4 KB per HSM) | 32 KB |
| Frame buffers (TX + RX per UART) | 16 KB |
| Embassy executor + task stacks | ~32 KB |
| SHA-256 scratch + misc | 2 KB |
| **Total** | **~106 KB** of 520 KB |

### Embassy task structure

```rust
// core0 Embassy executor
#[embassy_executor::task] async fn uart_hsm_task(hsm_idx: usize, uart: UartRx) { ... }
    // One per connected pico2hsm; reads/writes P2H1 frames via UART
#[embassy_executor::task] async fn uplink_task(uart: UartTx) { ... }
    // Forwards relay commands and status to the host daemon
#[embassy_executor::task] async fn sync_task() { ... }
    // Polls each HSM's generation + manifest every 30s
    // Computes state roots, reports divergence to uplink_task
#[embassy_executor::task] async fn display_task() { ... }
    // Optional: OLED showing "4/4 synced | gen=17 | ████████"
```

Tasks communicate via `embassy_sync::channel::Channel<CriticalSectionRawMutex, T, N>` (static, no alloc).

### `pico2hsm-proto` no_std strategy

```toml
# pico2hsm-proto/Cargo.toml
[features]
default = ["std"]
std  = []       # daemon uses this; enables Vec, std::io
alloc = []      # alloc but no std
# no features = no_std, no_alloc — embedded controller uses this

[dependencies]
heapless = "0.8"
sha2 = { version = "0.10", default-features = false }
serde = { version = "1", default-features = false, features = ["derive"] }
```

`KeyEntryVec` type alias: `Vec<KeyEntry>` with `std`, `heapless::Vec<KeyEntry, 128>` without.

`Frame` encode/decode operate on `&[u8]` slices — zero allocation.

---

## 12. Implementation Phases

### Phase 0 — Security prerequisites *(before any cluster code ships)*

- [ ] Mutual HSM authentication: sign ephemeral pubkeys with static key in `NOISE_INITIATE`
- [ ] Challenge-response replay protection in DKEK exchange
- [ ] Tombstone record design + firmware implementation
- [ ] Fix AAD truncation (use full 65-byte pubkey)

### Phase 1 — Firmware additions

- [ ] Upgrade generation counter to `u64`
- [ ] Add `timestamp_ms: u64` and `wrap_hash: [u8; 32]` to `KeyObject`
- [ ] `wrap_hash` computed at key generation and stored in flash
- [ ] `GET_KEY_MANIFEST` APDU handler (INS=0xCA)
- [ ] `GET_STATE_HASH` APDU handler (INS=0xB8)
- [ ] `IMPORT KEY` accepts optional `timestamp_ms` in TLV

### Phase 2 — Python daemon extension

- [ ] `manifest.py`: `KeyManifestEntry`, `compute_state_root()`
- [ ] `cluster.py`: `ClusterState`, `SyncPlan`, `diff_manifests()`
- [ ] `key_transfer.py`: fully implement export/import/sync
- [ ] `tls.py`: mTLS context generation
- [ ] `sync.py`: `full_sync()`, `verify_sync()`
- [ ] `daemon.py`: complete USB auto-sync, TCP relay, periodic health check
- [ ] `hsm_daemon.py`: CLI with all subcommands

### Phase 3 — `pico2hsm-proto` shared library

- [ ] `frame.rs`: encode/decode, no_std compatible
- [ ] `manifest.rs`: `KeyEntry`, `KeyManifest`, `ClusterStateRoot`, `state_root()`
- [ ] `apdu.rs`: `ClusterApdu` enum, wire builders
- [ ] Full unit test suite including state root round-trips

### Phase 4 — Rust daemon

- [ ] `device.rs`: PCSC device manager, `spawn_blocking` APDU calls
- [ ] `relay.rs`: 4-step DKEK relay state machine
- [ ] `sync.rs`: generation + manifest sync engine
- [ ] `peer.rs`: mTLS TCP connections, frame framing
- [ ] `config.rs`: serde_json persistence
- [ ] `main.rs`: tokio runtime, task spawning, clap CLI
- [ ] Integration test: wire-compatible with Python daemon

### Phase 5 — Embedded controller

- [ ] UART frame relay (one HSM, one uplink)
- [ ] Multi-HSM UART fan-out (up to 4)
- [ ] Sync engine (manifest poll + state root comparison)
- [ ] Status uplink to host daemon
- [ ] Optional: OLED display

---

## 13. New Wire Message Types

Extending the existing `P2H1` framing for cluster sync:

| `msg_type` | Name | Payload |
|---|---|---|
| `0x01` | `NOISE` | (existing) |
| `0x05` | `DEV_PUBKEY` | (existing) |
| `0x06` | `EPHEM_PUB` | (existing) |
| `0x07` | `ENC_DKEK` | (existing) |
| `0xFF` | `ACK` | (existing) |
| `0x10` | `MANIFEST_REQ` | device_id(16) |
| `0x11` | `MANIFEST_RESP` | serialized `KeyManifest` |
| `0x12` | `KEY_BLOB` | key_ref(1) \|\| wrapped_blob(var) |
| `0x13` | `SYNC_COMPLETE` | state_root(32) |
| `0x14` | `STATE_HASH_REQ` | — |
| `0x15` | `STATE_HASH_RESP` | generation(8) \|\| state_root(32) |
| `0x20` | `TOMBSTONE` | key_ref(1) \|\| generation_del(8) \|\| sig(64) |
| `0x21` | `PROMOTE_PRIMARY` | device_id(16) \|\| operator_sig(64) |

---

## 14. Open Questions for Operator Decision

1. **Quorum threshold**: Default `ceil(N/2 + 1)`? Or configurable per operation type?
2. **Orphan policy**: Auto-import orphan keys from a rejoining node, or quarantine them?
3. **Tombstone pruning**: After how long (or after how many acknowledged nodes) can tombstones be garbage-collected?
4. **Pico W as embedded controller**: Worth a separate firmware target, or overkill for the initial use case?
5. **Enrollment ceremony**: Out-of-band fingerprint verification (LCD display on device, operator confirms) vs. purely config-file based enrollment?
