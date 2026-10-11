//! Global heap allocator for RSA operations.
//!
//! Only compiled when the `rsa` feature is enabled.
//! Provides a 48 KB static heap for RSA key generation and operations.
//!
//! RSA operations (key generation, PKCS#1 v1.5 sign/verify, OAEP encrypt/decrypt)
//! require dynamic memory because the `rsa` crate uses `Vec<u32>` internally
//! for big-integer arithmetic via `crypto-bigint`. Without a global allocator
//! these operations cannot run on `no_std` targets.
//!
//! # Heap size rationale
//! 48 KB is sufficient for:
//! - RSA-2048 key generation: ~12 KB peak allocation
//! - RSA-4096 key generation: ~40 KB peak allocation
//! The RP2350 has 520 KB of SRAM, so 48 KB is a reasonable trade-off.
//!
//! # Safety
//! The allocator is initialized ONCE at startup via `init()`.
//! Calling `init()` more than once is safe — the `AtomicBool` guard
//! makes the function idempotent.
//!
//! The `static mut HEAP_MEM` array is only accessed inside `init()`,
//! under the protection of the `AtomicBool` swap. After `init()` the
//! memory is owned exclusively by the allocator and must not be accessed
//! directly.

#[cfg(feature = "rsa")]
use embedded_alloc::LlffHeap as Heap;

/// Global allocator instance — empty until `init()` is called.
///
/// Only registered as the global allocator on ARM targets. On x86_64 (host
/// tests), the std allocator is used and registering a second one would fail.
#[cfg(all(feature = "rsa", target_arch = "arm"))]
#[global_allocator]
static HEAP: Heap = Heap::empty();

/// Dummy instance used on non-ARM (test) targets so that `init()` compiles.
#[cfg(all(feature = "rsa", not(target_arch = "arm")))]
static HEAP: Heap = Heap::empty();

/// Guard that prevents double-initialization (ARM only; no-op on host).
#[cfg(all(feature = "rsa", target_arch = "arm"))]
static HEAP_INITIALIZED: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

/// Initialize the global heap allocator.
///
/// Must be called once before any RSA operations.
/// Safe to call multiple times — only the first call initializes the heap;
/// subsequent calls return immediately.
///
/// On non-ARM (x86_64 host test) targets this is a no-op because the std
/// allocator is already available.
///
/// # Panics
/// Does not panic. All unsafe operations are bounded by the static array.
#[cfg(all(feature = "rsa", target_arch = "arm"))]
pub fn init() {
    use core::sync::atomic::Ordering;

    // swap(true, SeqCst) returns the OLD value.
    // If it was already true, another call already initialized the heap.
    if HEAP_INITIALIZED.swap(true, Ordering::SeqCst) {
        return; // already initialized — idempotent
    }

    // 48 KB heap for RSA big-integer arithmetic.
    const HEAP_SIZE: usize = 49_152; // 48 × 1024 bytes

    // SAFETY:
    // - `HEAP_MEM` is a `static mut` zero-initialized array, accessed here
    //   exactly once (guarded by the AtomicBool above).
    // - After this call, `HEAP` owns the memory and `HEAP_MEM` must not be
    //   accessed again; the `static mut` borrow ends before `init()` returns.
    // - `LlffHeap::init(base, size)` expects the memory to be valid for the
    //   entire program lifetime — `static mut` satisfies this requirement.
    static mut HEAP_MEM: [core::mem::MaybeUninit<u8>; HEAP_SIZE] =
        [core::mem::MaybeUninit::uninit(); HEAP_SIZE];

    unsafe {
        HEAP.init(core::ptr::addr_of!(HEAP_MEM) as usize, HEAP_SIZE);
    }
}

/// No-op on non-ARM hosts: std provides the global allocator.
#[cfg(all(feature = "rsa", not(target_arch = "arm")))]
pub fn init() {}

/// No-op stub when the `rsa` feature is disabled.
///
/// Allows callers to always call `allocator::init()` without feature guards.
#[cfg(not(feature = "rsa"))]
pub fn init() {}
