//! Memory zeroization utilities.
//!
//! Provides secure memory clearing functions that are guaranteed not to be
//! optimized away by the compiler (unlike a naive `buf.fill(0)`).
//!
//! All functions in this module delegate to the `zeroize` crate, which
//! uses volatile writes to prevent the compiler from eliminating the clear.
//!
//! # Usage pattern
//! Prefer using the `zeroize::ZeroizeOnDrop` derive macro on structs that
//! contain secret material (see `pico2hsm_core::key::KeyMaterial`). This
//! module provides manual zeroize utilities for cases where the macro
//! cannot be used (e.g. fixed-size arrays, stack slices).

use zeroize::Zeroize;

/// Securely zero a byte slice in place.
///
/// Uses volatile writes to prevent the compiler from eliding the zeroing.
#[inline]
pub fn zeroize_slice(buf: &mut [u8]) {
    buf.zeroize();
}

/// Securely zero a fixed-size array in place.
#[inline]
pub fn zeroize_array<const N: usize>(buf: &mut [u8; N]) {
    buf.zeroize();
}

/// A RAII guard that zeroizes a byte slice when dropped.
///
/// ```rust,ignore
/// let mut key_bytes = [0u8; 32];
/// let _guard = ZeroizeGuard::new(&mut key_bytes);
/// // key_bytes is zeroed when _guard is dropped
/// ```
pub struct ZeroizeGuard<'a> {
    buf: &'a mut [u8],
}

impl<'a> ZeroizeGuard<'a> {
    /// Create a new `ZeroizeGuard` that will zero `buf` on drop.
    pub fn new(buf: &'a mut [u8]) -> Self {
        ZeroizeGuard { buf }
    }
}

impl<'a> Drop for ZeroizeGuard<'a> {
    fn drop(&mut self) {
        self.buf.zeroize();
    }
}

/// Copy a private key into a zeroizing fixed-size buffer.
///
/// Returns `None` when the key does not fit — e.g. an over-long imported
/// key — instead of panicking (and hard-faulting core1) on the slice copy.
/// The buffer is wiped when dropped, so no key copy lingers on the stack.
pub fn key_buf<const N: usize>(key: &[u8]) -> Option<zeroize::Zeroizing<[u8; N]>> {
    let mut buf = zeroize::Zeroizing::new([0u8; N]);
    buf.get_mut(..key.len())?.copy_from_slice(key);
    Some(buf)
}

/// A `heapless::Vec` of secret bytes that is wiped (volatile) when dropped.
/// `heapless::Vec` has no `Zeroize` impl, so `Zeroizing` cannot wrap it.
pub struct WipeOnDrop<const N: usize>(pub heapless::Vec<u8, N>);

impl<const N: usize> WipeOnDrop<N> {
    /// An empty buffer.
    pub fn new() -> Self {
        WipeOnDrop(heapless::Vec::new())
    }
}

impl<const N: usize> core::ops::Deref for WipeOnDrop<N> {
    type Target = heapless::Vec<u8, N>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<const N: usize> core::ops::DerefMut for WipeOnDrop<N> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<const N: usize> Drop for WipeOnDrop<N> {
    fn drop(&mut self) {
        self.0.as_mut_slice().zeroize();
    }
}
