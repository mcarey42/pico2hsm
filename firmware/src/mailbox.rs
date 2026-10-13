//! Single-slot mailbox for handing a byte buffer between the two cores.
//!
//! Core0 and core1 used to pass every APDU and response by value through
//! `embassy_sync` channels: each hop copied up to 4 KB onto a stack (the
//! sender's local, the channel slot, the receiver's local), and the channel
//! slots kept the last APDU and response after use (audit M-04, Z-03).
//! A mailbox is one static buffer that the producer fills in place and the
//! consumer reads in place; reading ends with a wipe.
//!
//! Single producer, single consumer.  `full` hands the buffer over: the
//! producer only touches it while `full` is false, the consumer only while
//! it is true, and the Release store / Acquire load order the buffer
//! accesses around the flag.  Waking the other side (`sev`, a doorbell
//! channel) is the caller's business.

use core::cell::UnsafeCell;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicBool, Ordering};

use heapless::Vec;
use zeroize::Zeroize;

pub struct Mailbox<const N: usize> {
    buf: UnsafeCell<Vec<u8, N>>,
    full: AtomicBool,
}

// SAFETY: access to `buf` is handed over by `full` (see the module docs).
unsafe impl<const N: usize> Sync for Mailbox<N> {}

impl<const N: usize> Default for Mailbox<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> Mailbox<N> {
    pub const fn new() -> Self {
        Self {
            buf: UnsafeCell::new(Vec::new()),
            full: AtomicBool::new(false),
        }
    }

    /// Holds a message the consumer has not taken yet.
    pub fn is_full(&self) -> bool {
        self.full.load(Ordering::Acquire)
    }

    /// Producer: if the mailbox is empty, fill it with `f` (which gets an
    /// empty buffer) and post it.  Returns `None`, leaving `f` uncalled,
    /// while the consumer still holds the previous message.
    pub fn try_fill<R>(&self, f: impl FnOnce(&mut Vec<u8, N>) -> R) -> Option<R> {
        if self.full.load(Ordering::Acquire) {
            return None;
        }
        // SAFETY: empty, so the producer (us) owns the buffer.
        let buf = unsafe { &mut *self.buf.get() };
        buf.clear();
        let r = f(buf);
        self.full.store(true, Ordering::Release);
        Some(r)
    }

    /// Consumer: take the posted message.  The returned guard derefs to the
    /// buffer; dropping it wipes the buffer and empties the mailbox.
    pub fn try_take(&self) -> Option<Taken<'_, N>> {
        if !self.full.load(Ordering::Acquire) {
            return None;
        }
        Some(Taken { mailbox: self })
    }
}

/// A message taken from a [`Mailbox`]; wiped and released on drop.
pub struct Taken<'a, const N: usize> {
    mailbox: &'a Mailbox<N>,
}

impl<const N: usize> Deref for Taken<'_, N> {
    type Target = Vec<u8, N>;
    fn deref(&self) -> &Vec<u8, N> {
        // SAFETY: full, so the consumer (this guard) owns the buffer.
        unsafe { &*self.mailbox.buf.get() }
    }
}

impl<const N: usize> DerefMut for Taken<'_, N> {
    fn deref_mut(&mut self) -> &mut Vec<u8, N> {
        // SAFETY: as for `deref`; the guard is unique (not Clone).
        unsafe { &mut *self.mailbox.buf.get() }
    }
}

impl<const N: usize> Drop for Taken<'_, N> {
    fn drop(&mut self) {
        let buf = self.deref_mut();
        buf.as_mut_slice().zeroize();
        buf.clear();
        self.mailbox.full.store(false, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fill_take_release() {
        let m: Mailbox<8> = Mailbox::new();
        assert!(m.try_take().is_none());
        assert_eq!(
            m.try_fill(|b| b.extend_from_slice(b"abc").is_ok()),
            Some(true)
        );
        assert!(m.is_full());
        // The consumer hasn't taken it: a second fill is refused.
        assert!(m.try_fill(|_| unreachable!()).is_none());
        {
            let mut t = m.try_take().unwrap();
            assert_eq!(&t[..], b"abc");
            t.push(b'd').unwrap();
        }
        assert!(!m.is_full());
        // Dropping the guard wiped and emptied the buffer.
        assert_eq!(unsafe { &*m.buf.get() }.len(), 0);
        m.try_fill(|b| b.extend_from_slice(b"x").unwrap()).unwrap();
        assert_eq!(&m.try_take().unwrap()[..], b"x");
    }

    #[test]
    fn wipe_covers_the_whole_message() {
        let m: Mailbox<4> = Mailbox::new();
        m.try_fill(|b| b.extend_from_slice(&[0xAA; 4]).unwrap())
            .unwrap();
        let t = m.try_take().unwrap();
        let p = t.as_ptr();
        drop(t);
        // SAFETY: `m` still owns the storage `p` points into.
        let raw = unsafe { core::slice::from_raw_parts(p, 4) };
        assert_eq!(raw, &[0; 4]);
    }
}
