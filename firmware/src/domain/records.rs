//! Keystore layout of the domain records.
//!
//! ```text
//! KeyId bits   31–24      23–16   15–8   7–0
//! sidecar      partition  0x10    local object id (16 bits)
//! member slot  0xD0       0x10    0x01   slot (0..32)
//! pinned peer  0xD0       0x10    0x02   0x00
//! ```
//!
//! A sidecar mirrors the SC-HSM object it describes: the low 16 bits are
//! that object's own `KeyId` bits 15–0 (key reference `00 rr`, or the EF's
//! file ID), and the partition byte is the object's partition.  Domain-wide
//! records use partition byte [`DOMAIN_PARTITION`], which no SC-HSM object
//! uses, so the two never collide.

use pico2hsm_core::key::KeyId;

use super::APPLET_DOMAIN;

/// Partition byte of domain-wide records (member list, pinned peer).
pub const DOMAIN_PARTITION: u8 = 0xD0;

/// Record kind (bits 15–8) of a member-list slot.
const KIND_MEMBER: u8 = 0x01;
/// Record kind (bits 15–8) of the pinned peer.
const KIND_PINNED_PEER: u8 = 0x02;

const fn domain_record(kind: u8, index: u8) -> KeyId {
    KeyId(
        (DOMAIN_PARTITION as u32) << 24
            | (APPLET_DOMAIN as u32) << 16
            | (kind as u32) << 8
            | index as u32,
    )
}

/// The sidecar of the SC-HSM object `local` (a key or an EF).
pub fn sidecar(local: KeyId) -> KeyId {
    KeyId(
        (u32::from(local.partition()) << 24)
            | (u32::from(APPLET_DOMAIN) << 16)
            | (local.0 & 0xFFFF),
    )
}

/// Member-list slot `slot`.
pub const fn member_slot(slot: u8) -> KeyId {
    domain_record(KIND_MEMBER, slot)
}

/// The peer pinned for the next DKEK exchange (§5.2 step 3).
pub const PINNED_PEER: KeyId = domain_record(KIND_PINNED_PEER, 0);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_never_collide_with_each_other_or_applets() {
        let key = KeyId::sc_hsm(0, 0x05);
        let ef = KeyId::sc_hsm_ef(0, 0xCD, 0x05);
        assert_eq!(sidecar(key).0, 0x0010_0005);
        assert_eq!(sidecar(ef).0, 0x0010_CD05);
        assert_ne!(sidecar(key), sidecar(ef));
        for s in 0..32 {
            let m = member_slot(s);
            assert_eq!(m.applet_byte(), APPLET_DOMAIN);
            assert_ne!(m, PINNED_PEER);
            assert_ne!(m.partition(), 0, "never a partition-0 sidecar");
        }
        assert_eq!(PINNED_PEER.0, 0xD010_0200);
    }
}
