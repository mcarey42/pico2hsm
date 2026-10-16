//! The firmware image version: the IMAGE_DEF VERSION item the bootrom
//! compares between A/B slots (`image_def`), and the version GET
//! PROVISIONING STATUS reports.  Compiled on the host too.

/// Parse a decimal `u16` at compile time (the build script's version).
const fn parse_u16(s: &str) -> u16 {
    let b = s.as_bytes();
    let mut i = 0;
    let mut v: u32 = 0;
    while i < b.len() {
        assert!(b[i].is_ascii_digit(), "image version digit");
        v = v * 10 + (b[i] - b'0') as u32;
        assert!(v <= 0xFFFF, "image version too large");
        i += 1;
    }
    v as u16
}

/// Image version (build.rs: crate version, or `PICO2HSM_IMAGE_VERSION`):
/// with a partition table, the bootrom boots the higher of the A/B images.
pub const IMAGE_MAJOR: u16 = parse_u16(env!("PICO2HSM_IMAGE_MAJOR"));
/// Minor version: `minor * 256 + patch`.
pub const IMAGE_MINOR: u16 = parse_u16(env!("PICO2HSM_IMAGE_MINOR"));
