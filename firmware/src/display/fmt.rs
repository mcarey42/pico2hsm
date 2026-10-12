//! Number formatting for the display (no heap; `heapless::String`).

use core::fmt::Write as _;
use heapless::String;

/// Uptime: `HH:MM:SS` under a day, `Nd HH:MM` under 1000 days, then `Nd`.
pub fn fmt_uptime(secs: u32) -> String<12> {
    let mut s = String::new();
    let days = secs / 86_400;
    let _ = if days == 0 {
        write!(
            s,
            "{:02}:{:02}:{:02}",
            secs / 3600,
            (secs / 60) % 60,
            secs % 60
        )
    } else if days < 1000 {
        write!(
            s,
            "{}d {:02}:{:02}",
            days,
            (secs / 3600) % 24,
            (secs / 60) % 60
        )
    } else {
        write!(s, "{days}d")
    };
    s
}

/// Coarse age of an event, as the activity line shows it.  Equal labels
/// render identically, so the view only changes when the text does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Age {
    /// Under a minute.
    Secs(u8),
    /// Under an hour.
    Mins(u8),
    /// Under a day.
    Hours(u8),
    /// A day or more.
    Days(u16),
}

impl Age {
    /// The label for `secs` seconds.
    pub fn of_secs(secs: u32) -> Self {
        match secs {
            0..=59 => Age::Secs(secs as u8),
            60..=3599 => Age::Mins((secs / 60) as u8),
            3600..=86_399 => Age::Hours((secs / 3600) as u8),
            _ => Age::Days((secs / 86_400).min(9999) as u16),
        }
    }

    /// `"4s ago"`, `"3m ago"`, ...; `short` drops `" ago"`.
    pub fn text(self, short: bool) -> String<12> {
        let mut s = String::new();
        let _ = match self {
            Age::Secs(n) => write!(s, "{n}s"),
            Age::Mins(n) => write!(s, "{n}m"),
            Age::Hours(n) => write!(s, "{n}h"),
            Age::Days(n) => write!(s, "{n}d"),
        };
        if !short {
            let _ = s.push_str(" ago");
        }
        s
    }
}

/// Elapsed time of a running operation: `m:ss` (minutes saturate at 99).
pub fn fmt_elapsed(secs: u32) -> String<8> {
    let mut s = String::new();
    let _ = write!(s, "{}:{:02}", (secs / 60).min(99), secs % 60);
    s
}

/// Four upper-case hex digits.
pub fn hex4(v: u16) -> String<4> {
    let mut s = String::new();
    let _ = write!(s, "{v:04X}");
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uptime_edges() {
        assert_eq!(fmt_uptime(0).as_str(), "00:00:00");
        assert_eq!(fmt_uptime(59).as_str(), "00:00:59");
        assert_eq!(fmt_uptime(3599).as_str(), "00:59:59");
        assert_eq!(fmt_uptime(86_399).as_str(), "23:59:59");
        assert_eq!(fmt_uptime(86_400).as_str(), "1d 00:00");
        assert_eq!(fmt_uptime(3_600_000).as_str(), "41d 16:00");
        assert_eq!(fmt_uptime(999 * 86_400 + 3599).as_str(), "999d 00:59");
        assert_eq!(fmt_uptime(1000 * 86_400).as_str(), "1000d");
        assert_eq!(fmt_uptime(u32::MAX).as_str(), "49710d");
    }

    #[test]
    fn ages() {
        assert_eq!(Age::of_secs(4).text(false).as_str(), "4s ago");
        assert_eq!(Age::of_secs(60).text(true).as_str(), "1m");
        assert_eq!(Age::of_secs(7200).text(false).as_str(), "2h ago");
        assert_eq!(Age::of_secs(u32::MAX).text(false).as_str(), "9999d ago");
        assert_eq!(Age::of_secs(61), Age::of_secs(119));
    }

    #[test]
    fn elapsed_and_hex() {
        assert_eq!(fmt_elapsed(75).as_str(), "1:15");
        assert_eq!(fmt_elapsed(u32::MAX).as_str(), "99:15");
        assert_eq!(hex4(0x3f9a).as_str(), "3F9A");
    }
}
