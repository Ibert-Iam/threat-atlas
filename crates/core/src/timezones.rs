//! Hourly time-zone labels for the shared map.
//!
//! The map shows one label per 15-degree band, using whole-hour offsets from UTC.
//! Labels are derived from the UTC hour only, so they change exactly on the full
//! hour and never tick between frames.

/// Whole-hour offsets from UTC for the 24 bands, west to east.
pub const OFFSETS: [i32; 24] = [
    -12, -11, -10, -9, -8, -7, -6, -5, -4, -3, -2, -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11,
];

/// UTC hour 0-23 for a timestamp in milliseconds.
pub fn utc_hour(now_ms: u64) -> u32 {
    ((now_ms / 3_600_000) % 24) as u32
}

/// Local hour 0-23 in a zone, with a whole-hour offset from UTC.
pub fn local_hour(utc_hour: u32, offset_hours: i32) -> u8 {
    ((utc_hour as i32 + offset_hours).rem_euclid(24)) as u8
}

/// `(longitude, local_hour)` for all 24 bands, west to east.
pub fn labels(now_ms: u64) -> [(f64, u8); 24] {
    let utc = utc_hour(now_ms);
    let mut out = [(0.0, 0); 24];
    for (i, offset) in OFFSETS.iter().enumerate() {
        out[i] = (-172.5 + i as f64 * 15.0, local_hour(utc, *offset));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_zone_matches_utc_at_a_fixed_hour() {
        let labels = labels(12 * 3_600_000);
        assert_eq!(labels.len(), 24);
        for (i, (_, hour)) in labels.iter().enumerate() {
            assert_eq!(*hour as i32, (12 + OFFSETS[i]).rem_euclid(24));
        }
        assert_eq!(labels[12].1, 12); // UTC
        assert_eq!(labels[24 - 1].1, 23); // UTC+11
    }

    #[test]
    fn labels_change_once_on_the_full_hour() {
        let hour = 12 * 3_600_000;
        assert_eq!(labels(hour), labels(hour + 3_599_999));
        let next = labels(hour + 3_600_000);
        for (a, b) in labels(hour).iter().zip(next.iter()) {
            assert_eq!(a.1, (b.1 + 23) % 24, "every zone advances one hour");
        }
        assert_ne!(labels(hour), next);
    }
}
