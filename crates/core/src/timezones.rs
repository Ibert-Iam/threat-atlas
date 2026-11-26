//! Hourly time-zone labels for the shared map.
//!
//! The map shows one label per 15-degree band, centred on the band's meridian (UTC at 0°, UTC+1 at 15°E
//! and so on), using whole-hour offsets from UTC. The band that holds the viewer gets the viewer's real
//! local hour from the system clock instead, so civil time zones and daylight saving time are right
//! where the viewer is (Spain or France at UTC+1, for example, although they lie in the UTC band).
//! Labels change exactly on the full hour (or the local half/quarter hour) and never tick between frames.

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

/// Local hour 0-23 for any offset in seconds east (also +05:30, -03:30 and daylight saving time).
pub fn local_hour_at(now_ms: u64, offset_seconds: i32) -> u8 {
    let local = (now_ms / 1000) as i64 + offset_seconds as i64;
    (local.div_euclid(3600).rem_euclid(24)) as u8
}

/// Centre longitude of band `i` (its meridian): -180° for UTC-12, 0° for UTC, 165°E for UTC+11.
pub fn band_longitude(i: usize) -> f64 {
    -180.0 + i as f64 * 15.0
}

/// The band whose meridian is nearest to `lon` (east of 172.5°E wraps to the UTC-12 band at 180°).
pub fn band_index(lon: f64) -> usize {
    let lon = (lon + 180.0).rem_euclid(360.0) - 180.0;
    ((lon / 15.0).round() as i32 + 12).rem_euclid(24) as usize
}

/// `(longitude, hour, is_local)` for all 24 bands, west to east. `local` is the viewer's longitude and
/// UTC offset in seconds; that band shows the viewer's real local hour and is marked.
pub fn labels(now_ms: u64, local: Option<(f64, i32)>) -> [(f64, u8, bool); 24] {
    let utc = utc_hour(now_ms);
    let mut out = [(0.0, 0, false); 24];
    for (i, offset) in OFFSETS.iter().enumerate() {
        out[i] = (band_longitude(i), local_hour(utc, *offset), false);
    }
    if let Some((lon, offset_seconds)) = local {
        let i = band_index(lon);
        out[i].1 = local_hour_at(now_ms, offset_seconds);
        out[i].2 = true;
    }
    out
}

/// The viewer's longitude: the host's location when known, otherwise the meridian of the UTC offset.
pub fn viewer_longitude(location_lon: Option<f64>, offset_seconds: i32) -> f64 {
    location_lon.unwrap_or_else(|| {
        let lon = offset_seconds as f64 / 3600.0 * 15.0;
        (lon + 180.0).rem_euclid(360.0) - 180.0
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOON_UTC: u64 = 12 * 3_600_000;

    #[test]
    fn every_zone_matches_utc_at_a_fixed_hour() {
        let labels = labels(NOON_UTC, None);
        assert_eq!(labels.len(), 24);
        for (i, (_, hour, local)) in labels.iter().enumerate() {
            assert_eq!(*hour as i32, (12 + OFFSETS[i]).rem_euclid(24));
            assert!(!local);
        }
        assert_eq!(labels[12].1, 12); // UTC
        assert_eq!(labels[24 - 1].1, 23); // UTC+11
    }

    #[test]
    fn labels_sit_on_their_zone_meridian() {
        let labels = labels(NOON_UTC, None);
        assert_eq!(labels[12].0, 0.0, "UTC over Greenwich");
        assert_eq!(labels[13].0, 15.0, "UTC+1 over central Europe");
        assert_eq!(labels[0].0, -180.0);
        assert_eq!(labels[23].0, 165.0);
        // Nominal bands: London 12, Stockholm (18.07°E) 13, Helsinki (24.9°E) 14 at 12:00 UTC.
        assert_eq!(labels[band_index(-0.13)].1, 12);
        assert_eq!(labels[band_index(18.07)].1, 13);
        assert_eq!(labels[band_index(24.94)].1, 14);
        assert_eq!(band_index(179.0), 0, "east of 172.5°E wraps to 180°");
        assert_eq!(band_index(-179.0), 0);
    }

    #[test]
    fn the_viewers_band_shows_real_local_time() {
        // Stockholm in winter: CET, +01:00.
        let l = labels(NOON_UTC, Some((18.07, 3600)));
        let i = band_index(18.07);
        assert_eq!((l[i].1, l[i].2), (13, true));
        // Madrid lies in the UTC band but uses CET: the viewer's band shows 13, not 12.
        let l = labels(NOON_UTC, Some((-3.7, 3600)));
        assert_eq!((l[12].1, l[12].2), (13, true));
        assert_eq!(l[13].1, 13, "other bands stay nominal");
        // Stockholm in summer: CEST, +02:00.
        let l = labels(NOON_UTC, Some((18.07, 7200)));
        assert_eq!(l[band_index(18.07)].1, 14);
        // India, +05:30, at 12:45 UTC: 18:15 local, so hour 18.
        let t = NOON_UTC + 45 * 60_000;
        assert_eq!(labels(t, Some((77.2, 19800)))[band_index(77.2)].1, 18);
        // Only one band is marked.
        assert_eq!(
            labels(NOON_UTC, Some((18.07, 3600)))
                .iter()
                .filter(|x| x.2)
                .count(),
            1
        );
    }

    #[test]
    fn viewer_longitude_falls_back_to_the_offset_meridian() {
        assert_eq!(viewer_longitude(Some(18.07), 3600), 18.07);
        assert_eq!(viewer_longitude(None, 3600), 15.0);
        assert_eq!(viewer_longitude(None, -5 * 3600), -75.0);
        assert_eq!(
            viewer_longitude(None, 13 * 3600),
            -165.0,
            "UTC+13 wraps west"
        );
    }

    #[test]
    fn local_hour_handles_negative_and_half_hour_offsets() {
        assert_eq!(local_hour_at(NOON_UTC, -12_600), 8); // -03:30 → 08:30
        assert_eq!(local_hour_at(30 * 60_000, -3600), 23); // 00:30 UTC at -01:00 → 23:30
    }

    #[test]
    fn labels_change_once_on_the_full_hour() {
        let hour = NOON_UTC;
        assert_eq!(labels(hour, None), labels(hour + 3_599_999, None));
        let next = labels(hour + 3_600_000, None);
        for (a, b) in labels(hour, None).iter().zip(next.iter()) {
            assert_eq!(a.1, (b.1 + 23) % 24, "every zone advances one hour");
        }
        assert_ne!(labels(hour, None), next);
    }
}
