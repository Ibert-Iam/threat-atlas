//! Low-precision solar position for the map's day/night terminator. Pure clock input; no network,
//! configuration or state. Accuracy is about 0.1–0.5° at map scale, enough for a 980×510 map.

use std::f64::consts::PI;

/// Mean solar day in milliseconds; the map only needs the current instant, not a calendar.
const DAY_MS: f64 = 86_400_000.0;

/// Days since J2000.0 (2000-01-01 12:00 UTC).
fn days_since_j2000(now_ms: u64) -> f64 {
    (now_ms as f64 - 946_728_000_000.0) / DAY_MS
}

fn radians(degrees: f64) -> f64 {
    degrees * PI / 180.0
}

fn degrees(radians: f64) -> f64 {
    radians * 180.0 / PI
}

/// Subsolar point `(latitude, longitude)` in degrees. Longitude is −180..180, positive east.
///
/// Standard low-precision formulas: mean longitude, mean anomaly, ecliptic longitude, obliquity,
/// right ascension and Greenwich mean sidereal time. The equation of time is implicit in the
/// right-ascension/sidereal-time difference.
pub fn subsolar_point(now_ms: u64) -> (f64, f64) {
    let n = days_since_j2000(now_ms);
    let mean_longitude = (280.460 + 0.985_647_4 * n).rem_euclid(360.0);
    let mean_anomaly = radians((357.528 + 0.985_600_3 * n).rem_euclid(360.0));
    let ecliptic_longitude = radians(
        (mean_longitude + 1.915 * mean_anomaly.sin() + 0.020 * (2.0 * mean_anomaly).sin())
            .rem_euclid(360.0),
    );
    let obliquity = radians(23.439 - 0.000_000_4 * n);
    let declination = (obliquity.sin() * ecliptic_longitude.sin()).asin();
    let right_ascension =
        degrees((obliquity.cos() * ecliptic_longitude.sin()).atan2(ecliptic_longitude.cos()))
            .rem_euclid(360.0);
    let gmst = (280.460_618_37 + 360.985_647_366_29 * n).rem_euclid(360.0);
    let longitude = (right_ascension - gmst + 180.0).rem_euclid(360.0) - 180.0;
    (degrees(declination), longitude)
}

/// Sun altitude in degrees at `(lat, lon)` and `now_ms`. Negative is night; 0° is the horizon;
/// −6° is the end of civil twilight.
pub fn sun_altitude_deg(lat: f64, lon: f64, now_ms: u64) -> f64 {
    let (decl, subsolar_lon) = subsolar_point(now_ms);
    let hour_angle = radians(lon - subsolar_lon);
    let lat = radians(lat);
    let decl = radians(decl);
    degrees(
        (lat.sin() * decl.sin() + lat.cos() * decl.cos() * hour_angle.cos())
            .clamp(-1.0, 1.0)
            .asin(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, UNIX_EPOCH};

    fn unix_ms(year: i32, month: u32, day: u32, hour: u32, minute: u32) -> u64 {
        // Small civil-date helper; all test dates are after 1970 and use UTC.
        let leap = |y: i32| (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
        let mut days = 0i64;
        for y in 1970..year {
            days += if leap(y) { 366 } else { 365 };
        }
        let month_days = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
        for m in 0..(month - 1) {
            days += month_days[m as usize] as i64 + u32::from(m == 1 && leap(year)) as i64;
        }
        days += (day - 1) as i64;
        let seconds = days as u64 * 86_400 + hour as u64 * 3_600 + minute as u64 * 60;
        UNIX_EPOCH
            .checked_add(Duration::from_secs(seconds))
            .unwrap()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
    }

    #[test]
    fn equinox_and_solstices_have_the_expected_declination() {
        let equinox = subsolar_point(unix_ms(2026, 3, 20, 12, 7)).0;
        assert!(equinox.abs() < 0.5, "equinox latitude {equinox}");
        let june = subsolar_point(unix_ms(2026, 6, 21, 12, 1)).0;
        assert!((june - 23.44).abs() < 0.5, "June latitude {june}");
        let december = subsolar_point(unix_ms(2026, 12, 21, 12, 0)).0;
        assert!(
            (december + 23.44).abs() < 0.5,
            "December latitude {december}"
        );
    }

    #[test]
    fn subsolar_longitude_is_near_greenwich_at_local_noon() {
        // At these UTC times the equation of time puts solar noon near Greenwich.
        for now in [
            unix_ms(2026, 3, 20, 12, 7),
            unix_ms(2026, 6, 21, 12, 1),
            unix_ms(2026, 12, 21, 12, 0),
        ] {
            let longitude = subsolar_point(now).1;
            assert!(longitude.abs() <= 1.0, "subsolar longitude {longitude}");
        }
    }

    #[test]
    fn altitude_is_day_at_the_subsolar_point_and_night_opposite() {
        let now = unix_ms(2026, 3, 20, 12, 0);
        let (lat, lon) = subsolar_point(now);
        assert!(sun_altitude_deg(lat, lon, now) > 80.0);
        let opposite = ((lon + 360.0) % 360.0) - 180.0;
        assert!(sun_altitude_deg(lat, opposite, now) < -80.0);
    }
}
