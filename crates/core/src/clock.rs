//! Display both clocks from the same system-clock sample; receipt times remain UTC.
use jiff::{tz::TimeZone, Timestamp, Zoned};

#[cfg(test)]
thread_local! {
    /// Fixed UTC offset (seconds east) for the current test thread, so a test can render a
    /// machine-independent frame without changing the process environment.
    pub(crate) static TEST_OFFSET: std::cell::Cell<Option<i32>> = const { std::cell::Cell::new(None) };
}

fn local_zone() -> TimeZone {
    #[cfg(test)]
    if let Some(offset) = TEST_OFFSET
        .with(|o| o.get())
        .and_then(|s| jiff::tz::Offset::from_seconds(s).ok())
    {
        return TimeZone::fixed(offset);
    }
    TimeZone::system()
}

/// Strict RFC 3339 (`YYYY-MM-DDTHH:MM:SS[.frac](Z|±HH:MM)`), as chrono's `parse_from_rfc3339`
/// accepted it. jiff's own parser is wider (basic format, hour-only times and offsets, bracket
/// annotations), so the shape is checked first; feed text that passes is shown as it came.
pub(crate) fn rfc3339(s: &str) -> Option<Timestamp> {
    let b = s.as_bytes();
    let shape = (20..=35).contains(&b.len())
        && b[4] == b'-'
        && b[7] == b'-'
        && matches!(b[10], b'T' | b't' | b' ')
        && b[13] == b':'
        && b[16] == b':'
        && b[..19]
            .iter()
            .enumerate()
            .all(|(i, c)| matches!(i, 4 | 7 | 10 | 13 | 16) || c.is_ascii_digit())
        && b[19..]
            .iter()
            .all(|c| c.is_ascii_digit() || matches!(c, b'.' | b'Z' | b'z' | b'+' | b'-' | b':'));
    if !shape {
        return None;
    }
    let tail = &s[19..];
    let offset = tail.trim_start_matches(|c: char| c == '.' || c.is_ascii_digit());
    if !(offset.eq_ignore_ascii_case("z")
        || (offset.len() == 6
            && matches!(offset.as_bytes()[0], b'+' | b'-')
            && offset.as_bytes()[3] == b':'))
    {
        return None;
    }
    s.parse().ok()
}

pub fn labels(now_ms: u64) -> (String, String) {
    let utc = i64::try_from(now_ms)
        .ok()
        .and_then(|ms| Timestamp::from_millisecond(ms).ok());
    match utc {
        Some(utc) => format_labels(utc, &utc.to_zoned(local_zone())),
        None => ("UTC unavailable".into(), "LOCAL unavailable".into()),
    }
}

fn format_labels(utc: Timestamp, local: &Zoned) -> (String, String) {
    (
        utc.strftime("%H:%M:%S UTC").to_string(),
        local.strftime("%H:%M:%S LOCAL %:z").to_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn local_offsets_preserve_the_same_instant_across_midnight() {
        let utc: Timestamp = "2026-10-28T23:45:12Z".parse().unwrap();
        for (seconds, expected) in [
            (3600, "00:45:12 LOCAL +01:00"),
            (7200, "01:45:12 LOCAL +02:00"),
            (19800, "05:15:12 LOCAL +05:30"),
            (-12600, "20:15:12 LOCAL -03:30"),
            (0, "23:45:12 LOCAL +00:00"),
        ] {
            let zone = TimeZone::fixed(jiff::tz::Offset::from_seconds(seconds).unwrap());
            let local = utc.to_zoned(zone);
            assert_eq!(local.timestamp(), utc);
            let (u, l) = format_labels(utc, &local);
            assert_eq!(u, "23:45:12 UTC");
            assert_eq!(l, expected);
        }
    }
    #[test]
    fn rfc3339_is_strict_like_chrono() {
        for ok in [
            "2026-11-20T12:30:00Z",
            "2026-11-20 12:30:00z",
            "2026-11-20T13:30:00.123+01:00",
            "2018-12-20T20:55:14+00:00",
        ] {
            assert!(rfc3339(ok).is_some(), "{ok}");
        }
        for bad in [
            "20261120T123000Z",
            "2026-11-20T12Z",
            "2026-11-20T12:30Z",
            "2026-11-20T12:30:00+01",
            "2026-11-20T12:30:00,5Z",
            "2026-11-20T12:30:00Z[Europe/Stockholm]",
            "2026-11-20T12:30:00Z[x-foo=aaaa]",
            "+002026-11-20T12:30:00Z",
            "2026-11-20T12:30:00",
            "",
        ] {
            assert!(rfc3339(bad).is_none(), "{bad}");
        }
    }
    #[test]
    fn unsupported_timestamp_has_explicit_fallback() {
        assert_eq!(
            labels(u64::MAX),
            ("UTC unavailable".into(), "LOCAL unavailable".into())
        );
    }
    #[test]
    fn system_timezone_is_used() {
        let now = Timestamp::now();
        let expected = now
            .to_zoned(TimeZone::system())
            .strftime("%H:%M:%S LOCAL %:z")
            .to_string();
        assert_eq!(labels(now.as_millisecond() as u64).1, expected);
    }
}
