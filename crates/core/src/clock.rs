//! Display both clocks from the same system-clock sample; receipt times remain UTC.
use jiff::{tz::TimeZone, Timestamp, ZonedDateTime};

#[cfg(test)]
thread_local! {
    /// Fixed UTC offset (seconds east) for the current test thread, so a test can render a
    /// machine-independent frame without changing the process environment.
    pub(crate) static TEST_OFFSET: std::cell::Cell<Option<i32>> = const { std::cell::Cell::new(None) };
}

fn local_time(utc: Timestamp) -> ZonedDateTime {
    #[cfg(test)]
    if let Some(offset) = TEST_OFFSET
        .with(|o| o.get())
        .and_then(|s| jiff::tz::Offset::from_seconds(s).ok())
    {
        return utc.to_zoned_datetime(TimeZone::fixed(offset));
    }
    utc.to_zoned_datetime(TimeZone::system())
}

/// The machine's current offset from UTC in seconds east (the same source as the LOCAL clock).
pub fn local_offset_seconds() -> i32 {
    local_time(Timestamp::now()).offset().seconds()
}

/// Parse an RFC 3339 timestamp (`2026-11-14T08:12:45.5Z`, `...+01:00`). The offset is required;
/// a bracketed time zone annotation or a zone without a colon is refused, as before.
pub fn parse_rfc3339(s: &str) -> Option<Timestamp> {
    let b = s.as_bytes();
    let offset_ok = match b.last()? {
        b'Z' | b'z' => true,
        _ => {
            b.len() >= 6
                && matches!(b[b.len() - 6], b'+' | b'-')
                && b[b.len() - 3] == b':'
                && [2, 4, 5].iter().all(|&i| b[b.len() - i].is_ascii_digit())
        }
    };
    if !offset_ok {
        return None;
    }
    s.parse().ok()
}

pub fn labels(now_ms: u64) -> (String, String) {
    let utc = i64::try_from(now_ms)
        .ok()
        .and_then(|ms| Timestamp::from_millisecond(ms).ok());
    match utc {
        Some(utc) => format_labels(utc, &local_time(utc)),
        None => ("UTC unavailable".into(), "LOCAL unavailable".into()),
    }
}

fn format_labels(utc: Timestamp, local: &ZonedDateTime) -> (String, String) {
    (
        utc.strftime("%H:%M:%S UTC").to_string(),
        local.strftime("%H:%M:%S LOCAL %:z").to_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use jiff::tz::Offset;
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
            let local =
                utc.to_zoned_datetime(TimeZone::fixed(Offset::from_seconds(seconds).unwrap()));
            assert_eq!(local.timestamp().as_millisecond(), utc.as_millisecond());
            let (u, l) = format_labels(utc, &local);
            assert_eq!(u, "23:45:12 UTC");
            assert_eq!(l, expected);
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
            .to_zoned_datetime(TimeZone::system())
            .strftime("%H:%M:%S LOCAL %:z")
            .to_string();
        assert_eq!(labels(now.as_millisecond() as u64).1, expected);
    }
    #[test]
    fn test_offset_drives_the_local_offset() {
        TEST_OFFSET.with(|o| o.set(Some(19800)));
        assert_eq!(local_offset_seconds(), 19800);
        TEST_OFFSET.with(|o| o.set(None));
    }
    #[test]
    fn rfc3339_accepts_the_feed_forms_and_refuses_the_rest() {
        for ok in [
            "2026-11-14T08:12:45Z",
            "2026-11-14T08:12:45.123456Z",
            "2026-11-14T09:12:45+01:00",
            "2026-11-14T03:42:45-04:30",
            "2026-11-14 08:12:45z",
        ] {
            let t = parse_rfc3339(ok).unwrap_or_else(|| panic!("{ok}"));
            assert_eq!(t.as_second(), 1_794_643_965, "{ok}");
        }
        for bad in [
            "",
            "2026-11-14",
            "2026-11-14T08:12:45",
            "2026-11-14T08:12:45+0100",
            "2026-11-14T08:12:45Z[Europe/Stockholm]",
            "2026-13-14T08:12:45Z",
            "not a date",
        ] {
            assert!(parse_rfc3339(bad).is_none(), "{bad}");
        }
    }
}
