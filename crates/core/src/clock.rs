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
