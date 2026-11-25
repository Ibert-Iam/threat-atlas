//! Settings → Updates (WP3), the platform-neutral part: which version and channel this build is, when the
//! next daily check is due, how one check runs through `update_check::check`, and the menu text for each of
//! the five outcomes. The Windows host (`soc_update.rs`) only adds the HTTPS download, the state file and the
//! menu. Nothing here downloads, writes files or installs anything.
#![cfg_attr(not(windows), allow(dead_code))]
use serde::{Deserialize, Serialize};
use threat_atlas_core::{
    feed_signature::{official_trust_root, TrustRoot},
    update_check::{check, CheckError, CheckState, Installed, Outcome},
    update_feed::{Channel, FeedError, Kind},
};

/// The signed feed and its detached signature (docs/UPDATE-CHANNELS.md, "Location").
pub const FEED_HOST: &str = "raw.githubusercontent.com";
pub const FEED_PATH: &str = "/Ibert-Iam/threat-atlas/update-feed/feed.json";
pub const SIGNATURE_PATH: &str = "/Ibert-Iam/threat-atlas/update-feed/feed.json.sig";
/// The feed parser refuses anything larger; the signature is one short line.
pub const MAX_FEED_BYTES: usize = threat_atlas_core::update_feed::MAX_FEED_BYTES;
pub const MAX_SIGNATURE_BYTES: usize = threat_atlas_core::feed_signature::MAX_SIGNATURE_BYTES;
/// A check is due once a day, plus a per-installation offset so installations do not all ask at once.
pub const DAY_SECONDS: i64 = 24 * 60 * 60;
pub const MAX_JITTER_SECONDS: i64 = 60 * 60;
/// After a failed check (no network at start-up, a GitHub hiccup) the next try comes after an hour.
pub const RETRY_AFTER_FAILURE_SECONDS: i64 = 60 * 60;

const IDENTITY: &str = include_str!("../../../atlassoc-beta-version.json");

/// The update channel the user chose in Settings. `Build` follows the channel of the installed build
/// (an RC build checks the RC channel), which is the default.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UpdateChannel {
    #[default]
    Build,
    Stable,
    Rc,
    Beta,
}

impl UpdateChannel {
    pub fn is_build(&self) -> bool {
        *self == UpdateChannel::Build
    }

    /// The feed channel to resolve for an installation of `installed`.
    pub fn resolve(self, installed: Channel) -> Channel {
        match self {
            UpdateChannel::Build => installed,
            UpdateChannel::Stable => Channel::Stable,
            UpdateChannel::Rc => Channel::Rc,
            UpdateChannel::Beta => Channel::Beta,
        }
    }
}

/// `0.8.0-rc.1` for an RC build, `0.8.0` for a stable one. `numeric` is the host's `VERSION`.
pub fn installed_version(numeric: &str) -> String {
    match prerelease() {
        Some(pre) => format!("{numeric}-{pre}"),
        None => numeric.to_string(),
    }
}

/// The channel of the installed build, from its pre-release tag.
pub fn installed_channel() -> Channel {
    match prerelease().as_deref() {
        Some(pre) if pre.starts_with("rc") => Channel::Rc,
        Some(_) => Channel::Beta,
        None => Channel::Stable,
    }
}

fn prerelease() -> Option<String> {
    serde_json::from_str::<serde_json::Value>(IDENTITY)
        .ok()?
        .get("prerelease")?
        .as_str()
        .filter(|text| !text.is_empty())
        .map(str::to_string)
}

pub fn channel_name(channel: Channel) -> &'static str {
    match channel {
        Channel::Stable => "Stable",
        Channel::Rc => "Release Candidates",
        Channel::Beta => "Betas",
    }
}

/// True when the daily check is due: never checked, the last check is a day plus `jitter` old (an hour
/// after a failed check), or the stored time is unreadable or in the future (a clock that moved back must
/// not stop checks for good).
pub fn due(state: &CheckState, now_seconds: i64, jitter_seconds: i64) -> bool {
    let Some(last) = state
        .last_check
        .as_deref()
        .and_then(|text| text.parse::<jiff::Timestamp>().ok())
    else {
        return true;
    };
    let age = now_seconds - last.as_second();
    let wait = if state.last_result.as_deref() == Some("failed") {
        RETRY_AFTER_FAILURE_SECONDS
    } else {
        DAY_SECONDS + jitter_seconds.clamp(0, MAX_JITTER_SECONDS)
    };
    age < 0 || age >= wait
}

/// A stable per-installation offset in `0..=MAX_JITTER_SECONDS`, derived from the state directory path so
/// it needs no extra file and no randomness source.
pub fn jitter_for(seed: &str) -> i64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in seed.bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    (hash % (MAX_JITTER_SECONDS as u64 + 1)) as i64
}

/// Where one check reads the feed and which key it trusts. Release builds always use the official feed and
/// the built-in R1 key. Only a build with the `test-feed` Cargo feature (updater tests, WP9) may take a test
/// feed path on the same host and a throwaway test root from the environment; it then keeps its own state
/// file and says "TEST FEED" in the menu, so it never moves the rollback mark of a real installation.
pub struct FeedSource {
    pub feed_path: String,
    pub signature_path: String,
    pub root: Option<TrustRoot>,
    pub test: bool,
}

impl FeedSource {
    fn official() -> Self {
        Self {
            feed_path: FEED_PATH.into(),
            signature_path: SIGNATURE_PATH.into(),
            root: official_trust_root(),
            test: false,
        }
    }
}

pub fn feed_source() -> FeedSource {
    #[cfg(feature = "test-feed")]
    if let Some(source) = test_source(
        std::env::var("ATLAS_TEST_FEED_PATH").ok().as_deref(),
        std::env::var("ATLAS_TEST_ROOT").ok().as_deref(),
    ) {
        return source;
    }
    FeedSource::official()
}

/// `None` (official feed) when no test path is set. A test path outside this repository, or any odd
/// character, also gives `None`. A set path with a missing or malformed root gives a source with no root,
/// so the check reports "not available" instead of trusting anything.
#[cfg_attr(not(feature = "test-feed"), allow(dead_code))]
fn test_source(path: Option<&str>, root: Option<&str>) -> Option<FeedSource> {
    let path = path?;
    let rest = path.strip_prefix("/Ibert-Iam/threat-atlas/")?;
    let plain = rest
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b'/'));
    if !plain || rest.contains("..") || rest.contains("//") || !path.ends_with(".json") {
        return None;
    }
    let root = root.and_then(|hex| {
        let ok = hex.len() == 64 && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
        ok.then(|| {
            let mut key = [0u8; 32];
            for (i, byte) in key.iter_mut().enumerate() {
                *byte = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap_or(0);
            }
            TrustRoot { recovery: key }
        })
    });
    Some(FeedSource {
        feed_path: path.into(),
        signature_path: format!("{path}.sig"),
        root,
        test: true,
    })
}

/// One check. `fetch(path, max_bytes)` downloads from [`FEED_HOST`]; `None` means the download failed.
/// Without the feed or its signature nothing is evaluated and the result is "failed", never "up to date".
pub fn run(
    fetch: &dyn Fn(&str, usize) -> Option<Vec<u8>>,
    now: jiff::Timestamp,
    numeric_version: &str,
    build: u32,
    choice: UpdateChannel,
    state: &mut CheckState,
) -> Outcome {
    let version = installed_version(numeric_version);
    let installed = Installed {
        product: "atlassoc",
        version: &version,
        build: Some(build),
        channel: choice.resolve(installed_channel()),
        platform: "windows-x64",
        kind: Kind::Installer,
    };
    let source = feed_source();
    let root = source.root;
    if root.is_none() {
        return check(&[], &[], None, now, &installed, state);
    }
    let (Some(feed), Some(signature)) = (
        fetch(&source.feed_path, MAX_FEED_BYTES),
        fetch(&source.signature_path, MAX_SIGNATURE_BYTES),
    ) else {
        state.last_check = Some(now.to_string());
        state.last_result = Some("failed".into());
        return download_failed();
    };
    check(&feed, &signature, root.as_ref(), now, &installed, state)
}

/// The menu says "could not download" for this one instead of a feed error.
fn download_failed() -> Outcome {
    Outcome::Failed(CheckError::Feed(FeedError::Invalid(DOWNLOAD_FAILED.into())))
}
const DOWNLOAD_FAILED: &str = "download failed";

/// The release page for an offered version. Only tags the signed feed named reach this point, and the tag
/// characters are checked again so the link stays on the official releases page.
pub fn release_page(tag: &str) -> Option<String> {
    (!tag.is_empty()
        && tag.len() <= 64
        && tag
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_')))
    .then(|| format!("https://github.com/Ibert-Iam/threat-atlas/releases/tag/{tag}"))
}

/// One line per menu entry: the result, then when it last ran and last succeeded.
pub fn status_lines(outcome: Option<&Outcome>, state: &CheckState, checking: bool) -> Vec<String> {
    let mut lines = Vec::new();
    let source = feed_source();
    if source.test {
        lines.push(format!("TEST FEED: {}", source.feed_path));
    }
    lines.push(match (checking, outcome) {
        (true, _) => "Checking for updates...".to_string(),
        (false, None) => "Not checked yet".to_string(),
        (false, Some(outcome)) => describe(outcome),
    });
    lines.push(format!(
        "Last check: {}",
        state
            .last_check
            .as_deref()
            .map_or("never".into(), short_time)
    ));
    if state.last_result.as_deref() == Some("failed") {
        lines.push(format!(
            "Last successful check: {}",
            state
                .last_success
                .as_deref()
                .map_or("never".into(), short_time)
        ));
    }
    lines
}

fn describe(outcome: &Outcome) -> String {
    match outcome {
        Outcome::Unavailable => "Update checks are not available in this build".into(),
        Outcome::UpToDate => "You have the newest version for this channel".into(),
        Outcome::Available(found) => format!(
            "Update available: {}{} ({})",
            found.version,
            found.build.map_or(String::new(), |b| format!(" build {b}")),
            channel_name(found.channel)
        ),
        Outcome::Withdrawn { alternative } => match alternative {
            Some(found) => format!(
                "This version was withdrawn. Safer choice: {} ({})",
                found.version,
                channel_name(found.channel)
            ),
            None => "This version was withdrawn. No safer version is offered yet".into(),
        },
        Outcome::Failed(CheckError::Feed(FeedError::Invalid(why))) if why == DOWNLOAD_FAILED => {
            "Could not download the update list; your version is unchanged".into()
        }
        Outcome::Failed(_) => {
            "The update list did not pass its checks; your version is unchanged".into()
        }
    }
}

/// `2026-11-23T20:15:00Z` → `2026-11-23 20:15 UTC`; anything else is shown as stored.
fn short_time(text: &str) -> String {
    text.parse::<jiff::Timestamp>()
        .map(|t| t.strftime("%Y-%m-%d %H:%M UTC").to_string())
        .unwrap_or_else(|_| text.chars().take(40).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    fn at(text: &str) -> jiff::Timestamp {
        text.parse().unwrap()
    }

    #[test]
    fn version_and_channel_follow_the_build_identity() {
        let version = installed_version("0.8.0");
        let channel = installed_channel();
        match prerelease() {
            Some(pre) => {
                assert_eq!(version, format!("0.8.0-{pre}"));
                assert_ne!(channel, Channel::Stable);
            }
            None => {
                assert_eq!(version, "0.8.0");
                assert_eq!(channel, Channel::Stable);
            }
        }
        assert_eq!(UpdateChannel::Build.resolve(Channel::Rc), Channel::Rc);
        assert_eq!(UpdateChannel::Stable.resolve(Channel::Rc), Channel::Stable);
        assert_eq!(UpdateChannel::Beta.resolve(Channel::Stable), Channel::Beta);
    }

    #[test]
    fn daily_check_is_due_after_a_day_plus_jitter_and_after_a_clock_jump_back() {
        let mut state = CheckState::default();
        let now = at("2026-11-23T12:00:00Z").as_second();
        assert!(due(&state, now, 0), "never checked");
        state.last_check = Some("2026-11-23T12:00:00Z".into());
        assert!(!due(&state, now + 3600, 0));
        assert!(due(&state, now + DAY_SECONDS, 0));
        assert!(!due(&state, now + DAY_SECONDS, 1800), "jitter delays");
        assert!(
            due(&state, now + DAY_SECONDS + MAX_JITTER_SECONDS, 99_999),
            "jitter is capped"
        );
        assert!(due(&state, now - 7200, 0), "clock moved back");
        state.last_result = Some("failed".into());
        assert!(!due(&state, now + 1800, 0), "failed check waits a little");
        assert!(
            due(&state, now + RETRY_AFTER_FAILURE_SECONDS, 3600),
            "then retries within the hour"
        );
        state.last_check = Some("garbage".into());
        assert!(due(&state, now, 0));
    }

    #[test]
    fn jitter_is_stable_and_bounded() {
        let a = jitter_for(r"C:\Users\x\AppData\Local\ThreatAtlasSOC");
        assert_eq!(a, jitter_for(r"C:\Users\x\AppData\Local\ThreatAtlasSOC"));
        assert!((0..=MAX_JITTER_SECONDS).contains(&a));
        assert!((0..=MAX_JITTER_SECONDS).contains(&jitter_for("")));
    }

    #[test]
    fn failed_download_is_reported_as_failed_not_up_to_date() {
        let calls = RefCell::new(Vec::new());
        let fetch = |path: &str, max: usize| {
            calls.borrow_mut().push((path.to_string(), max));
            None
        };
        let mut state = CheckState::default();
        let outcome = run(
            &fetch,
            at("2026-11-23T12:00:00Z"),
            "0.8.0",
            15,
            UpdateChannel::Build,
            &mut state,
        );
        if official_trust_root().is_some() {
            assert!(matches!(outcome, Outcome::Failed(_)));
            assert_eq!(state.last_result.as_deref(), Some("failed"));
            assert_eq!(state.last_check.as_deref(), Some("2026-11-23T12:00:00Z"));
            assert!(state.newest_feed.is_none(), "rollback mark untouched");
            assert_eq!(calls.borrow()[0], (FEED_PATH.to_string(), MAX_FEED_BYTES));
            let lines = status_lines(Some(&outcome), &state, false);
            assert!(lines[0].starts_with("Could not download"));
            assert_eq!(lines[1], "Last check: 2026-11-23 12:00 UTC");
            assert_eq!(lines[2], "Last successful check: never");
        } else {
            assert_eq!(outcome, Outcome::Unavailable);
            assert!(
                calls.borrow().is_empty(),
                "nothing downloaded without a trust root"
            );
        }
    }

    #[test]
    fn tampered_feed_is_refused_and_keeps_the_rollback_mark() {
        let fetch = |path: &str, _max: usize| {
            Some(if path == FEED_PATH {
                br#"{"schema":1,"generated_at":"2026-11-23T10:00:00Z","products":{}}"#.to_vec()
            } else {
                format!("ed25519 0123456789abcdef {}\n", "00".repeat(64)).into_bytes()
            })
        };
        let mut state = CheckState {
            newest_feed: Some("2026-11-22T10:00:00Z".into()),
            ..CheckState::default()
        };
        let outcome = run(
            &fetch,
            at("2026-11-23T12:00:00Z"),
            "0.8.0",
            15,
            UpdateChannel::Stable,
            &mut state,
        );
        if official_trust_root().is_some() {
            assert!(matches!(outcome, Outcome::Failed(CheckError::Signature(_))));
            assert_eq!(state.newest_feed.as_deref(), Some("2026-11-22T10:00:00Z"));
            assert!(status_lines(Some(&outcome), &state, false)[0]
                .starts_with("The update list did not pass"));
        }
    }

    #[test]
    fn release_page_only_for_plain_tags() {
        assert_eq!(
            release_page("atlassoc-v0.8.0-rc.2").as_deref(),
            Some("https://github.com/Ibert-Iam/threat-atlas/releases/tag/atlassoc-v0.8.0-rc.2")
        );
        for bad in ["", "../x", "a/b", "a?b", "a b", "a%2f", &"x".repeat(65)] {
            assert_eq!(release_page(bad), None, "{bad}");
        }
    }

    #[test]
    fn every_outcome_has_a_truthful_line() {
        let state = CheckState::default();
        assert_eq!(
            status_lines(None, &state, true)[0],
            "Checking for updates..."
        );
        assert_eq!(status_lines(None, &state, false)[0], "Not checked yet");
        assert!(
            status_lines(Some(&Outcome::Unavailable), &state, false)[0].contains("not available")
        );
        assert!(status_lines(Some(&Outcome::UpToDate), &state, false)[0].contains("newest"));
        assert!(status_lines(
            Some(&Outcome::Withdrawn { alternative: None }),
            &state,
            false
        )[0]
        .contains("withdrawn"));
        assert_eq!(status_lines(None, &state, false)[1], "Last check: never");
    }

    #[test]
    fn test_feed_source_is_confined() {
        let root = "ab".repeat(32);
        let ok = test_source(
            Some("/Ibert-Iam/threat-atlas/wp9/newer-rc/feed.json"),
            Some(&root),
        )
        .unwrap();
        assert!(ok.test && ok.root.is_some());
        assert_eq!(
            ok.signature_path,
            "/Ibert-Iam/threat-atlas/wp9/newer-rc/feed.json.sig"
        );
        assert!(
            test_source(None, Some(&root)).is_none(),
            "no path: official feed"
        );
        for bad in [
            "/other/repo/feed.json",
            "/Ibert-Iam/threat-atlas/../x/feed.json",
            "/Ibert-Iam/threat-atlas/a b/feed.json",
            "/Ibert-Iam/threat-atlas/a//feed.json",
            "/Ibert-Iam/threat-atlas/feed.txt",
            "/Ibert-Iam/threat-atlas/a?b=feed.json",
        ] {
            assert!(test_source(Some(bad), Some(&root)).is_none(), "{bad}");
        }
        let no_root = test_source(Some("/Ibert-Iam/threat-atlas/x/feed.json"), Some("AB")).unwrap();
        assert!(no_root.root.is_none(), "a malformed root trusts nothing");
        assert!(
            !feed_source().test,
            "default builds always use the official feed"
        );
    }
}
