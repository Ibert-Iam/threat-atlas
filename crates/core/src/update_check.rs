//! WP2: one update check for Settings → Updates (docs/UPDATE-CHANNELS.md). Pure decision logic shared by
//! AtlasSOC and the screensaver on every platform: the host downloads `feed.json` and `feed.json.sig`, passes
//! the bytes, the current time and the stored [`CheckState`], shows the [`Outcome`] and saves the state.
//! No network, no file access, no installation here.
//!
//! Order of checks, each failing closed and keeping the installed version:
//! 1. No built-in trust root (before R1) → [`Outcome::Unavailable`]; nothing is parsed.
//! 2. Detached Ed25519 signature ([`crate::feed_signature`]).
//! 3. Feed syntax and security checks ([`crate::update_feed::parse_feed`]).
//! 4. Freshness: `generated_at` must parse, must not lie more than [`MAX_CLOCK_SKEW_SECONDS`] in the future,
//!    and must not be older than the newest feed this installation already accepted (rollback guard).
//! 5. Withdrawn installed version → banner with a safe alternative; otherwise newer version or up to date.
use crate::feed_signature::{verify_feed, SignatureError, TrustRoot};
use crate::update_feed::{
    installed_is_withdrawn, parse_feed, safe_alternative, update_for, Channel, FeedError, Kind,
    Selected, SemVer,
};
use jiff::{tz::TimeZone, Timestamp};
use serde::{Deserialize, Serialize};

/// A feed stamped further ahead than this is refused, so a mis-stamped feed cannot lock out later ones.
pub const MAX_CLOCK_SKEW_SECONDS: i64 = 24 * 60 * 60;
/// The state file is tiny; anything larger is ignored.
pub const MAX_STATE_BYTES: usize = 4096;

/// What the installed app is and wants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Installed<'a> {
    /// Feed product name: `atlassoc` or `screensaver`.
    pub product: &'a str,
    /// Exact installed version text, e.g. `0.8.0-rc.1`.
    pub version: &'a str,
    pub build: Option<u32>,
    pub channel: Channel,
    /// Feed platform, e.g. `windows-x64` or `macos-universal`.
    pub platform: &'a str,
    pub kind: Kind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckError {
    Signature(SignatureError),
    Feed(FeedError),
    /// The installed version text does not parse; the host has a bug, so never offer anything.
    InstalledVersion,
    /// `generated_at` missing or not an RFC 3339 timestamp.
    Timestamp,
    /// The feed claims to be from the future (beyond the allowed clock skew).
    FromTheFuture,
    /// Older than a feed already accepted here: possible replay of an old, validly signed feed.
    Rollback,
}

impl From<FeedError> for CheckError {
    fn from(error: FeedError) -> Self {
        CheckError::Feed(error)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// No trusted key is built in yet (before R1): feed updates are switched off, not unverified.
    Unavailable,
    UpToDate,
    /// A newer version (or the same version with a higher build) for this channel and platform.
    Available(Selected),
    /// The installed version was withdrawn. `alternative` may be older and is only ever offered for the user
    /// to choose, never applied silently.
    Withdrawn {
        alternative: Option<Selected>,
    },
    Failed(CheckError),
}

impl Outcome {
    /// Short stable label for the state file and logs.
    pub fn label(&self) -> &'static str {
        match self {
            Outcome::Unavailable => "unavailable",
            Outcome::UpToDate => "up-to-date",
            Outcome::Available(_) => "available",
            Outcome::Withdrawn { .. } => "withdrawn",
            Outcome::Failed(_) => "failed",
        }
    }
}

/// Saved between checks by the host (a few lines of JSON next to the settings). Holds no personal data and
/// is never sent anywhere.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckState {
    /// `generated_at` of the newest feed accepted on this installation (rollback guard).
    #[serde(default)]
    pub newest_feed: Option<String>,
    /// When the last check ran, whatever its result (RFC 3339, UTC).
    #[serde(default)]
    pub last_check: Option<String>,
    /// When a check last succeeded (RFC 3339, UTC).
    #[serde(default)]
    pub last_success: Option<String>,
    /// [`Outcome::label`] of the last check.
    #[serde(default)]
    pub last_result: Option<String>,
}

impl CheckState {
    /// Reads a saved state. A missing, oversized or corrupt file starts empty; the only thing lost is the
    /// rollback mark, which the next accepted feed sets again.
    pub fn from_json(bytes: &[u8]) -> Self {
        if bytes.len() > MAX_STATE_BYTES {
            return Self::default();
        }
        serde_json::from_slice(bytes).unwrap_or_default()
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|_| "{}".into())
    }
}

/// Runs one check at `now` and updates `state` (last check always; rollback mark and last success only when
/// the feed was accepted).
pub fn check(
    feed: &[u8],
    signature: &[u8],
    root: Option<&TrustRoot>,
    now: Timestamp,
    installed: &Installed,
    state: &mut CheckState,
) -> Outcome {
    let outcome = evaluate(feed, signature, root, now, installed, state);
    state.last_check = Some(now.to_string());
    state.last_result = Some(outcome.label().into());
    outcome
}

fn evaluate(
    feed_bytes: &[u8],
    signature: &[u8],
    root: Option<&TrustRoot>,
    now: Timestamp,
    installed: &Installed,
    state: &mut CheckState,
) -> Outcome {
    let Some(root) = root else {
        return Outcome::Unavailable;
    };
    let today = now.to_zoned_datetime(TimeZone::UTC).date();
    if let Err(error) = verify_feed(feed_bytes, signature, root, today) {
        return Outcome::Failed(CheckError::Signature(error));
    }
    let feed = match parse_feed(feed_bytes) {
        Ok(feed) => feed,
        Err(error) => return Outcome::Failed(error.into()),
    };
    let generated = match generated_at(feed_bytes) {
        Some(stamp) => stamp,
        None => return Outcome::Failed(CheckError::Timestamp),
    };
    if generated.as_second() > now.as_second() + MAX_CLOCK_SKEW_SECONDS {
        return Outcome::Failed(CheckError::FromTheFuture);
    }
    let newest = state
        .newest_feed
        .as_deref()
        .and_then(|text| text.parse::<Timestamp>().ok());
    if newest.is_some_and(|newest| generated < newest) {
        return Outcome::Failed(CheckError::Rollback);
    }
    let Some(version) = SemVer::parse(installed.version) else {
        return Outcome::Failed(CheckError::InstalledVersion);
    };
    // Accepted: move the rollback mark forward only.
    state.newest_feed = Some(generated.to_string());
    state.last_success = Some(now.to_string());
    if installed_is_withdrawn(&feed, installed.product, installed.version) {
        let alternative = safe_alternative(
            &feed,
            installed.product,
            installed.channel,
            installed.platform,
            installed.kind,
            installed.version,
        )
        .filter(|selected| selected.version != installed.version);
        return Outcome::Withdrawn { alternative };
    }
    match update_for(
        &feed,
        installed.product,
        installed.channel,
        installed.platform,
        installed.kind,
        version,
        installed.build,
    ) {
        Some(selected) => Outcome::Available(selected),
        None => Outcome::UpToDate,
    }
}

fn generated_at(feed: &[u8]) -> Option<Timestamp> {
    let value: serde_json::Value = serde_json::from_slice(feed).ok()?;
    value.get("generated_at")?.as_str()?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::feed_signature::{delegation_message, key_id, FEED_CONTEXT};
    use ring::rand::SystemRandom;
    use ring::signature::{Ed25519KeyPair, KeyPair};

    const SAMPLE: &str = include_str!("../testdata/update-feed-sample.json");

    struct Keys {
        recovery: Ed25519KeyPair,
        signing: Ed25519KeyPair,
    }

    fn keypair() -> Ed25519KeyPair {
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap()
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn public(k: &Ed25519KeyPair) -> [u8; 32] {
        k.public_key().as_ref().try_into().unwrap()
    }

    impl Keys {
        fn new() -> Self {
            Keys {
                recovery: keypair(),
                signing: keypair(),
            }
        }
        fn root(&self) -> TrustRoot {
            TrustRoot {
                recovery: public(&self.recovery),
            }
        }
        /// The sample feed with `generated_at` replaced and a delegation for the signing key added, plus its
        /// signature by the signing key.
        fn feed(&self, generated_at: &str) -> (Vec<u8>, Vec<u8>) {
            let mut value: serde_json::Value = serde_json::from_str(SAMPLE).unwrap();
            value["generated_at"] = generated_at.into();
            let expires = "2027-02-21";
            let delegation = self
                .recovery
                .sign(&delegation_message(&public(&self.signing), expires));
            value["signing_keys"] = serde_json::json!([{
                "key": hex(&public(&self.signing)),
                "expires": expires,
                "recovery_signature": hex(delegation.as_ref()),
            }]);
            let feed = serde_json::to_vec(&value).unwrap();
            let mut message = FEED_CONTEXT.to_vec();
            message.extend_from_slice(&feed);
            let sig = format!(
                "ed25519 {} {}\n",
                key_id(&public(&self.signing)),
                hex(self.signing.sign(&message).as_ref())
            );
            (feed, sig.into_bytes())
        }
    }

    fn now() -> Timestamp {
        "2026-11-23T12:00:00Z".parse().unwrap()
    }

    fn soc(version: &str, channel: Channel) -> Installed<'_> {
        Installed {
            product: "atlassoc",
            version,
            build: None,
            channel,
            platform: "windows-x64",
            kind: Kind::Installer,
        }
    }

    #[test]
    fn without_a_trust_root_updates_are_unavailable_and_nothing_is_parsed() {
        let mut state = CheckState::default();
        let outcome = check(
            b"not even json",
            b"",
            None,
            now(),
            &soc("0.7.0", Channel::Stable),
            &mut state,
        );
        assert_eq!(outcome, Outcome::Unavailable);
        assert_eq!(state.last_result.as_deref(), Some("unavailable"));
        assert_eq!(state.newest_feed, None);
        assert_eq!(state.last_success, None);
    }

    #[test]
    fn signed_feed_offers_the_channel_update_and_records_success() {
        let keys = Keys::new();
        let (feed, sig) = keys.feed("2026-11-23T06:00:00Z");
        let mut state = CheckState::default();
        // An RC user on rc.1 gets nothing newer on RC (rc.2 is withdrawn), but rc.1 itself is fine.
        let outcome = check(
            &feed,
            &sig,
            Some(&keys.root()),
            now(),
            &soc("0.8.0-rc.1", Channel::Rc),
            &mut state,
        );
        assert_eq!(outcome, Outcome::UpToDate);
        // A Beta user on rc.1 is offered 0.9.0-beta.1.
        let outcome = check(
            &feed,
            &sig,
            Some(&keys.root()),
            now(),
            &soc("0.8.0-rc.1", Channel::Beta),
            &mut state,
        );
        let Outcome::Available(selected) = outcome else {
            panic!("{outcome:?}")
        };
        assert_eq!(selected.version, "0.9.0-beta.1");
        assert_eq!(state.newest_feed.as_deref(), Some("2026-11-23T06:00:00Z"));
        assert_eq!(state.last_success.as_deref(), Some("2026-11-23T12:00:00Z"));
        assert_eq!(state.last_result.as_deref(), Some("available"));
    }

    #[test]
    fn withdrawn_installed_version_gets_the_banner_and_a_choice_not_a_silent_move() {
        let keys = Keys::new();
        let (feed, sig) = keys.feed("2026-11-23T06:00:00Z");
        let mut state = CheckState::default();
        let outcome = check(
            &feed,
            &sig,
            Some(&keys.root()),
            now(),
            &soc("0.8.0-rc.2", Channel::Rc),
            &mut state,
        );
        let Outcome::Withdrawn {
            alternative: Some(alternative),
        } = outcome
        else {
            panic!("{outcome:?}")
        };
        assert_eq!(alternative.version, "0.8.0-rc.1", "older, so only offered");
    }

    #[test]
    fn rollback_to_an_older_signed_feed_is_refused_and_keeps_the_mark() {
        let keys = Keys::new();
        let mut state = CheckState::default();
        let (new_feed, new_sig) = keys.feed("2026-11-23T06:00:00Z");
        let installed = soc("0.7.0", Channel::Stable);
        let root = keys.root();
        assert_eq!(
            check(
                &new_feed,
                &new_sig,
                Some(&root),
                now(),
                &installed,
                &mut state
            ),
            Outcome::UpToDate
        );
        let (old_feed, old_sig) = keys.feed("2026-11-20T06:00:00Z");
        assert_eq!(
            check(
                &old_feed,
                &old_sig,
                Some(&root),
                now(),
                &installed,
                &mut state
            ),
            Outcome::Failed(CheckError::Rollback)
        );
        assert_eq!(state.newest_feed.as_deref(), Some("2026-11-23T06:00:00Z"));
        assert_eq!(state.last_result.as_deref(), Some("failed"));
        assert_eq!(state.last_success.as_deref(), Some("2026-11-23T12:00:00Z"));
        // The same feed again is fine (equal, not older).
        assert_eq!(
            check(
                &new_feed,
                &new_sig,
                Some(&root),
                now(),
                &installed,
                &mut state
            ),
            Outcome::UpToDate
        );
    }

    #[test]
    fn future_stamped_or_unstamped_feeds_are_refused() {
        let keys = Keys::new();
        let root = keys.root();
        let installed = soc("0.7.0", Channel::Stable);
        let mut state = CheckState::default();
        let (feed, sig) = keys.feed("2026-11-25T12:00:01Z");
        assert_eq!(
            check(&feed, &sig, Some(&root), now(), &installed, &mut state),
            Outcome::Failed(CheckError::FromTheFuture)
        );
        assert_eq!(
            state.newest_feed, None,
            "a refused feed never moves the mark"
        );
        let (feed, sig) = keys.feed("yesterday");
        assert_eq!(
            check(&feed, &sig, Some(&root), now(), &installed, &mut state),
            Outcome::Failed(CheckError::Timestamp)
        );
        // Within the allowed skew is accepted.
        let (feed, sig) = keys.feed("2026-11-24T11:00:00Z");
        assert_eq!(
            check(&feed, &sig, Some(&root), now(), &installed, &mut state),
            Outcome::UpToDate
        );
    }

    #[test]
    fn bad_signatures_and_bad_installed_versions_fail_closed() {
        let keys = Keys::new();
        let (feed, sig) = keys.feed("2026-11-23T06:00:00Z");
        let mut state = CheckState::default();
        let installed = soc("0.7.0", Channel::Stable);
        let other = Keys::new();
        assert_eq!(
            check(
                &feed,
                &sig,
                Some(&other.root()),
                now(),
                &installed,
                &mut state
            ),
            Outcome::Failed(CheckError::Signature(SignatureError::BadDelegation))
        );
        assert_eq!(
            check(
                &feed,
                b"",
                Some(&keys.root()),
                now(),
                &installed,
                &mut state
            ),
            Outcome::Failed(CheckError::Signature(SignatureError::Malformed))
        );
        assert_eq!(state.newest_feed, None);
        assert_eq!(
            check(
                &feed,
                &sig,
                Some(&keys.root()),
                now(),
                &soc("seven", Channel::Stable),
                &mut state
            ),
            Outcome::Failed(CheckError::InstalledVersion)
        );
    }

    #[test]
    fn expired_delegation_turns_into_a_signature_failure() {
        let keys = Keys::new();
        let (feed, sig) = keys.feed("2026-11-23T06:00:00Z");
        let mut state = CheckState::default();
        let later: Timestamp = "2027-02-22T00:00:01Z".parse().unwrap();
        assert_eq!(
            check(
                &feed,
                &sig,
                Some(&keys.root()),
                later,
                &soc("0.7.0", Channel::Stable),
                &mut state
            ),
            Outcome::Failed(CheckError::Signature(SignatureError::UnknownKey))
        );
    }

    #[test]
    fn state_round_trips_and_corrupt_state_starts_empty() {
        let state = CheckState {
            newest_feed: Some("2026-11-23T06:00:00Z".into()),
            last_check: Some("2026-11-23T12:00:00Z".into()),
            last_success: None,
            last_result: Some("failed".into()),
        };
        assert_eq!(CheckState::from_json(state.to_json().as_bytes()), state);
        assert_eq!(CheckState::from_json(b"{not json"), CheckState::default());
        assert_eq!(CheckState::from_json(b"{}"), CheckState::default());
        let huge = vec![b' '; MAX_STATE_BYTES + 1];
        assert_eq!(CheckState::from_json(&huge), CheckState::default());
        // A garbage rollback mark is ignored rather than blocking every future check.
        let mut odd = CheckState {
            newest_feed: Some("garbage".into()),
            ..CheckState::default()
        };
        let keys = Keys::new();
        let (feed, sig) = keys.feed("2026-11-23T06:00:00Z");
        assert_eq!(
            check(
                &feed,
                &sig,
                Some(&keys.root()),
                now(),
                &soc("0.7.0", Channel::Stable),
                &mut odd
            ),
            Outcome::UpToDate
        );
        assert_eq!(odd.newest_feed.as_deref(), Some("2026-11-23T06:00:00Z"));
    }
}
