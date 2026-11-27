//! WP5 (#92): the screensaver's update banner and Update button, the platform-neutral part. The saver's
//! settings dialog runs one check through [`crate::update_check::check`] (signed feed only, no fallback),
//! shows one line for the result and, only after the user clicks Update, downloads the offered package and
//! checks it against the signed feed ([`crate::update_package`]). The host then opens the normal installer,
//! where the operating system asks for approval. Nothing here installs anything, and nothing runs while the
//! screensaver itself is showing (decision Q10).
use crate::feed_signature::TrustRoot;
use crate::update_check::{check, CheckError, CheckState, Installed, Outcome};
use crate::update_feed::{Channel, FeedError, Kind, Selected};
use crate::update_package;
use crate::update_test_feed::{FeedSource, FEED_HOST};

/// The feed parser refuses anything larger; the signature is one short line.
pub const MAX_FEED_BYTES: usize = crate::update_feed::MAX_FEED_BYTES;
pub const MAX_SIGNATURE_BYTES: usize = crate::feed_signature::MAX_SIGNATURE_BYTES;
/// Feed product name of the screensaver.
pub const PRODUCT: &str = "screensaver";

const IDENTITY: &str = include_str!("../../../version.json");
const DOWNLOAD_FAILED: &str = "download failed";

/// `host, path, max_bytes` → `(status, body)`, or `None` when the transfer failed. HTTPS only.
pub type Get<'a> = &'a dyn Fn(&str, &str, usize) -> Option<(u16, Vec<u8>)>;

/// The installed screensaver from `version.json`: `(version text, build, channel)`, e.g. `("0.8.0", 17, Stable)`
/// or `("0.8.0-rc.1", 17, Rc)`.
pub fn installed() -> (String, Option<u32>, Channel) {
    identity(IDENTITY)
}

fn identity(text: &str) -> (String, Option<u32>, Channel) {
    let value: serde_json::Value = serde_json::from_str(text).unwrap_or_default();
    let numeric = value
        .get("version")
        .and_then(|v| v.as_str())
        .unwrap_or("0.0.0");
    let build = value
        .get("build")
        .and_then(|b| b.as_u64())
        .and_then(|b| u32::try_from(b).ok());
    let pre = value
        .get("prerelease")
        .and_then(|p| p.as_str())
        .filter(|p| !p.is_empty());
    let version = match pre {
        Some(pre) => format!("{numeric}-{pre}"),
        None => numeric.to_string(),
    };
    let channel = match pre {
        Some(pre) if pre.starts_with("rc") => Channel::Rc,
        Some(_) => Channel::Beta,
        None => Channel::Stable,
    };
    (version, build, channel)
}

/// One check of the signed feed for this screensaver build. Without a trust root nothing is downloaded and the
/// result is "unavailable"; without the feed or its signature the result is "failed", never "up to date".
pub fn run(
    get: Get,
    source: &FeedSource,
    now: jiff::Timestamp,
    platform: &str,
    kind: Kind,
    state: &mut CheckState,
) -> Outcome {
    let (version, build, channel) = installed();
    run_as(
        get, source, now, &version, build, channel, platform, kind, state,
    )
}

#[allow(clippy::too_many_arguments)]
fn run_as(
    get: Get,
    source: &FeedSource,
    now: jiff::Timestamp,
    version: &str,
    build: Option<u32>,
    channel: Channel,
    platform: &str,
    kind: Kind,
    state: &mut CheckState,
) -> Outcome {
    let installed = Installed {
        product: PRODUCT,
        version,
        build,
        channel,
        platform,
        kind,
    };
    let root: Option<&TrustRoot> = source.root.as_ref();
    if root.is_none() {
        return check(&[], &[], None, now, &installed, state);
    }
    let fetch = |path: &str, max: usize| {
        get(FEED_HOST, path, max)
            .filter(|(status, _)| *status == 200)
            .map(|(_, body)| body)
    };
    // The signature is fetched only after the feed arrived, so an offline dialog waits for one attempt.
    let feed = fetch(&source.feed_path, MAX_FEED_BYTES);
    let signature = match feed {
        Some(_) => fetch(&source.signature_path, MAX_SIGNATURE_BYTES),
        None => None,
    };
    let (Some(feed), Some(signature)) = (feed, signature) else {
        state.last_check = Some(now.to_string());
        state.last_result = Some("failed".into());
        return Outcome::Failed(CheckError::Feed(FeedError::Invalid(DOWNLOAD_FAILED.into())));
    };
    check(&feed, &signature, root, now, &installed, state)
}

/// The version the Update button installs: a newer version in the build's channel, or the safer
/// alternative to a withdrawn installed version. `None` means no button.
pub fn offer(outcome: &Outcome) -> Option<&Selected> {
    match outcome {
        Outcome::Available(found) => Some(found),
        Outcome::Withdrawn { alternative } => alternative.as_ref(),
        _ => None,
    }
}

/// One line for the settings dialog (the banner).
pub fn describe(outcome: &Outcome) -> String {
    match outcome {
        Outcome::Unavailable => "Update checks are not available in this build.".into(),
        Outcome::UpToDate => "You have the newest screensaver version.".into(),
        Outcome::Available(found) => format!("Update available: {}.", label(found)),
        Outcome::Withdrawn {
            alternative: Some(found),
        } => format!(
            "This version was withdrawn. Safer version: {}.",
            label(found)
        ),
        Outcome::Withdrawn { alternative: None } => {
            "This version was withdrawn. No safer version is offered yet.".into()
        }
        Outcome::Failed(CheckError::Feed(FeedError::Invalid(why))) if why == DOWNLOAD_FAILED => {
            "Could not download the update list; your version is unchanged.".into()
        }
        Outcome::Failed(_) => {
            "The update list did not pass its checks; your version is unchanged.".into()
        }
    }
}

fn label(found: &Selected) -> String {
    let channel = match found.channel {
        Channel::Stable => "stable",
        Channel::Rc => "release candidate",
        Channel::Beta => "beta",
    };
    format!(
        "{}{} ({channel})",
        found.version,
        found.build.map_or(String::new(), |b| format!(" build {b}"))
    )
}

/// After the user clicked Update: downloads the offered package from the release address the signed feed
/// names and returns its bytes only when the size and SHA-256 match the feed. The host writes them to a
/// private, fresh folder, checks the file once more with [`update_package::verify`] and opens the installer.
pub fn download(get: Get, offer: &Selected) -> Result<Vec<u8>, String> {
    let (host, path) = update_package::download_target(offer).map_err(|e| e.text())?;
    let max = usize::try_from(offer.asset.size).map_err(|_| "the file is too large".to_string())?;
    let (status, body) = get(host, &path, max).ok_or("the download failed or was interrupted")?;
    if status != 200 {
        return Err(format!("the server answered {status}"));
    }
    update_package::verify(offer, &body).map_err(|e| e.text())?;
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::feed_signature::{delegation_message, key_id, FEED_CONTEXT};
    use crate::update_test_feed::FEED_PATH;
    use ring::rand::SystemRandom;
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use sha2::{Digest, Sha256};
    use std::cell::RefCell;

    const SAMPLE: &str = include_str!("../testdata/update-feed-sample.json");

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

    /// A test source with a throwaway root, and the sample feed signed for it. `package` replaces the
    /// screensaver RC's Windows installer hash and size, so a download can be checked against it.
    fn signed(package: &[u8]) -> (FeedSource, Vec<u8>, Vec<u8>) {
        let (recovery, signing) = (keypair(), keypair());
        let mut value: serde_json::Value = serde_json::from_str(SAMPLE).unwrap();
        value["generated_at"] = "2026-11-23T06:00:00Z".into();
        let asset = &mut value["products"]["screensaver"]["releases"][0]["assets"][0];
        asset["sha256"] = hex(&Sha256::digest(package)).into();
        asset["size"] = package.len().into();
        let expires = "2027-02-21";
        let delegation = recovery.sign(&delegation_message(&public(&signing), expires));
        value["signing_keys"] = serde_json::json!([{
            "key": hex(&public(&signing)),
            "expires": expires,
            "recovery_signature": hex(delegation.as_ref()),
        }]);
        let feed = serde_json::to_vec(&value).unwrap();
        let mut message = FEED_CONTEXT.to_vec();
        message.extend_from_slice(&feed);
        let sig = format!(
            "ed25519 {} {}\n",
            key_id(&public(&signing)),
            hex(signing.sign(&message).as_ref())
        );
        let source = FeedSource {
            feed_path: FEED_PATH.into(),
            signature_path: format!("{FEED_PATH}.sig"),
            root: Some(TrustRoot {
                recovery: public(&recovery),
            }),
            test: true,
        };
        (source, feed, sig.into_bytes())
    }

    fn now() -> jiff::Timestamp {
        "2026-11-23T12:00:00Z".parse().unwrap()
    }

    fn check_as(
        get: Get,
        source: &FeedSource,
        version: &str,
        channel: Channel,
        state: &mut CheckState,
    ) -> Outcome {
        run_as(
            get,
            source,
            now(),
            version,
            None,
            channel,
            "windows-x64",
            Kind::Installer,
            state,
        )
    }

    #[test]
    fn identity_follows_version_json() {
        assert_eq!(
            identity(r#"{"version":"0.8.0","build":17,"prerelease":null}"#),
            ("0.8.0".into(), Some(17), Channel::Stable)
        );
        assert_eq!(
            identity(r#"{"version":"0.8.0","build":17,"prerelease":"rc.1"}"#),
            ("0.8.0-rc.1".into(), Some(17), Channel::Rc)
        );
        assert_eq!(
            identity(r#"{"version":"0.9.0","prerelease":"beta.2"}"#).2,
            Channel::Beta
        );
        let (version, _, _) = installed();
        assert!(crate::update_feed::SemVer::parse(&version).is_some());
    }

    #[test]
    fn no_trust_root_means_unavailable_and_no_download() {
        let calls = RefCell::new(0);
        let get = |_: &str, _: &str, _: usize| {
            *calls.borrow_mut() += 1;
            None
        };
        let source = FeedSource {
            root: None,
            ..FeedSource::official()
        };
        let mut state = CheckState::default();
        let outcome = check_as(&get, &source, "0.4.8", Channel::Stable, &mut state);
        assert_eq!(outcome, Outcome::Unavailable);
        assert_eq!(*calls.borrow(), 0);
        assert!(offer(&outcome).is_none());
    }

    #[test]
    fn failed_download_is_failed_not_up_to_date() {
        let (source, _, _) = signed(b"x");
        let get = |_: &str, _: &str, _: usize| Some((404, Vec::new()));
        let mut state = CheckState::default();
        let outcome = check_as(&get, &source, "0.4.8", Channel::Stable, &mut state);
        assert!(matches!(outcome, Outcome::Failed(_)));
        assert!(describe(&outcome).starts_with("Could not download"));
        assert_eq!(state.last_result.as_deref(), Some("failed"));
        assert!(state.newest_feed.is_none());
        assert!(offer(&outcome).is_none());
    }

    #[test]
    fn signed_feed_offers_the_rc_and_the_download_is_verified() {
        let package = b"pretend msi bytes".to_vec();
        let (source, feed, sig) = signed(&package);
        let requests = RefCell::new(Vec::new());
        let served = package.clone();
        let get = |host: &str, path: &str, _: usize| {
            requests.borrow_mut().push(format!("{host}{path}"));
            Some(match path {
                FEED_PATH => (200, feed.clone()),
                p if p == source.signature_path => (200, sig.clone()),
                _ => (200, served.clone()),
            })
        };
        let mut state = CheckState::default();
        // A stable user is up to date on 0.4.8; an RC user is offered 0.4.9-rc.1.
        let stable = check_as(&get, &source, "0.4.8", Channel::Stable, &mut state);
        assert_eq!(stable, Outcome::UpToDate);
        assert!(offer(&stable).is_none());
        let rc = check_as(&get, &source, "0.4.8", Channel::Rc, &mut state);
        let found = offer(&rc).expect("an RC is offered").clone();
        assert_eq!(found.version, "0.4.9-rc.1");
        assert_eq!(
            describe(&rc),
            "Update available: 0.4.9-rc.1 (release candidate)."
        );
        // Nothing is downloaded until the host calls `download` (the user's click).
        assert!(requests
            .borrow()
            .iter()
            .all(|r| r.starts_with("raw.githubusercontent.com/")));
        assert_eq!(download(&get, &found).unwrap(), package);
        assert_eq!(
            requests.borrow().last().unwrap(),
            "github.com/Ibert-Iam/threat-atlas/releases/download/v0.4.9-rc.1/ThreatAtlas-0.4.9-x64.msi"
        );
    }

    #[test]
    fn a_wrong_or_short_package_is_refused() {
        let (source, feed, sig) = signed(b"the real package");
        let body = RefCell::new(b"a tampered package".to_vec());
        let get = |_: &str, path: &str, _: usize| {
            Some(match path {
                FEED_PATH => (200, feed.clone()),
                p if p.ends_with(".sig") => (200, sig.clone()),
                _ => (200, body.borrow().clone()),
            })
        };
        let mut state = CheckState::default();
        let outcome = check_as(&get, &source, "0.4.8", Channel::Rc, &mut state);
        let found = offer(&outcome).unwrap().clone();
        assert!(download(&get, &found).unwrap_err().contains("wrong size"));
        *body.borrow_mut() = b"the fake package".to_vec(); // same length, other bytes
        assert!(download(&get, &found).unwrap_err().contains("SHA-256"));
        let refused = |_: &str, _: &str, _: usize| Some((403, Vec::new()));
        assert_eq!(
            download(&refused, &found).unwrap_err(),
            "the server answered 403"
        );
    }

    #[test]
    fn every_outcome_has_a_line() {
        for outcome in [
            Outcome::Unavailable,
            Outcome::UpToDate,
            Outcome::Withdrawn { alternative: None },
            Outcome::Failed(CheckError::Rollback),
        ] {
            assert!(describe(&outcome).ends_with('.'));
            assert!(offer(&outcome).is_none());
        }
    }
}
