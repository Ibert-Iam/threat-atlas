//! Updater tests (WP9), shared by the Windows and macOS hosts: which feed a check reads and which key it
//! trusts. Release builds always use the official feed and the built-in R1 key. Only a build with the
//! `test-feed` Cargo feature may take a test feed path (on the official feed host, inside this repository)
//! and a throwaway test root from the environment (`ATLAS_TEST_FEED_PATH`, `ATLAS_TEST_ROOT`). Such a build
//! keeps its own state file and shows the test feed, so it never moves a real installation's rollback mark.
use crate::feed_signature::{official_trust_root, TrustRoot};

/// Host of the official feed; a test feed must live on the same host.
pub const FEED_HOST: &str = "raw.githubusercontent.com";
/// Path of the official feed on [`FEED_HOST`]; the signature is the same path plus `.sig`.
pub const FEED_PATH: &str = "/Ibert-Iam/threat-atlas/update-feed/feed.json";
const REPOSITORY_PREFIX: &str = "/Ibert-Iam/threat-atlas/";

/// Where one check reads the feed and which key it trusts.
pub struct FeedSource {
    pub feed_path: String,
    pub signature_path: String,
    pub root: Option<TrustRoot>,
    pub test: bool,
}

impl FeedSource {
    pub fn official() -> Self {
        Self {
            feed_path: FEED_PATH.into(),
            signature_path: format!("{FEED_PATH}.sig"),
            root: official_trust_root(),
            test: false,
        }
    }
}

/// The source this build uses. Without the `test-feed` feature this is always the official feed.
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
pub fn test_source(path: Option<&str>, root: Option<&str>) -> Option<FeedSource> {
    let path = path?;
    let rest = path.strip_prefix(REPOSITORY_PREFIX)?;
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

#[cfg(test)]
mod tests {
    use super::*;

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
    }

    #[test]
    fn default_builds_use_the_official_feed() {
        let source = feed_source();
        if cfg!(feature = "test-feed") && std::env::var_os("ATLAS_TEST_FEED_PATH").is_some() {
            return;
        }
        assert!(!source.test);
        assert_eq!(source.feed_path, FEED_PATH);
        assert_eq!(source.signature_path, format!("{FEED_PATH}.sig"));
        assert!(source.root.is_some(), "release builds trust R1");
    }
}
