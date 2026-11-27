//! C ABI for Settings → Updates in the macOS app (WP4). One pure call: the host passes the two downloaded
//! files, what it is and its saved state, and gets the outcome and the new state back as JSON. The core
//! does the whole check through [`crate::update_check::check`]; the host only downloads (HTTPS, no
//! redirects), saves the state and shows the result. No network, files or installation here.
use crate::update_check::{check, CheckError, CheckState, Installed, Outcome};
use crate::update_feed::{Asset, Channel, FeedError, Kind, Selected};
use crate::update_package::{self, PackageError};
use crate::update_test_feed::{feed_source, FEED_HOST};
use serde::Deserialize;
use std::ffi::{c_char, CStr};

/// The official release page of a tag the signed feed named; only plain tag characters are accepted.
pub fn release_page(tag: &str) -> Option<String> {
    (!tag.is_empty()
        && tag.len() <= 64
        && tag
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_')))
    .then(|| format!("https://github.com/Ibert-Iam/threat-atlas/releases/tag/{tag}"))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    product: String,
    version: String,
    build: Option<u32>,
    channel: String,
    platform: String,
    kind: String,
    /// Unix seconds. Passed in so a size query and the real call give the same answer.
    now: i64,
    #[serde(default)]
    state: CheckState,
    /// True when the host could not download the feed or its signature.
    #[serde(default)]
    download_failed: bool,
}

/// Runs one check and returns the response JSON:
/// `{"result": "available"|"up-to-date"|"withdrawn"|"unavailable"|"failed", "reason": ..., "offer": {...}|null,
///   "newer": bool, "state": {...}}`. A request that does not parse gives `{"result":"failed","reason":"request"}`
/// and no state, so the host keeps its old one.
pub fn respond(feed: &[u8], signature: &[u8], request: &str) -> String {
    let Ok(req) = serde_json::from_str::<Request>(request) else {
        return r#"{"result":"failed","reason":"request","offer":null,"newer":false,"state":null}"#
            .into();
    };
    let (Some(channel), Some(kind), Ok(now)) = (
        Channel::parse(&req.channel),
        match req.kind.as_str() {
            "auto" => Some(Kind::Auto),
            "installer" => Some(Kind::Installer),
            "portable" => Some(Kind::Portable),
            _ => None,
        },
        jiff::Timestamp::from_second(req.now),
    ) else {
        return r#"{"result":"failed","reason":"request","offer":null,"newer":false,"state":null}"#
            .into();
    };
    let installed = Installed {
        product: &req.product,
        version: &req.version,
        build: req.build,
        channel,
        platform: &req.platform,
        kind,
    };
    let mut state = req.state;
    // The official R1 key, or the throwaway test root in a `test-feed` build given one (WP9).
    let root = feed_source().root;
    let outcome = if root.is_some() && req.download_failed {
        state.last_check = Some(now.to_string());
        state.last_result = Some("failed".into());
        Outcome::Failed(CheckError::Feed(FeedError::Invalid("download".into())))
    } else {
        check(feed, signature, root.as_ref(), now, &installed, &mut state)
    };
    let (offer, newer) = match &outcome {
        Outcome::Available(found) => (Some(found), true),
        Outcome::Withdrawn { alternative } => (alternative.as_ref(), false),
        _ => (None, false),
    };
    let reason = match &outcome {
        Outcome::Failed(CheckError::Feed(FeedError::Invalid(why))) if why == "download" => {
            "download"
        }
        Outcome::Failed(CheckError::Signature(_)) => "signature",
        Outcome::Failed(CheckError::Rollback) => "rollback",
        Outcome::Failed(CheckError::FromTheFuture) => "future",
        Outcome::Failed(_) => "feed",
        _ => "",
    };
    serde_json::json!({
        "result": outcome.label(),
        "reason": reason,
        "offer": offer.map(|o| serde_json::json!({
            "version": o.version,
            "channel": o.channel.as_str(),
            "tag": o.tag,
            "build": o.build,
            "release_page": release_page(&o.tag),
            "asset": {
                "platform": o.asset.platform,
                "kind": o.asset.kind,
                "name": o.asset.name,
                "url": o.asset.url,
                "sha256": o.asset.sha256,
                "size": o.asset.size,
            },
        })),
        "newer": newer,
        "state": state,
    })
    .to_string()
}

unsafe fn bytes<'a>(ptr: *const u8, len: usize) -> &'a [u8] {
    if ptr.is_null() || len == 0 {
        &[]
    } else {
        std::slice::from_raw_parts(ptr, len)
    }
}

/// One update check; writes at most `cap` bytes of the response JSON (no NUL) to `out` and returns the full
/// length. Call with `out` null to learn the size, then again with a buffer: the call is pure, so both
/// answers are identical for the same inputs.
/// # Safety
/// `feed`/`signature` must point to `feed_len`/`signature_len` readable bytes or be null; `request` must be
/// a valid NUL-terminated UTF-8 string or null; `out` must have room for `cap` bytes or be null.
#[no_mangle]
pub unsafe extern "C" fn ta_update_check(
    feed: *const u8,
    feed_len: usize,
    signature: *const u8,
    signature_len: usize,
    request: *const c_char,
    out: *mut u8,
    cap: usize,
) -> usize {
    let request = if request.is_null() {
        ""
    } else {
        CStr::from_ptr(request).to_str().unwrap_or("")
    };
    let response = respond(
        bytes(feed, feed_len),
        bytes(signature, signature_len),
        request,
    );
    if !out.is_null() {
        let n = response.len().min(cap);
        std::ptr::copy_nonoverlapping(response.as_ptr(), out, n);
    }
    response.len()
}

/// The feed this build reads, as JSON: `{"feed": "https://...", "signature": "https://...", "test": bool}`.
/// Always the official feed unless this is a `test-feed` build with a valid `ATLAS_TEST_FEED_PATH`
/// (see [`crate::update_test_feed`]); the host shows "TEST FEED" and keeps a separate state file then.
pub fn source_json() -> String {
    let source = feed_source();
    serde_json::json!({
        "feed": format!("https://{FEED_HOST}{}", source.feed_path),
        "signature": format!("https://{FEED_HOST}{}", source.signature_path),
        "test": source.test,
    })
    .to_string()
}

/// C entry for [`source_json`]: writes at most `cap` bytes (no NUL) to `out` and returns the full length.
/// # Safety
/// `out` must have room for `cap` bytes or be null.
#[no_mangle]
pub unsafe extern "C" fn ta_update_source(out: *mut u8, cap: usize) -> usize {
    let text = source_json();
    if !out.is_null() {
        let n = text.len().min(cap);
        std::ptr::copy_nonoverlapping(text.as_ptr(), out, n);
    }
    text.len()
}

#[derive(Deserialize)]
struct OfferJson {
    version: String,
    channel: String,
    tag: String,
    build: Option<u32>,
    asset: AssetJson,
}

#[derive(Deserialize)]
struct AssetJson {
    platform: String,
    kind: String,
    name: String,
    url: String,
    sha256: String,
    size: u64,
}

/// Checks downloaded bytes against an `offer` object exactly as [`respond`] returned it (release URL,
/// file name, size, SHA-256; see [`update_package::verify`]). 0 = passes; 1 URL, 2 name, 3 announced size,
/// 4 size differs (interrupted or padded), 5 SHA-256 differs, 9 the offer JSON is not one of ours.
pub fn verify_package(offer: &str, bytes: &[u8]) -> i32 {
    let Ok(o) = serde_json::from_str::<OfferJson>(offer) else {
        return 9;
    };
    let Some(channel) = Channel::parse(&o.channel) else {
        return 9;
    };
    let selected = Selected {
        version: o.version,
        channel,
        tag: o.tag,
        build: o.build,
        asset: Asset {
            platform: o.asset.platform,
            kind: o.asset.kind,
            name: o.asset.name,
            url: o.asset.url,
            sha256: o.asset.sha256,
            size: o.asset.size,
        },
    };
    match update_package::verify(&selected, bytes) {
        Ok(()) => 0,
        Err(PackageError::Url) => 1,
        Err(PackageError::Name) => 2,
        Err(PackageError::TooLarge) => 3,
        Err(PackageError::Size { .. }) => 4,
        Err(PackageError::Hash) => 5,
    }
}

/// C entry for [`verify_package`].
/// # Safety
/// `offer` must be a valid NUL-terminated UTF-8 string or null; `bytes` must point to `len` readable bytes
/// or be null.
#[no_mangle]
pub unsafe extern "C" fn ta_update_verify_package(
    offer: *const c_char,
    bytes: *const u8,
    len: usize,
) -> i32 {
    let offer = if offer.is_null() {
        ""
    } else {
        CStr::from_ptr(offer).to_str().unwrap_or("")
    };
    verify_package(offer, self::bytes(bytes, len))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::feed_signature::official_trust_root;

    #[test]
    fn source_is_the_official_feed_by_default() {
        if cfg!(feature = "test-feed") && std::env::var_os("ATLAS_TEST_FEED_PATH").is_some() {
            return;
        }
        let v: serde_json::Value = serde_json::from_str(&source_json()).unwrap();
        assert_eq!(
            v["feed"],
            "https://raw.githubusercontent.com/Ibert-Iam/threat-atlas/update-feed/feed.json"
        );
        assert_eq!(
            v["signature"],
            "https://raw.githubusercontent.com/Ibert-Iam/threat-atlas/update-feed/feed.json.sig"
        );
        assert_eq!(v["test"], false);
        let needed = unsafe { ta_update_source(std::ptr::null_mut(), 0) };
        let mut buffer = vec![0u8; needed];
        assert_eq!(
            unsafe { ta_update_source(buffer.as_mut_ptr(), needed) },
            needed
        );
        assert_eq!(buffer, source_json().into_bytes());
    }

    fn request(extra: &str) -> String {
        format!(
            r#"{{"product":"atlassoc","version":"0.8.0-rc.1","build":15,"channel":"rc","platform":"macos-universal","kind":"portable","now":1795435200{extra}}}"#
        )
    }

    fn parse(json: &str) -> serde_json::Value {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn bad_requests_fail_without_touching_state() {
        for bad in [
            "",
            "{}",
            "not json",
            &request(r#","extra":1"#),
            &request("").replace("\"rc\"", "\"nightly\""),
        ] {
            let v = parse(&respond(b"", b"", bad));
            assert_eq!(v["result"], "failed", "{bad}");
            assert_eq!(v["reason"], "request");
            assert!(v["state"].is_null());
        }
    }

    #[test]
    fn download_failure_is_failed_and_keeps_the_rollback_mark() {
        let v = parse(&respond(
            b"",
            b"",
            &request(r#","download_failed":true,"state":{"newest_feed":"2026-11-22T10:00:00Z"}"#),
        ));
        if official_trust_root().is_some() {
            assert_eq!(v["result"], "failed");
            assert_eq!(v["reason"], "download");
            assert_eq!(v["state"]["newest_feed"], "2026-11-22T10:00:00Z");
            assert_eq!(v["state"]["last_check"], "2026-11-23T12:00:00Z");
            assert_eq!(v["state"]["last_result"], "failed");
        } else {
            assert_eq!(v["result"], "unavailable");
        }
    }

    #[test]
    fn tampered_feed_fails_on_the_signature() {
        let feed = br#"{"schema":1,"generated_at":"2026-11-24T10:00:00Z","products":{}}"#;
        let sig = format!("ed25519 0123456789abcdef {}\n", "00".repeat(64));
        let v = parse(&respond(feed, sig.as_bytes(), &request("")));
        if official_trust_root().is_some() {
            assert_eq!(v["result"], "failed");
            assert_eq!(v["reason"], "signature");
            assert!(v["offer"].is_null());
            assert_eq!(v["newer"], false);
            assert!(v["state"]["newest_feed"].is_null());
        }
    }

    #[test]
    fn size_query_and_fill_agree() {
        let req = std::ffi::CString::new(request(r#","download_failed":true"#)).unwrap();
        unsafe {
            let needed = ta_update_check(
                std::ptr::null(),
                0,
                std::ptr::null(),
                0,
                req.as_ptr(),
                std::ptr::null_mut(),
                0,
            );
            let mut buf = vec![0u8; needed];
            let written = ta_update_check(
                std::ptr::null(),
                0,
                std::ptr::null(),
                0,
                req.as_ptr(),
                buf.as_mut_ptr(),
                needed,
            );
            assert_eq!(written, needed);
            assert_eq!(parse(std::str::from_utf8(&buf).unwrap())["newer"], false);
            let small = ta_update_check(
                std::ptr::null(),
                0,
                std::ptr::null(),
                0,
                req.as_ptr(),
                buf.as_mut_ptr(),
                3,
            );
            assert_eq!(small, needed, "a short buffer still reports the full size");
        }
    }

    #[test]
    fn release_page_only_for_plain_tags() {
        assert_eq!(
            release_page("atlassoc-v0.8.0-rc.2").as_deref(),
            Some("https://github.com/Ibert-Iam/threat-atlas/releases/tag/atlassoc-v0.8.0-rc.2")
        );
        for bad in ["", "../x", "a/b", "a?b", "a b", "a%2f"] {
            assert_eq!(release_page(bad), None, "{bad}");
        }
    }

    #[test]
    fn package_check_matches_the_offer() {
        use sha2::{Digest, Sha256};
        let payload = b"zip bytes";
        let hex: String = Sha256::digest(payload)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let offer = |sha: &str, size: usize, url: &str| {
            serde_json::json!({
                "version": "0.8.0", "channel": "stable", "tag": "atlassoc-v0.8.0", "build": 16,
                "asset": {"platform": "macos-universal", "kind": "portable",
                          "name": "AtlasSOC-macOS-universal-v0.8.0-build16.zip", "url": url,
                          "sha256": sha, "size": size}
            })
            .to_string()
        };
        let url = "https://github.com/Ibert-Iam/threat-atlas/releases/download/atlassoc-v0.8.0/AtlasSOC-macOS-universal-v0.8.0-build16.zip";
        assert_eq!(verify_package(&offer(&hex, payload.len(), url), payload), 0);
        assert_eq!(
            verify_package(
                &offer(&hex, payload.len(), "https://evil.example/x.zip"),
                payload
            ),
            1
        );
        assert_eq!(
            verify_package(&offer(&hex, payload.len() + 1, url), payload),
            4
        );
        assert_eq!(
            verify_package(&offer(&"0".repeat(64), payload.len(), url), payload),
            5
        );
        assert_eq!(verify_package("{}", payload), 9);
        let c = std::ffi::CString::new(offer(&hex, payload.len(), url)).unwrap();
        assert_eq!(
            unsafe { ta_update_verify_package(c.as_ptr(), payload.as_ptr(), payload.len()) },
            0
        );
        assert_eq!(
            unsafe { ta_update_verify_package(std::ptr::null(), std::ptr::null(), 0) },
            9
        );
    }
}
