//! C ABI for Settings → Updates in the macOS app (WP4). One pure call: the host passes the two downloaded
//! files, what it is and its saved state, and gets the outcome and the new state back as JSON. The core
//! does the whole check through [`crate::update_check::check`]; the host only downloads (HTTPS, no
//! redirects), saves the state and shows the result. No network, files or installation here.
use crate::feed_signature::official_trust_root;
use crate::update_check::{check, CheckError, CheckState, Installed, Outcome};
use crate::update_feed::{Channel, FeedError, Kind};
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
    let root = official_trust_root();
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
