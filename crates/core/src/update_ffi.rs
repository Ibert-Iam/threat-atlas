//! C ABI for the shared update check (macOS Swift host). The host downloads `feed.json` and
//! `feed.json.sig`, passes the bytes plus the saved state, and persists the returned state.
//! No network, no files and no key material here.
use crate::{
    feed_signature::official_trust_root,
    update_check::{self, CheckError, CheckState, Installed, Outcome, MAX_STATE_BYTES},
    update_feed::{Channel, Kind, Selected},
};
use jiff::Timestamp;
use std::{ffi::c_char, ptr, slice};

const VERSION_CAP: usize = 64;
const TAG_CAP: usize = 128;
const URL_CAP: usize = 1024;
const SHA_CAP: usize = 65;
const MESSAGE_CAP: usize = 256;

/// Result codes shared with the Swift view.
pub const TA_UPDATE_UNAVAILABLE: i32 = 0;
pub const TA_UPDATE_UP_TO_DATE: i32 = 1;
pub const TA_UPDATE_AVAILABLE: i32 = 2;
pub const TA_UPDATE_WITHDRAWN: i32 = 3;
pub const TA_UPDATE_FAILED: i32 = 4;

#[repr(C)]
pub struct TaUpdateResult {
    pub outcome: i32,
    pub build: u32,
    pub size: u64,
    pub version: [c_char; VERSION_CAP],
    pub tag: [c_char; TAG_CAP],
    pub url: [c_char; URL_CAP],
    pub sha256: [c_char; SHA_CAP],
    pub message: [c_char; MESSAGE_CAP],
}

impl Default for TaUpdateResult {
    fn default() -> Self {
        Self {
            outcome: TA_UPDATE_UNAVAILABLE,
            build: 0,
            size: 0,
            version: [0; VERSION_CAP],
            tag: [0; TAG_CAP],
            url: [0; URL_CAP],
            sha256: [0; SHA_CAP],
            message: [0; MESSAGE_CAP],
        }
    }
}

unsafe fn text<'a>(ptr: *const c_char) -> Option<&'a str> {
    if ptr.is_null() {
        return None;
    }
    std::ffi::CStr::from_ptr(ptr).to_str().ok()
}

fn put(dst: &mut [c_char], text: &str) {
    if dst.is_empty() {
        return;
    }
    let n = text.len().min(dst.len() - 1);
    for (slot, byte) in dst.iter_mut().zip(text.as_bytes().iter().copied()).take(n) {
        *slot = byte as c_char;
    }
    dst[n] = 0;
}

fn fill(result: &mut TaUpdateResult, selected: &Selected) {
    result.build = selected.build.unwrap_or(0);
    result.size = selected.asset.size;
    put(&mut result.version, &selected.version);
    put(&mut result.tag, &selected.tag);
    put(&mut result.url, &selected.asset.url);
    put(&mut result.sha256, &selected.asset.sha256);
}

fn apply(result: &mut TaUpdateResult, outcome: &Outcome) {
    match outcome {
        Outcome::Unavailable => {
            result.outcome = TA_UPDATE_UNAVAILABLE;
            put(&mut result.message, "Updates are not configured");
        }
        Outcome::UpToDate => {
            result.outcome = TA_UPDATE_UP_TO_DATE;
            put(
                &mut result.message,
                "You have the newest version for this channel",
            );
        }
        Outcome::Available(selected) => {
            result.outcome = TA_UPDATE_AVAILABLE;
            fill(result, selected);
            put(&mut result.message, "A newer version is available");
        }
        Outcome::Withdrawn { alternative } => {
            result.outcome = TA_UPDATE_WITHDRAWN;
            match alternative {
                Some(selected) => {
                    fill(result, selected);
                    put(
                        &mut result.message,
                        "This version was withdrawn; a safer version is available",
                    );
                }
                None => put(
                    &mut result.message,
                    "This version was withdrawn; no replacement is available",
                ),
            }
        }
        Outcome::Failed(error) => {
            result.outcome = TA_UPDATE_FAILED;
            let message = match error {
                CheckError::Signature(error) => format!("Signature rejected: {error:?}"),
                CheckError::Feed(error) => format!("Feed rejected: {error:?}"),
                CheckError::InstalledVersion => "Installed version is invalid".into(),
                CheckError::Timestamp => "Feed timestamp is invalid".into(),
                CheckError::FromTheFuture => "Feed timestamp is too far in the future".into(),
                CheckError::Rollback => "Feed is older than the last accepted feed".into(),
            };
            put(&mut result.message, &message);
        }
    }
}

fn channel(value: i32) -> Option<Channel> {
    match value {
        0 => Some(Channel::Stable),
        1 => Some(Channel::Rc),
        2 => Some(Channel::Beta),
        _ => None,
    }
}

fn kind(value: i32) -> Option<Kind> {
    match value {
        0 => Some(Kind::Auto),
        1 => Some(Kind::Installer),
        2 => Some(Kind::Portable),
        _ => None,
    }
}

unsafe fn copy_cstr(text: &str, out: *mut c_char, cap: usize) -> usize {
    if !out.is_null() && cap > 0 {
        let bytes = text.as_bytes();
        let n = bytes.len().min(cap - 1);
        ptr::copy_nonoverlapping(bytes.as_ptr(), out.cast::<u8>(), n);
        *out.add(n) = 0;
    }
    text.len()
}

/// Runs the same decision logic as the apps.
///
/// Returns 0 when the call was made with valid arguments (even if the result is `Failed`), -1 for
/// invalid pointers/strings/enums. `state_out` receives the new JSON state; a short buffer is
/// truncated but the full length is returned.
///
/// # Safety
/// Pointers must be valid for the stated lengths; `out`, `state_out` may be null only when their
/// capacity is zero. Strings must be NUL-terminated UTF-8 or null.
#[no_mangle]
pub unsafe extern "C" fn ta_update_check(
    feed: *const u8,
    feed_len: usize,
    signature: *const u8,
    signature_len: usize,
    installed_version: *const c_char,
    product: *const c_char,
    platform: *const c_char,
    channel_code: i32,
    kind_code: i32,
    now_unix: i64,
    state_in: *const c_char,
    out: *mut TaUpdateResult,
    state_out: *mut c_char,
    state_cap: usize,
) -> i32 {
    if out.is_null() {
        return -1;
    }
    let (Some(version), Some(product), Some(platform)) =
        (text(installed_version), text(product), text(platform))
    else {
        return -1;
    };
    let (Some(channel), Some(kind)) = (channel(channel_code), kind(kind_code)) else {
        return -1;
    };
    if feed_len > crate::update_feed::MAX_FEED_BYTES || signature_len > 256 {
        return -1;
    }
    if feed.is_null() && feed_len != 0 || signature.is_null() && signature_len != 0 {
        return -1;
    }
    let feed = if feed_len == 0 {
        &[]
    } else {
        slice::from_raw_parts(feed, feed_len)
    };
    let signature = if signature_len == 0 {
        &[]
    } else {
        slice::from_raw_parts(signature, signature_len)
    };
    let Some(now) = Timestamp::from_second(now_unix).ok() else {
        return -1;
    };
    let state_text = text(state_in).unwrap_or("");
    let mut state = CheckState::from_json(state_text.as_bytes());
    let installed = Installed {
        product,
        version,
        build: None,
        channel,
        platform,
        kind,
    };
    let result = update_check::check(
        feed,
        signature,
        official_trust_root().as_ref(),
        now,
        &installed,
        &mut state,
    );
    let mut result_out = TaUpdateResult::default();
    apply(&mut result_out, &result);
    *out = result_out;
    if state_cap > 0 {
        if state_cap > MAX_STATE_BYTES {
            return -1;
        }
        copy_cstr(&state.to_json(), state_out, state_cap);
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    fn call(
        feed: &[u8],
        sig: &[u8],
        channel: i32,
        kind: i32,
        state: &str,
        out: &mut TaUpdateResult,
        state_buf: &mut [c_char],
    ) -> i32 {
        let version = CString::new("0.8.0-rc.1").unwrap();
        let product = CString::new("atlassoc").unwrap();
        let platform = CString::new("macos-universal").unwrap();
        let state = CString::new(state).unwrap();
        unsafe {
            ta_update_check(
                feed.as_ptr(),
                feed.len(),
                sig.as_ptr(),
                sig.len(),
                version.as_ptr(),
                product.as_ptr(),
                platform.as_ptr(),
                channel,
                kind,
                1_700_000_000,
                state.as_ptr(),
                out,
                state_buf.as_mut_ptr(),
                state_buf.len(),
            )
        }
    }

    #[test]
    fn rejects_null_and_invalid_enums() {
        let mut out = TaUpdateResult::default();
        assert_eq!(
            unsafe {
                ta_update_check(
                    ptr::null(),
                    0,
                    ptr::null(),
                    0,
                    ptr::null(),
                    ptr::null(),
                    ptr::null(),
                    0,
                    0,
                    0,
                    ptr::null(),
                    &mut out,
                    ptr::null_mut(),
                    0,
                )
            },
            -1
        );
        let mut buf = [0 as c_char; 4096];
        assert_eq!(call(&[], &[], 9, 0, "", &mut out, &mut buf), -1);
        assert_eq!(call(&[], &[], 0, 9, "", &mut out, &mut buf), -1);
    }

    #[test]
    fn bad_feed_fails_closed_and_persists_state() {
        let mut out = TaUpdateResult::default();
        let mut buf = [0 as c_char; 4096];
        assert_eq!(call(b"not json", b"", 0, 1, "", &mut out, &mut buf), 0);
        assert_eq!(out.outcome, TA_UPDATE_FAILED);
        let state = unsafe { std::ffi::CStr::from_ptr(buf.as_ptr()) }
            .to_str()
            .unwrap();
        assert!(state.contains("\"last_result\": \"failed\""), "{state}");
    }
}
