//! #92 (WP5) on Windows: the update line and Update button of the screensaver's settings dialog. One check of
//! the signed feed runs when the settings dialog opens (never while the screensaver is showing). Only after the
//! user clicks Update is the offered installer downloaded, checked against the feed's size and SHA-256, saved
//! in a fresh private folder, checked again and opened with the normal shell verb, so Windows Installer shows
//! its own window and asks for approval. No silent switches and no automatic installation (decision Q9).
use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
};
use threat_atlas_core::{
    osint_net, saver_update,
    update_check::{CheckState, Outcome, MAX_STATE_BYTES},
    update_feed::{Kind, Selected},
    update_package,
    update_test_feed::feed_source,
};

const STATE_FILE: &str = "update-check.json";
const PLATFORM: &str = "windows-x64";

/// The saver's own folder (`%LOCALAPPDATA%\ThreatAtlasSaver`), shared with its OSINT cache.
fn folder() -> Option<PathBuf> {
    crate::saver_host::paths().map(|(_, saver)| saver)
}

fn get(host: &str, path: &str, max: usize) -> Option<(u16, Vec<u8>)> {
    osint_net::https_get(host, path, "", max).map(|reply| (reply.status, reply.body))
}

fn read_at_most(path: &Path, max: u64) -> Option<Vec<u8>> {
    let mut bytes = Vec::new();
    fs::File::open(path)
        .ok()?
        .take(max)
        .read_to_end(&mut bytes)
        .ok()?;
    Some(bytes)
}

/// Runs one check and saves the small state file (rollback mark, last check). `None` when the local folder
/// is unknown; the dialog then shows no update line.
pub fn check() -> Option<Outcome> {
    let dir = folder()?;
    let source = feed_source();
    // A test-feed build keeps its own state, so test feeds never move a real installation's rollback mark.
    let path = dir.join(if source.test {
        "update-check-test.json"
    } else {
        STATE_FILE
    });
    let mut state = read_at_most(&path, MAX_STATE_BYTES as u64 + 1)
        .map(|bytes| CheckState::from_json(&bytes))
        .unwrap_or_default();
    let outcome = saver_update::run(
        &get,
        &source,
        jiff::Timestamp::now(),
        PLATFORM,
        Kind::Installer,
        &mut state,
    );
    // A failed save only costs the rollback mark until the next accepted feed sets it again.
    let _ = fs::create_dir_all(&dir);
    let temporary = path.with_extension(format!("{}.tmp", std::process::id()));
    if fs::write(&temporary, state.to_json()).is_ok() && fs::rename(&temporary, &path).is_err() {
        let _ = fs::remove_file(&temporary);
    }
    Some(outcome)
}

/// After the user clicked Update: download, verify, save privately, verify the saved file again and open it.
pub fn download_and_open(offer: &Selected) -> Result<(), String> {
    let updates = folder()
        .ok_or("Cannot find the local settings folder")?
        .join("updates");
    let bytes = saver_update::download(&get, offer)?;
    // Installers from an earlier attempt are no longer needed (a file still in use stays; that is fine).
    let _ = fs::remove_dir_all(&updates);
    let dir = updates.join(format!("{:016x}", random_u64()));
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let file = dir.join(&offer.asset.name);
    let written = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&file)
        .and_then(|mut f| f.write_all(&bytes).and_then(|()| f.sync_all()));
    if let Err(error) = written {
        let _ = fs::remove_dir_all(&dir);
        return Err(error.to_string());
    }
    // Checked again right before opening, so a file changed on disk in between is refused.
    let saved = read_at_most(&file, offer.asset.size + 1).unwrap_or_default();
    if let Err(error) = update_package::verify(offer, &saved) {
        let _ = fs::remove_dir_all(&dir);
        return Err(error.text());
    }
    open(&file)
}

fn open(file: &Path) -> Result<(), String> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::UI::{Shell::ShellExecuteW, WindowsAndMessaging::SW_SHOWNORMAL};
    let wide = |text: &std::ffi::OsStr| text.encode_wide().chain([0]).collect::<Vec<u16>>();
    let verb = wide(std::ffi::OsStr::new("open"));
    let target = wide(file.as_os_str());
    let folder = file.parent().map(|p| wide(p.as_os_str()));
    // SAFETY: all strings are NUL-terminated and outlive the call. No parameters: the installer's own UI runs.
    let result = unsafe {
        ShellExecuteW(
            std::ptr::null_mut(),
            verb.as_ptr(),
            target.as_ptr(),
            std::ptr::null(),
            folder.as_ref().map_or(std::ptr::null(), |f| f.as_ptr()),
            SW_SHOWNORMAL,
        )
    };
    if result as isize > 32 {
        Ok(())
    } else {
        Err(format!(
            "Windows could not start the installer (code {})",
            result as isize
        ))
    }
}

/// 64 bits from the standard library's per-process random hash keys (seeded by the OS) mixed with the
/// clock: only to make the download folder name unguessable, not for cryptography.
fn random_u64() -> u64 {
    use std::hash::{BuildHasher, Hasher};
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    h.write_u128(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos()),
    );
    h.finish()
}
