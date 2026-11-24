//! Settings → Updates on Windows (WP3, plus download and verify). A background thread checks the signed update feed once a day
//! at a per-installation time (and on "Check now"), through `update_check::check` only: no unsigned
//! fallback. The small state file sits next to the settings. Nothing is installed by the app: after one
//! click the offered installer is downloaded from the release URL the signed feed names and checked against
//! the feed's size and SHA-256 (`update_package`); after a second click it is checked again and the normal,
//! interactive installer window opens.
use crate::soc_config::{self, BUILD, VERSION};
use crate::soc_radar::{https_get, https_get_public};
use crate::soc_updates::{self, UpdateChannel};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    sync::{
        mpsc::{self, Receiver, RecvTimeoutError, Sender},
        Arc, Mutex,
    },
    thread,
    time::Duration,
};
use threat_atlas_core::{
    update_check::{CheckState, Outcome},
    update_feed::Selected,
    update_package,
};

const STATE_FILE: &str = "update-check.json";
/// How often the thread looks whether the daily check is due.
const WAKE: Duration = Duration::from_secs(10 * 60);

/// What the menu shows: status lines and, when there is one, the version on offer.
#[derive(Clone)]
pub struct UpdateView {
    pub lines: Vec<String>,
    /// A newer version, or the safer alternative to a withdrawn installed version.
    pub offer: Option<Selected>,
    /// True only for a newer version in the user's channel (not for a withdrawn alternative).
    pub newer: bool,
    pub download: Download,
}

/// The download step. `Ready` holds the offer the file was checked against and the private path.
#[derive(Clone, Default)]
pub enum Download {
    #[default]
    Idle,
    Running(String),
    Ready(Selected, PathBuf),
    Failed(String),
}

struct Shared {
    outcome: Option<Outcome>,
    state: CheckState,
    checking: bool,
    download: Download,
}

enum Request {
    CheckNow,
    Channel(UpdateChannel),
    Download(Selected),
}

/// Created only after licence consent, and never by the offline smoke test.
pub struct Updater {
    shared: Arc<Mutex<Shared>>,
    tx: Sender<Request>,
}

impl Updater {
    pub fn start(state_dir: &Path, channel: UpdateChannel) -> Self {
        let path = state_dir.join(STATE_FILE);
        let state = soc_config::read_bounded(&path)
            .map(|bytes| CheckState::from_json(&bytes))
            .unwrap_or_default();
        let jitter = soc_updates::jitter_for(&state_dir.to_string_lossy());
        let shared = Arc::new(Mutex::new(Shared {
            outcome: None,
            state,
            checking: false,
            download: Download::Idle,
        }));
        let (tx, rx) = mpsc::channel();
        let worker = shared.clone();
        let updates = state_dir.join("updates");
        thread::spawn(move || run(worker, rx, path, updates, channel, jitter));
        Self { shared, tx }
    }

    pub fn check_now(&self) {
        self.mark_checking();
        let _ = self.tx.send(Request::CheckNow);
    }

    /// Shows "Checking..." at once, so the menu never presents an old result as the answer to the request.
    fn mark_checking(&self) {
        if let Ok(mut shared) = self.shared.lock() {
            shared.checking = true;
        }
    }

    /// A new channel checks again at once, so the menu never shows a result for the old channel.
    pub fn set_channel(&self, channel: UpdateChannel) {
        self.mark_checking();
        let _ = self.tx.send(Request::Channel(channel));
    }

    /// Starts the download of `offer` in the background; the menu shows its progress and result.
    pub fn download(&self, offer: Selected) {
        if let Ok(mut shared) = self.shared.lock() {
            if matches!(shared.download, Download::Running(_)) {
                return;
            }
            shared.download = Download::Running(offer.version.clone());
        }
        let _ = self.tx.send(Request::Download(offer));
    }

    pub fn view(&self) -> UpdateView {
        let Ok(shared) = self.shared.lock() else {
            return UpdateView {
                lines: vec!["Update status unavailable".into()],
                offer: None,
                newer: false,
                download: Download::Idle,
            };
        };
        let (offer, newer) = match &shared.outcome {
            Some(Outcome::Available(found)) => (Some(found.clone()), !shared.checking),
            Some(Outcome::Withdrawn { alternative }) => (alternative.clone(), false),
            _ => (None, false),
        };
        let mut lines =
            soc_updates::status_lines(shared.outcome.as_ref(), &shared.state, shared.checking);
        match &shared.download {
            Download::Idle => {}
            Download::Running(version) => lines.push(format!("Downloading {version}...")),
            Download::Ready(ready, _) => lines.push(format!(
                "{} downloaded and checked (SHA-256 matches the signed update list)",
                ready.version
            )),
            Download::Failed(why) => lines.push(format!("Download stopped: {why}")),
        }
        UpdateView {
            lines,
            offer,
            newer,
            download: shared.download.clone(),
        }
    }
}

fn run(
    shared: Arc<Mutex<Shared>>,
    rx: Receiver<Request>,
    path: PathBuf,
    updates: PathBuf,
    mut channel: UpdateChannel,
    jitter: i64,
) {
    let mut forced = false;
    loop {
        let now = jiff::Timestamp::now();
        let state = shared.lock().map(|s| s.state.clone()).unwrap_or_default();
        if forced || soc_updates::due(&state, now.as_second(), jitter) {
            forced = false;
            check_once(&shared, &path, channel, now, state);
        }
        match rx.recv_timeout(WAKE) {
            Ok(Request::CheckNow) => forced = true,
            Ok(Request::Channel(next)) => {
                channel = next;
                forced = true;
            }
            Ok(Request::Download(offer)) => {
                let result = match fetch_package(&offer, &updates) {
                    Ok(file) => Download::Ready(offer, file),
                    Err(why) => Download::Failed(why),
                };
                if let Ok(mut s) = shared.lock() {
                    s.download = result;
                }
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => return,
        }
    }
}

fn check_once(
    shared: &Arc<Mutex<Shared>>,
    path: &Path,
    channel: UpdateChannel,
    now: jiff::Timestamp,
    mut state: CheckState,
) {
    if let Ok(mut s) = shared.lock() {
        s.checking = true;
    }
    let fetch = |file: &str, max: usize| {
        https_get(soc_updates::FEED_HOST, file, "", max)
            .filter(|reply| reply.status == 200)
            .map(|reply| reply.body)
    };
    let outcome = soc_updates::run(&fetch, now, VERSION, BUILD, channel, &mut state);
    // A failed save only costs the rollback mark until the next accepted feed sets it again.
    let _ = soc_config::write_atomic(path, state.to_json().as_bytes());
    if let Ok(mut s) = shared.lock() {
        s.outcome = Some(outcome);
        s.state = state;
        s.checking = false;
    }
}

/// Downloads the offered installer, checks it against the signed feed and saves it under a fresh,
/// unguessable folder in `updates`. Nothing is written unless every check passed; earlier downloads are
/// removed first, so a failed or interrupted attempt leaves no file behind.
fn fetch_package(offer: &Selected, updates: &Path) -> Result<PathBuf, String> {
    let (host, path) = update_package::download_target(offer).map_err(|e| e.text())?;
    let _ = fs::remove_dir_all(updates);
    let max = usize::try_from(offer.asset.size).map_err(|_| "the file is too large".to_string())?;
    let reply =
        https_get_public(host, &path, "", max).ok_or("the download failed or was interrupted")?;
    if reply.status != 200 {
        return Err(format!("the server answered {}", reply.status));
    }
    update_package::verify(offer, &reply.body).map_err(|e| e.text())?;
    let folder = updates.join(format!("{:016x}", random_u64()));
    fs::create_dir_all(&folder).map_err(|e| e.to_string())?;
    let file = folder.join(&offer.asset.name);
    let written = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&file)
        .and_then(|mut f| f.write_all(&reply.body).and_then(|()| f.sync_all()));
    if let Err(error) = written {
        let _ = fs::remove_dir_all(updates);
        return Err(error.to_string());
    }
    Ok(file)
}

/// Checks the saved installer once more against the offer (a file changed on disk since the download is
/// refused and deleted) and opens it with the normal shell verb, so Windows shows its own prompts and the
/// installer its own window. Never passes silent-install switches.
pub fn install(offer: &Selected, file: &Path) -> Result<(), String> {
    let bytes = read_at_most(file, offer.asset.size + 1)
        .ok_or("the downloaded file is missing; download it again")?;
    if let Err(error) = update_package::verify(offer, &bytes) {
        if let Some(folder) = file.parent() {
            let _ = fs::remove_dir_all(folder);
        }
        return Err(format!("{}; download it again", error.text()));
    }
    open_installer(file)
}

fn read_at_most(file: &Path, max: u64) -> Option<Vec<u8>> {
    use std::io::Read;
    let mut bytes = Vec::new();
    fs::File::open(file)
        .ok()?
        .take(max)
        .read_to_end(&mut bytes)
        .ok()?;
    Some(bytes)
}

fn open_installer(file: &Path) -> Result<(), String> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::UI::{Shell::ShellExecuteW, WindowsAndMessaging::SW_SHOWNORMAL};
    let wide = |text: &std::ffi::OsStr| text.encode_wide().chain([0]).collect::<Vec<u16>>();
    let verb = wide(std::ffi::OsStr::new("open"));
    let target = wide(file.as_os_str());
    let folder = file.parent().map(|p| wide(p.as_os_str()));
    // SAFETY: all strings are NUL-terminated and outlive the call.
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
