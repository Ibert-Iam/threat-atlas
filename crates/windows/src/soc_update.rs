//! Settings → Updates on Windows (WP3). A background thread checks the signed update feed once a day at a
//! per-installation time (and on "Check now"), through `update_check::check` only: no unsigned fallback.
//! The small state file sits next to the settings. The app never installs anything by itself; an offered
//! version opens its release page, and the existing update script runs only after the user confirms.
use crate::soc_config::{self, BUILD, VERSION};
use crate::soc_radar::https_get;
use crate::soc_updates::{self, UpdateChannel};
use std::{
    env, fs,
    path::{Path, PathBuf},
    process::{self, Command},
    sync::{
        mpsc::{self, Receiver, RecvTimeoutError, Sender},
        Arc, Mutex,
    },
    thread,
    time::Duration,
};
use threat_atlas_core::{
    update::is_prerelease,
    update_check::{CheckState, Outcome},
    update_feed::Selected,
};

const IDENTITY: &str = include_str!("../../../atlassoc-beta-version.json");
const SCRIPT: &str = include_str!("../../../scripts/update-atlassoc.ps1");
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
}

struct Shared {
    outcome: Option<Outcome>,
    state: CheckState,
    checking: bool,
}

enum Request {
    CheckNow,
    Channel(UpdateChannel),
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
        }));
        let (tx, rx) = mpsc::channel();
        let worker = shared.clone();
        thread::spawn(move || run(worker, rx, path, channel, jitter));
        Self { shared, tx }
    }

    pub fn check_now(&self) {
        let _ = self.tx.send(Request::CheckNow);
    }

    /// A new channel checks again at once, so the menu never shows a result for the old channel.
    pub fn set_channel(&self, channel: UpdateChannel) {
        let _ = self.tx.send(Request::Channel(channel));
    }

    pub fn view(&self) -> UpdateView {
        let Ok(shared) = self.shared.lock() else {
            return UpdateView {
                lines: vec!["Update status unavailable".into()],
                offer: None,
                newer: false,
            };
        };
        let (offer, newer) = match &shared.outcome {
            Some(Outcome::Available(found)) => (Some(found.clone()), !shared.checking),
            Some(Outcome::Withdrawn { alternative }) => (alternative.clone(), false),
            _ => (None, false),
        };
        UpdateView {
            lines: soc_updates::status_lines(
                shared.outcome.as_ref(),
                &shared.state,
                shared.checking,
            ),
            offer,
            newer,
        }
    }
}

fn run(
    shared: Arc<Mutex<Shared>>,
    rx: Receiver<Request>,
    path: PathBuf,
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

/// Starts the update script in a visible PowerShell window. The script waits for this process to end and
/// verifies the installer's SHA-256 before it starts the normal (interactive) installer.
pub fn launch() -> Result<(), String> {
    let root = env::var_os("SystemRoot").ok_or("SystemRoot is unavailable")?;
    let powershell = PathBuf::from(root).join(r"System32\WindowsPowerShell\v1.0\powershell.exe");
    let script = env::temp_dir().join(format!("update-atlassoc-{}.ps1", process::id()));
    fs::write(&script, SCRIPT).map_err(|error| error.to_string())?;
    Command::new(powershell)
        .args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-File"])
        .arg(&script)
        .args([
            "-Channel",
            if is_prerelease(IDENTITY) {
                "beta"
            } else {
                "stable"
            },
        ])
        .arg("-Silent")
        .args(["-WaitPid", &process::id().to_string()])
        .spawn()
        .map(drop)
        .map_err(|error| error.to_string())
}
