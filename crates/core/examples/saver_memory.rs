//! Heap budget probe for the screensaver (issue #124): live and peak heap bytes per phase.
//! `saver_memory [WxH]` draws the SOC view with synthetic records, `saver_memory epss` shows what the EPSS list
//! would cost in memory, `saver_memory live [seconds]` runs the live feed and the OSINT worker. Heap only: the
//! Windows window buffer, thread stacks and loaded DLLs come on top of these numbers.
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};
use threat_atlas_core::{feed::State, saver::SaverSession};

struct Counting;
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        let p = System.alloc(l);
        if !p.is_null() {
            let now = LIVE.fetch_add(l.size(), Relaxed) + l.size();
            PEAK.fetch_max(now, Relaxed);
        }
        p
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        System.dealloc(p, l);
        LIVE.fetch_sub(l.size(), Relaxed);
    }
}
#[global_allocator]
static A: Counting = Counting;

fn mb(b: usize) -> String {
    format!("{:.1} MB", b as f64 / 1_048_576.)
}
fn report(phase: &str) {
    println!(
        "{phase:<32} live {:>9}  peak {:>9}",
        mb(LIVE.load(Relaxed)),
        mb(PEAK.load(Relaxed))
    );
}

fn main() {
    if std::env::args().nth(1).as_deref() == Some("epss") {
        return epss();
    }
    if std::env::args().nth(1).as_deref() == Some("live") {
        return live(
            std::env::args()
                .nth(2)
                .and_then(|s| s.parse().ok())
                .unwrap_or(60),
        );
    }
    let (w, h) = std::env::args()
        .nth(1)
        .and_then(|s| {
            s.split_once('x')
                .map(|(a, b)| (a.parse().unwrap(), b.parse().unwrap()))
        })
        .unwrap_or((1920u32, 1080u32));
    report("start");
    let mut session = SaverSession::new();
    report("SaverSession::new");
    let fw = session.fit_window(w, h);
    report(&format!("fit_window {w}x{h} -> {fw}x900"));
    let places = [
        ("US", 39., -98.),
        ("CN", 35., 104.),
        ("BR", -14., -52.),
        ("DE", 51., 10.),
        ("NL", 52., 5.),
        ("RU", 61., 100.),
        ("IN", 21., 79.),
    ];
    let mut state = State::default();
    let start = 1_767_225_600_000u64;
    for frame in 0..400u64 {
        let now = start + frame * 50;
        for i in 0..50usize {
            let (s, d) = (places[(i + frame as usize) % 7], places[(i * 3 + 1) % 7]);
            let intention =
                ["malicious", "suspicious", "benign", "benign"][(i + frame as usize) % 4];
            let row = format!(
                r#"{{"source":{{"latitude":{},"longitude":{},"country":"{}"}},"destination":{{"latitude":{},"longitude":{},"country":"{}"}},"intention":"{intention}","destination_port":{}}}"#,
                s.1,
                s.2,
                s.0,
                d.1,
                d.2,
                d.0,
                [22, 23, 80, 443, 2222][i % 5]
            );
            state.ingest(&row, now);
        }
        let snapshot = state.snapshot(now);
        let counts = state.counts(now);
        let _ = session.draw_at(frame * 50 * 60, &snapshot, counts);
        if frame == 0 {
            report("first frame");
        }
    }
    report("after 400 frames");
}

/// `saver_memory live <seconds>`: the full saver stack (live feed, OSINT worker with every keyless source on).
#[allow(dead_code)]
pub fn live(seconds: u64) {
    use threat_atlas_core::{saver_config::NoKeys, saver_ffi::SaverWorker};
    let dir = std::env::temp_dir().join("saver-memory-probe");
    let _ = std::fs::create_dir_all(&dir);
    let settings = dir.join("settings.json");
    std::fs::write(&settings, r#"{"enabled_sources":["cisa-kev","first-epss","tor-exit","sans-isc","team-cymru","sslbl","ransomware-live","shodan-internetdb","ripe-ris","spamhaus-drop","phishtank"],"watch_domains":[]}"#).unwrap();
    report("start");
    let mut session = SaverSession::new();
    session.fit_window(1920, 1080);
    report("session");
    let worker = SaverWorker::start(dir.join("cache"), settings, Box::new(NoKeys), None);
    report("worker");
    let t = std::time::Instant::now();
    let mut next = 0;
    while t.elapsed().as_secs() < seconds {
        session.set_intel(worker.osint());
        let _ = session.frame();
        if t.elapsed().as_secs() >= next {
            report(&format!("t={next}s"));
            next += 10;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    report("end");
}

/// `saver_memory epss`: what the in-memory EPSS list costs (about 400,000 scores, as the worker keeps them).
#[allow(dead_code)]
pub fn epss() {
    use threat_atlas_core::osint::EpssScore;
    let base = LIVE.load(Relaxed);
    let scores: Vec<EpssScore> = (0..400_000)
        .map(|i| EpssScore {
            cve: format!("CVE-{}-{:05}", 1999 + i % 27, i),
            epss: 0.01,
            percentile: 0.5,
        })
        .collect();
    let bytes = serde_json::to_vec(&scores).unwrap();
    println!(
        "400k scores in memory: {}  as JSON file: {}",
        mb(LIVE.load(Relaxed) - base - bytes.len()),
        mb(bytes.len())
    );
    let wanted: std::collections::HashSet<&str> = ["CVE-1999-00000", "CVE-2024-00025"].into();
    drop(scores);
    PEAK.store(LIVE.load(Relaxed), Relaxed);
    let before = LIVE.load(Relaxed);
    let kept = threat_atlas_core::osint::epss_for(&bytes, &wanted).unwrap();
    println!(
        "epss_for over the file: kept {} scores, extra peak {}",
        kept.len(),
        mb(PEAK.load(Relaxed) - before)
    );
}
