//! Verify a signed update feed exactly as the apps will (docs/UPDATE-CHANNELS.md, section 4).
//!
//!     cargo run -q -p threat-atlas-core --example verify_feed -- feed.json feed.json.sig
//!
//! Runs the apps' own stateless acceptance path, `update_check::accept_feed`, with the built-in trust root (the
//! owner's R1 recovery key) and the current time: signature by a trusted, unexpired key, the feed's security
//! checks, a timezone-aware `generated_at` and the future bound. Only the per-installation rollback mark is out
//! of scope here. Prints one line and exits 0 only when the apps would accept the feed. Used by
//! scripts/sign_feed.py before anything replaces the published files, and by the daily feed check.
use jiff::Timestamp;
use threat_atlas_core::feed_signature::official_trust_root;
use threat_atlas_core::update_check::accept_feed;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [feed_path, sig_path] = args.as_slice() else {
        eprintln!("usage: verify_feed <feed.json> <feed.json.sig>");
        std::process::exit(2);
    };
    let read = |path: &str| {
        std::fs::read(path).unwrap_or_else(|e| {
            eprintln!("FAIL cannot read {path}: {e}");
            std::process::exit(1);
        })
    };
    let (feed, sig) = (read(feed_path), read(sig_path));
    let Some(root) = official_trust_root() else {
        eprintln!("FAIL no trust root built in");
        std::process::exit(1);
    };
    let now = Timestamp::now();
    match accept_feed(&feed, &sig, &root, now) {
        Ok((_, generated)) => {
            let key_id = String::from_utf8_lossy(&sig)
                .split(' ')
                .nth(1)
                .unwrap_or("?")
                .to_string();
            println!("OK signed by key {key_id}, generated_at {generated}, checked at {now}");
        }
        Err(error) => {
            eprintln!("FAIL {error:?}");
            std::process::exit(1);
        }
    }
}
