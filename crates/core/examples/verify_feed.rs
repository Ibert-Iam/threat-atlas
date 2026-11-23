//! Verify a signed update feed exactly as the apps will (docs/UPDATE-CHANNELS.md, section 4).
//!
//!     cargo run -q -p threat-atlas-core --example verify_feed -- feed.json feed.json.sig
//!
//! Uses the built-in trust root (the owner's R1 recovery key) and today's UTC date, then the feed's own
//! security checks. Prints one line and exits 0 only when the feed would be accepted. Used by
//! scripts/sign_feed.py before anything is written out, and by the daily feed check.
use jiff::{tz::TimeZone, Timestamp};
use threat_atlas_core::feed_signature::{official_trust_root, verify_feed};
use threat_atlas_core::update_feed::parse_feed;

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
    let today = Timestamp::now().to_zoned_datetime(TimeZone::UTC).date();
    if let Err(error) = verify_feed(&feed, &sig, &root, today) {
        eprintln!("FAIL signature: {error:?}");
        std::process::exit(1);
    }
    if let Err(error) = parse_feed(&feed) {
        eprintln!("FAIL feed: {error:?}");
        std::process::exit(1);
    }
    let key_id = String::from_utf8_lossy(&sig)
        .split(' ')
        .nth(1)
        .unwrap_or("?")
        .to_string();
    println!("OK signed by key {key_id}, valid on {today}");
}
