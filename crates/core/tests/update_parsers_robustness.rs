//! Robustness and property round for the update parsers (RC2 hardening, Gate 3): the feed parser, the
//! detached signature line and its delegations, the whole update check, the saved state file and the
//! macOS C ABI (request JSON and package offer).
//!
//! Like the OSINT round: random bytes, truncated, bit-flipped, padded and repeated real payloads, NUL bytes
//! and invalid UTF-8 must never panic and must finish quickly. Two properties on top:
//! 1. Any change to the bytes of the real signed feed (or its signature) is never accepted.
//! 2. The state file survives a write/read round trip, and any bytes read back give a usable state.
//!
//! The fixture is the published signed feed (`fixtures/update/`), checked at a fixed time inside its
//! delegation. Deterministic (fixed seed), so a failure reproduces.
use std::time::{Duration, Instant};
use threat_atlas_core::{
    feed_signature::{official_trust_root, verify_feed, TrustRoot},
    update_check::{check, CheckState, Installed, Outcome},
    update_feed::{parse_feed, Channel, Kind},
    update_ffi::{respond, verify_package},
};

const FEED: &[u8] = include_bytes!("fixtures/update/feed.json");
const SIG: &[u8] = include_bytes!("fixtures/update/feed.json.sig");
/// 2026-11-26 12:00 UTC: inside the fixture's delegation and after its generation time.
const NOW: i64 = 1_795_694_400;

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        // xorshift64*
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn bytes(&mut self, max: usize) -> Vec<u8> {
        let len = (self.next() as usize) % (max + 1);
        (0..len).map(|_| self.next() as u8).collect()
    }
}

/// One random change; never returns the input unchanged.
fn mutate(rng: &mut Rng, seed: &[u8]) -> Vec<u8> {
    loop {
        let mut b = seed.to_vec();
        match rng.next() % 6 {
            0 => b.truncate((rng.next() as usize) % (b.len() + 1)),
            1 => {
                for _ in 0..=(rng.next() % 8) {
                    if !b.is_empty() {
                        let i = (rng.next() as usize) % b.len();
                        b[i] ^= 1 << (rng.next() % 8);
                    }
                }
            }
            2 => {
                let i = (rng.next() as usize) % (b.len() + 1);
                b.splice(i..i, rng.bytes(32));
            }
            3 => b.extend(std::iter::repeat_n(b'0', (rng.next() % 4096) as usize)),
            4 => b = b.repeat(((rng.next() % 40) + 2) as usize),
            _ => {
                let i = (rng.next() as usize) % (b.len() + 1);
                b.insert(i, 0);
            }
        }
        if b != seed {
            return b;
        }
    }
}

fn now() -> jiff::Timestamp {
    jiff::Timestamp::from_second(NOW).unwrap()
}

fn installed(channel: Channel) -> Installed<'static> {
    Installed {
        product: "atlassoc",
        version: "0.8.0-rc.1",
        build: Some(15),
        channel,
        platform: "macos-universal",
        kind: Kind::Portable,
    }
}

fn root() -> TrustRoot {
    official_trust_root().expect("R1 is built in")
}

/// Runs every update parser on one feed/signature pair; returns the check outcome for the RC channel.
fn feed_all(feed: &[u8], sig: &[u8]) -> Outcome {
    let _ = parse_feed(feed);
    let _ = verify_feed(
        feed,
        sig,
        &root(),
        now().to_zoned_datetime(jiff::tz::TimeZone::UTC).date(),
    );
    let other = TrustRoot { recovery: [7; 32] };
    let _ = verify_feed(
        feed,
        sig,
        &other,
        now().to_zoned_datetime(jiff::tz::TimeZone::UTC).date(),
    );
    let mut state = CheckState::default();
    check(
        feed,
        sig,
        Some(&root()),
        now(),
        &installed(Channel::Rc),
        &mut state,
    )
}

fn accepted(outcome: &Outcome) -> bool {
    !matches!(outcome, Outcome::Failed(_) | Outcome::Unavailable)
}

#[test]
fn the_fixture_is_accepted_unchanged() {
    // Baseline for the property below: the real signed feed passes at NOW.
    assert!(accepted(&feed_all(FEED, SIG)), "fixture must verify");
}

#[test]
fn update_parsers_survive_random_bytes() {
    let started = Instant::now();
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    for _ in 0..2000 {
        let feed = rng.bytes(4096);
        let sig = rng.bytes(200);
        assert!(!accepted(&feed_all(&feed, &sig)), "random bytes accepted");
        let _ = CheckState::from_json(&feed);
        let _ = respond(&feed, &sig, &String::from_utf8_lossy(&feed));
        let _ = verify_package(&String::from_utf8_lossy(&sig), &feed);
    }
    assert!(started.elapsed() < Duration::from_secs(60));
}

#[test]
fn any_change_to_the_signed_feed_is_refused() {
    let started = Instant::now();
    let mut rng = Rng(0xD1B5_4A32_D192_ED03);
    for _ in 0..400 {
        let feed = mutate(&mut rng, FEED);
        assert!(
            !accepted(&feed_all(&feed, SIG)),
            "a changed feed was accepted"
        );
        let sig = mutate(&mut rng, SIG);
        assert!(
            !accepted(&feed_all(FEED, &sig)),
            "a changed signature was accepted"
        );
    }
    assert!(started.elapsed() < Duration::from_secs(120));
}

#[test]
fn pathological_inputs_are_refused_quickly() {
    let started = Instant::now();
    let deep = format!("{}{}", "[".repeat(100_000), "]".repeat(100_000));
    let huge_number = format!("{{\"schema_version\": 1{}}}", "0".repeat(100_000));
    let nul = vec![0u8; 1_000_000];
    let big = vec![b'{'; 2_000_000];
    for input in [
        deep.as_bytes(),
        huge_number.as_bytes(),
        &nul,
        &big,
        &[0xff, 0xfe, 0xfd],
    ] {
        assert!(!accepted(&feed_all(input, SIG)));
        let _ = CheckState::from_json(input);
        let _ = respond(input, SIG, &String::from_utf8_lossy(input));
    }
    assert!(started.elapsed() < Duration::from_secs(30));
}

#[test]
fn state_file_round_trips_and_never_panics() {
    let mut state = CheckState::default();
    let _ = check(
        FEED,
        SIG,
        Some(&root()),
        now(),
        &installed(Channel::Rc),
        &mut state,
    );
    let text = state.to_json();
    let back = CheckState::from_json(text.as_bytes());
    assert_eq!(back.to_json(), text, "state must round-trip");
    let mut rng = Rng(0x2545_F491_4F6C_DD1D);
    for _ in 0..2000 {
        let damaged = mutate(&mut rng, text.as_bytes());
        let read = CheckState::from_json(&damaged);
        // Whatever comes back can be written again and read back the same.
        let again = read.to_json();
        assert_eq!(CheckState::from_json(again.as_bytes()).to_json(), again);
    }
}

#[test]
fn ffi_request_and_offer_survive_mutation() {
    let request = r#"{"product":"atlassoc","version":"0.8.0-rc.0","build":14,"channel":"rc","platform":"macos-universal","kind":"portable","now":1795694400}"#;
    let reply: serde_json::Value = serde_json::from_str(&respond(FEED, SIG, request)).unwrap();
    assert_eq!(
        reply["result"], "available",
        "fixture offers rc.1 to build 14"
    );
    let offer = reply["offer"].to_string();
    let mut rng = Rng(0x94D0_49BB_1331_11EB);
    for _ in 0..2000 {
        let req = mutate(&mut rng, request.as_bytes());
        let _ = respond(FEED, SIG, &String::from_utf8_lossy(&req));
        let o = mutate(&mut rng, offer.as_bytes());
        let payload = rng.bytes(512);
        // A changed offer or random bytes never pass the package check.
        assert_ne!(verify_package(&String::from_utf8_lossy(&o), &payload), 0);
    }
}
