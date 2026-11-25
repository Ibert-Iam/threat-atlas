//! Updater tests (WP9): builds signed test-feed variants from a copy of the real feed.
//!
//!     cargo run -p threat-atlas-core --example make_test_feeds -- <feed.json> <out-dir>
//!
//! Every run makes a new throwaway test root and signing key in memory and drops them at the end; only the
//! public test root is written (`out-dir/ROOT.txt`). No real key is read or used, and release builds never
//! trust this root: only a `test-feed` build given `ATLAS_TEST_ROOT` does. Each variant is checked here with
//! the same `update_check::check` the apps use, so the expected outcomes in `out-dir/EXPECTED.txt` are
//! verified before anyone tests them on a device.
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::{json, Value};
use threat_atlas_core::feed_signature::{delegation_message, key_id, TrustRoot, FEED_CONTEXT};
use threat_atlas_core::update_check::{check, CheckState, Installed, Outcome};
use threat_atlas_core::update_feed::{Channel, Kind};

fn keypair() -> Ed25519KeyPair {
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).expect("random");
    Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("key")
}

fn public(k: &Ed25519KeyPair) -> [u8; 32] {
    k.public_key().as_ref().try_into().expect("32 bytes")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn sign_line(key: &Ed25519KeyPair, feed: &[u8]) -> String {
    let mut message = FEED_CONTEXT.to_vec();
    message.extend_from_slice(feed);
    format!(
        "ed25519 {} {}\n",
        key_id(&public(key)),
        hex(key.sign(&message).as_ref())
    )
}

/// A copy of the installed release under a new version, build and channel (asset names and URLs follow).
fn fake_release(base: &Value, version: &str, build: u32, channel: &str) -> Value {
    let text = base
        .to_string()
        .replace("0.8.0-rc.1", version)
        .replace("build15", &format!("build{build}"));
    let mut release: Value = serde_json::from_str(&text).expect("json");
    release["build"] = json!(build);
    release["channel"] = json!(channel);
    release
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let (input, out) = (&args[1], std::path::Path::new(&args[2]));
    let base: Value =
        serde_json::from_slice(&std::fs::read(input).expect("read feed")).expect("json");
    let root = keypair();
    let signer = keypair();
    let trust = TrustRoot {
        recovery: public(&root),
    };
    let now = jiff::Timestamp::now();
    let today = now.to_zoned_datetime(jiff::tz::TimeZone::UTC).date();
    let day = |offset: i64| {
        today
            .checked_add(jiff::Span::new().days(offset))
            .expect("day")
            .to_string()
    };
    // Every accepted variant carries the same generated_at, so testing them in any order never trips the
    // rollback guard; only the rollback variant is older.
    let generated = (now - jiff::Span::new().minutes(10))
        .round(jiff::Unit::Second)
        .expect("round");
    let delegation = |expires: &str| {
        json!([{
            "key": hex(&public(&signer)),
            "expires": expires,
            "recovery_signature": hex(root.sign(&delegation_message(&public(&signer), expires)).as_ref()),
        }])
    };
    let installed_release = base["products"]["atlassoc"]["releases"]
        .as_array()
        .expect("releases")
        .iter()
        .find(|r| r["version"] == "0.8.0-rc.1")
        .expect("0.8.0-rc.1 in the feed")
        .clone();
    let make = |edit: &dyn Fn(&mut Value), generated_at: String, expires: &str| {
        let mut feed = base.clone();
        feed["generated_at"] = json!(generated_at);
        feed["signing_keys"] = delegation(expires);
        edit(&mut feed);
        serde_json::to_vec_pretty(&feed).expect("json")
    };
    let add = |feed: &mut Value, release: Value, channel: &str| {
        let block = &mut feed["products"]["atlassoc"];
        block["channels"][channel] = json!({"version": release["version"], "tag": release["tag"]});
        block["releases"]
            .as_array_mut()
            .expect("releases")
            .insert(0, release);
    };
    let g = generated.to_string();
    let valid = day(90);
    let rc2 = fake_release(&installed_release, "0.8.0-rc.2", 16, "rc");
    let stable = fake_release(&installed_release, "0.8.0", 16, "stable");
    let newer_rc = make(&|f| add(f, rc2.clone(), "rc"), g.clone(), &valid);
    let variants: Vec<(&str, Vec<u8>, Option<String>)> = vec![
        ("base", make(&|_| {}, g.clone(), &valid), None),
        ("newer-rc", newer_rc.clone(), None),
        (
            "newer-stable",
            make(&|f| add(f, stable.clone(), "stable"), g.clone(), &valid),
            None,
        ),
        (
            "withdrawn",
            make(
                &|f| {
                    add(f, rc2.clone(), "rc");
                    f["products"]["atlassoc"]["withdrawn"] = json!(["0.8.0-rc.1"]);
                },
                g.clone(),
                &valid,
            ),
            None,
        ),
        (
            "rollback",
            make(&|_| {}, "2026-11-01T00:00:00Z".into(), &valid),
            None,
        ),
        (
            "expired-delegation",
            make(&|_| {}, g.clone(), &day(-3)),
            None,
        ),
        // The newer-rc feed with the base feed's signature: the bytes were changed after signing.
        ("bad-signature", newer_rc, Some("base".into())),
    ];
    std::fs::create_dir_all(out).expect("out dir");
    let mut signatures = std::collections::HashMap::new();
    for (name, feed, _) in &variants {
        signatures.insert(name.to_string(), sign_line(&signer, feed));
    }
    let mut expected = String::from(
        "Installed: AtlasSOC 0.8.0-rc.1 build 15, windows-x64 installer. Each line: channel -> outcome.\n\
         'after base' = state already holds the base feed (rollback case).\n\n",
    );
    for (name, feed, sig_from) in &variants {
        let sig = &signatures[sig_from.as_deref().unwrap_or(name)];
        let dir = out.join(name);
        std::fs::create_dir_all(&dir).expect("dir");
        std::fs::write(dir.join("feed.json"), feed).expect("write");
        std::fs::write(dir.join("feed.json.sig"), sig).expect("write");
        for channel in [Channel::Stable, Channel::Rc, Channel::Beta] {
            let installed = Installed {
                product: "atlassoc",
                version: "0.8.0-rc.1",
                build: Some(15),
                channel,
                platform: "windows-x64",
                kind: Kind::Installer,
            };
            let mut state = CheckState::default();
            if *name == "rollback" {
                state.newest_feed = Some(g.clone());
            }
            let outcome = check(
                feed,
                sig.as_bytes(),
                Some(&trust),
                now,
                &installed,
                &mut state,
            );
            let text = match &outcome {
                Outcome::Available(s) => {
                    format!("available {} ({})", s.version, s.channel.as_str())
                }
                Outcome::Withdrawn { alternative } => format!(
                    "withdrawn, alternative {}",
                    alternative
                        .as_ref()
                        .map_or("none".into(), |s| s.version.clone())
                ),
                other => format!("{other:?}").to_lowercase(),
            };
            let after = if *name == "rollback" {
                " (after base)"
            } else {
                ""
            };
            expected.push_str(&format!(
                "{name:<19} {:<7}-> {text}{after}\n",
                channel.as_str()
            ));
        }
    }
    std::fs::write(out.join("ROOT.txt"), format!("{}\n", hex(&public(&root)))).expect("write");
    std::fs::write(out.join("EXPECTED.txt"), &expected).expect("write");
    print!("{expected}");
    println!("\ntest root (ATLAS_TEST_ROOT): {}", hex(&public(&root)));
}
