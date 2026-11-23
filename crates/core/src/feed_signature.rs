//! Detached Ed25519 signature for the update feed (docs/UPDATE-CHANNELS.md, section 4 and section 10,
//! decision 2, revocation design Option A chosen by the owner on 23 Nov 2026). Apps reject an unsigned or
//! wrongly signed feed and keep the installed version.
//!
//! Trust model: apps embed **only** the owner's offline recovery key. The publisher's daily signing key is
//! delegated in the feed itself, signed by the recovery key **with an expiry date**, so a stolen signing key
//! stops working on its own when its delegation expires and is not renewed.
//!
//! Format, version 1:
//! - Signature file `feed.json.sig`: one line `ed25519 <key-id> <signature>`, where `key-id` is the first
//!   16 lowercase hex characters of SHA-256(public key) and `signature` is 128 lowercase hex characters.
//!   A trailing newline is allowed; nothing else is.
//! - Signed feed message: [`FEED_CONTEXT`] followed by the exact bytes of `feed.json`.
//! - Delegations: top-level `"signing_keys": [{"key": "<64 hex>", "expires": "YYYY-MM-DD",
//!   "recovery_signature": "<128 hex>"}]` (at most [`MAX_DELEGATIONS`]). The recovery key signs
//!   [`KEY_CONTEXT`] followed by the 32 key bytes and the 10 ASCII bytes of `expires`. A delegation is valid
//!   up to and including its `expires` day (UTC). Expired delegations are ignored; a malformed or wrongly
//!   signed one, or one reaching more than [`MAX_DELEGATION_DAYS`] ahead, rejects the whole feed.
//!
//! Accepted signers: the recovery key itself (emergency) and delegated keys that have not expired. The two
//! context strings keep a feed signature from ever counting as a delegation and the other way round.
//! No network, no file access and no key material lives here; callers pass bytes and today's UTC date.
use crate::update_feed::MAX_FEED_BYTES;
use jiff::civil::Date;
use ring::signature::{UnparsedPublicKey, ED25519};
use sha2::{Digest, Sha256};

/// Prefix of every signed feed message.
pub const FEED_CONTEXT: &[u8] = b"threat-atlas-feed-v1\n";
/// Prefix of every recovery signature over a delegated signing key.
pub const KEY_CONTEXT: &[u8] = b"threat-atlas-signing-key-v1\n";
/// A signature file is one short line; anything much longer is not ours.
pub const MAX_SIGNATURE_BYTES: usize = 256;
/// More delegations than this in one feed is treated as tampering.
pub const MAX_DELEGATIONS: usize = 4;
/// A delegation may not reach further ahead than this; renewal is planned about every 90 days.
pub const MAX_DELEGATION_DAYS: i32 = 400;

/// The public key an app trusts: the owner's offline recovery key (R1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustRoot {
    pub recovery: [u8; 32],
}

/// The owner's offline recovery public key (R1), created by Robert on 23 Nov 2026 with OpenSSL Ed25519.
/// Key id `4a52c7c6add9e830`. The private key never leaves the owner: an encrypted file stored as a
/// Document in his 1Password (verified byte for byte), passphrase on paper. Changing this constant needs an
/// owner decision and a new app version.
pub const RECOVERY_PUBLIC_KEY: [u8; 32] = [
    0xf4, 0xc7, 0x63, 0xc7, 0xc2, 0x41, 0xf9, 0xcb, 0xed, 0xaa, 0xf6, 0xc5, 0x28, 0x10, 0x73, 0xc9,
    0x7e, 0x52, 0xb5, 0xea, 0xce, 0x00, 0xc6, 0x38, 0x59, 0x25, 0xa7, 0x72, 0xc6, 0x37, 0xbf, 0xcc,
];

/// The key built into release builds. Callers that get `None` must treat feed-based updates as
/// unavailable, never as "accept anything" (that was the state before R1).
pub fn official_trust_root() -> Option<TrustRoot> {
    Some(TrustRoot {
        recovery: RECOVERY_PUBLIC_KEY,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureError {
    /// Feed or signature file larger than allowed.
    TooLarge,
    /// No signature file, or not the `ed25519 <key-id> <signature>` line.
    Malformed,
    /// The key id names neither the recovery key nor a valid, unexpired delegated key.
    UnknownKey,
    /// The signature does not verify for the named key.
    BadSignature,
    /// A `signing_keys` delegation is malformed, wrongly signed or reaches too far ahead.
    BadDelegation,
}

/// Lowercase hex id of a public key: first 8 bytes of its SHA-256.
pub fn key_id(public_key: &[u8; 32]) -> String {
    hex(&Sha256::digest(public_key)[..8])
}

/// The bytes the recovery key signs for one delegation.
pub fn delegation_message(key: &[u8; 32], expires: &str) -> Vec<u8> {
    let mut message = KEY_CONTEXT.to_vec();
    message.extend_from_slice(key);
    message.extend_from_slice(expires.as_bytes());
    message
}

/// Verifies `feed` against the detached `signature` file on `today` (UTC). `Ok(())` means a trusted key
/// signed exactly these bytes; the caller still runs `update_feed::parse_feed` and every download check.
pub fn verify_feed(
    feed: &[u8],
    signature: &[u8],
    root: &TrustRoot,
    today: Date,
) -> Result<(), SignatureError> {
    if feed.len() > MAX_FEED_BYTES || signature.len() > MAX_SIGNATURE_BYTES {
        return Err(SignatureError::TooLarge);
    }
    let (id, sig) = parse_signature_line(signature)?;
    let mut trusted = vec![root.recovery];
    trusted.extend(delegated_keys(feed, &root.recovery, today)?);
    let key = trusted
        .iter()
        .find(|k| key_id(k) == id)
        .ok_or(SignatureError::UnknownKey)?;
    let mut message = Vec::with_capacity(FEED_CONTEXT.len() + feed.len());
    message.extend_from_slice(FEED_CONTEXT);
    message.extend_from_slice(feed);
    UnparsedPublicKey::new(&ED25519, key)
        .verify(&message, &sig)
        .map_err(|_| SignatureError::BadSignature)
}

fn parse_signature_line(bytes: &[u8]) -> Result<(String, [u8; 64]), SignatureError> {
    let text = std::str::from_utf8(bytes).map_err(|_| SignatureError::Malformed)?;
    let line = text.strip_suffix('\n').unwrap_or(text);
    let mut parts = line.split(' ');
    let (Some("ed25519"), Some(id), Some(sig), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(SignatureError::Malformed);
    };
    if id.len() != 16 || !is_lower_hex(id) {
        return Err(SignatureError::Malformed);
    }
    let sig = unhex::<64>(sig).ok_or(SignatureError::Malformed)?;
    Ok((id.to_string(), sig))
}

/// Strict `YYYY-MM-DD`.
fn parse_day(text: &str) -> Option<Date> {
    let b = text.as_bytes();
    let shape = b.len() == 10
        && b[4] == b'-'
        && b[7] == b'-'
        && b.iter()
            .enumerate()
            .all(|(i, c)| i == 4 || i == 7 || c.is_ascii_digit());
    if !shape {
        return None;
    }
    text.parse().ok()
}

/// Unexpired delegated signing keys announced in the feed, each checked against the recovery key.
fn delegated_keys(
    feed: &[u8],
    recovery: &[u8; 32],
    today: Date,
) -> Result<Vec<[u8; 32]>, SignatureError> {
    // An unparsable feed has no delegations; the signature check (and later parse_feed) still decide.
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(feed) else {
        return Ok(Vec::new());
    };
    let Some(entries) = value.get("signing_keys") else {
        return Ok(Vec::new());
    };
    let entries = entries.as_array().ok_or(SignatureError::BadDelegation)?;
    if entries.len() > MAX_DELEGATIONS {
        return Err(SignatureError::BadDelegation);
    }
    let horizon = today
        .checked_add(jiff::Span::new().days(MAX_DELEGATION_DAYS))
        .map_err(|_| SignatureError::BadDelegation)?;
    let verifier = UnparsedPublicKey::new(&ED25519, recovery);
    let mut keys = Vec::new();
    for entry in entries {
        let field = |name: &str| entry.get(name).and_then(serde_json::Value::as_str);
        let key = field("key")
            .and_then(unhex::<32>)
            .ok_or(SignatureError::BadDelegation)?;
        let expires_text = field("expires").ok_or(SignatureError::BadDelegation)?;
        let expires = parse_day(expires_text).ok_or(SignatureError::BadDelegation)?;
        let sig = field("recovery_signature")
            .and_then(unhex::<64>)
            .ok_or(SignatureError::BadDelegation)?;
        verifier
            .verify(&delegation_message(&key, expires_text), &sig)
            .map_err(|_| SignatureError::BadDelegation)?;
        if expires > horizon {
            return Err(SignatureError::BadDelegation);
        }
        if expires >= today {
            keys.push(key);
        }
    }
    Ok(keys)
}

fn is_lower_hex(text: &str) -> bool {
    text.bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn unhex<const N: usize>(text: &str) -> Option<[u8; N]> {
    if text.len() != N * 2 || !is_lower_hex(text) {
        return None;
    }
    let mut out = [0u8; N];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use jiff::civil::date;
    use ring::rand::SystemRandom;
    use ring::signature::{Ed25519KeyPair, KeyPair};

    struct Key(Ed25519KeyPair);
    impl Key {
        fn new() -> Self {
            let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
            Key(Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap())
        }
        fn public(&self) -> [u8; 32] {
            self.0.public_key().as_ref().try_into().unwrap()
        }
        fn sign_feed(&self, feed: &[u8]) -> Vec<u8> {
            let mut message = FEED_CONTEXT.to_vec();
            message.extend_from_slice(feed);
            let sig = self.0.sign(&message);
            format!("ed25519 {} {}\n", key_id(&self.public()), hex(sig.as_ref())).into_bytes()
        }
        /// A delegation entry for `key`, signed by `self` (the recovery key in honest use).
        fn delegate(&self, key: &Key, expires: &str) -> String {
            let sig = self.0.sign(&delegation_message(&key.public(), expires));
            format!(
                r#"{{"key":"{}","expires":"{}","recovery_signature":"{}"}}"#,
                hex(&key.public()),
                expires,
                hex(sig.as_ref())
            )
        }
    }

    const TODAY: Date = date(2026, 11, 23);
    const FEED: &[u8] = br#"{"schema_version":1,"products":{}}"#;

    fn feed_with(delegations: &[String]) -> String {
        format!(
            r#"{{"schema_version":1,"products":{{}},"signing_keys":[{}]}}"#,
            delegations.join(",")
        )
    }

    fn check(feed: &str, signer: &Key, recovery: &Key, today: Date) -> Result<(), SignatureError> {
        let root = TrustRoot {
            recovery: recovery.public(),
        };
        verify_feed(
            feed.as_bytes(),
            &signer.sign_feed(feed.as_bytes()),
            &root,
            today,
        )
    }

    #[test]
    fn official_root_is_the_owners_r1_key() {
        let root = official_trust_root().expect("R1 is built in");
        // Pinned to the value Robert printed on 23 Nov 2026; a silent change here must fail the build.
        assert_eq!(
            hex(&root.recovery),
            "f4c763c7c241f9cbedaaf6c5281073c97e52b5eace00c6385925a772c637bfcc"
        );
        assert_eq!(key_id(&root.recovery), "4a52c7c6add9e830");
        // A valid Ed25519 point: ring rejects malformed public keys at verification time, so check that a
        // garbage signature fails as BadSignature (key accepted) rather than anything else.
        let feed = br#"{"schema_version":1}"#;
        let sig = format!("ed25519 4a52c7c6add9e830 {}", "00".repeat(64));
        assert_eq!(
            verify_feed(feed, sig.as_bytes(), &root, date(2026, 11, 23)),
            Err(SignatureError::BadSignature)
        );
    }

    #[test]
    fn the_real_first_delegation_verifies_with_the_built_in_key() {
        // Signed by Robert with OpenSSL on 23 Nov 2026: R1 delegates CL's feed signing key until 2027-02-21.
        // Proves OpenSSL (owner side) and ring (app side) agree on the exact message bytes.
        let cl_key: [u8; 32] =
            unhex("1b0f14750dc683b348fa728ea2921ea287291d03d7b0b555b3c22036d57c0c8e").unwrap();
        let sig: [u8; 64] = unhex(concat!(
            "8771d9d28e8c73e4fc31c66cb28a3abc7d599dccf0955c2546618725adeb93ef",
            "96c297e5671e97eb5930fc8a8e10b1fd9435212664a608fda90d597a75aa8e0b"
        ))
        .unwrap();
        assert_eq!(key_id(&cl_key), "524c828be6e1600b");
        let verifier = UnparsedPublicKey::new(&ED25519, RECOVERY_PUBLIC_KEY);
        assert!(verifier
            .verify(&delegation_message(&cl_key, "2027-02-21"), &sig)
            .is_ok());
        assert!(
            verifier
                .verify(&delegation_message(&cl_key, "2027-02-22"), &sig)
                .is_err(),
            "the date is covered by the signature"
        );
    }

    #[test]
    fn delegated_key_works_until_and_including_its_expiry_day() {
        let (recovery, signing) = (Key::new(), Key::new());
        let feed = feed_with(&[recovery.delegate(&signing, "2027-02-21")]);
        assert_eq!(check(&feed, &signing, &recovery, TODAY), Ok(()));
        assert_eq!(check(&feed, &signing, &recovery, date(2027, 2, 21)), Ok(()));
        assert_eq!(
            check(&feed, &signing, &recovery, date(2027, 2, 22)),
            Err(SignatureError::UnknownKey),
            "a stolen key stops working when its delegation expires"
        );
    }

    #[test]
    fn recovery_key_may_sign_directly_but_an_undelegated_key_may_not() {
        let (recovery, signing) = (Key::new(), Key::new());
        let text = std::str::from_utf8(FEED).unwrap();
        assert_eq!(check(text, &recovery, &recovery, TODAY), Ok(()));
        assert_eq!(
            check(text, &signing, &recovery, TODAY),
            Err(SignatureError::UnknownKey)
        );
    }

    #[test]
    fn unsigned_tampered_or_forged_feeds_are_rejected() {
        let (recovery, signing, stranger) = (Key::new(), Key::new(), Key::new());
        let root = TrustRoot {
            recovery: recovery.public(),
        };
        let feed = feed_with(&[recovery.delegate(&signing, "2027-02-21")]);
        let sig = signing.sign_feed(feed.as_bytes());
        assert_eq!(
            verify_feed(feed.as_bytes(), b"", &root, TODAY),
            Err(SignatureError::Malformed)
        );
        let tampered = feed.replace(r#""products":{}"#, r#""products":{"x":{}}"#);
        assert_eq!(
            verify_feed(tampered.as_bytes(), &sig, &root, TODAY),
            Err(SignatureError::BadSignature)
        );
        // A stranger's signature presented under a trusted key id fails on the signature itself.
        let forged = String::from_utf8(stranger.sign_feed(feed.as_bytes()))
            .unwrap()
            .replace(&key_id(&stranger.public()), &key_id(&signing.public()));
        assert_eq!(
            verify_feed(feed.as_bytes(), forged.as_bytes(), &root, TODAY),
            Err(SignatureError::BadSignature)
        );
    }

    #[test]
    fn delegations_not_signed_by_the_recovery_key_reject_the_feed() {
        let (recovery, signing, attacker) = (Key::new(), Key::new(), Key::new());
        // The attacker delegates their own key with their own signature.
        let feed = feed_with(&[attacker.delegate(&attacker, "2027-01-01")]);
        assert_eq!(
            check(&feed, &attacker, &recovery, TODAY),
            Err(SignatureError::BadDelegation)
        );
        // A stolen signing key cannot extend its own delegation.
        let feed = feed_with(&[signing.delegate(&signing, "2027-12-01")]);
        assert_eq!(
            check(&feed, &signing, &recovery, TODAY),
            Err(SignatureError::BadDelegation)
        );
        // Changing the expiry after signing breaks the recovery signature.
        let honest = recovery.delegate(&signing, "2027-01-01");
        let feed = feed_with(&[honest.replace("2027-01-01", "2027-06-01")]);
        assert_eq!(
            check(&feed, &signing, &recovery, TODAY),
            Err(SignatureError::BadDelegation)
        );
    }

    #[test]
    fn a_feed_signature_cannot_be_replayed_as_a_delegation() {
        let (recovery, signing) = (Key::new(), Key::new());
        // Recovery signs a feed whose bytes happen to equal key + date: the context strings differ.
        let mut message = FEED_CONTEXT.to_vec();
        message.extend_from_slice(&signing.public());
        message.extend_from_slice(b"2027-01-01");
        let replay = format!(
            r#"{{"key":"{}","expires":"2027-01-01","recovery_signature":"{}"}}"#,
            hex(&signing.public()),
            hex(recovery.0.sign(&message).as_ref())
        );
        assert_eq!(
            check(&feed_with(&[replay]), &signing, &recovery, TODAY),
            Err(SignatureError::BadDelegation)
        );
    }

    #[test]
    fn expired_delegations_are_ignored_and_a_renewed_one_takes_over() {
        let (recovery, old, new) = (Key::new(), Key::new(), Key::new());
        let feed = feed_with(&[
            recovery.delegate(&old, "2026-11-01"),
            recovery.delegate(&new, "2027-02-21"),
        ]);
        assert_eq!(check(&feed, &new, &recovery, TODAY), Ok(()));
        assert_eq!(
            check(&feed, &old, &recovery, TODAY),
            Err(SignatureError::UnknownKey)
        );
    }

    #[test]
    fn delegations_reaching_too_far_or_badly_formed_reject_the_feed() {
        let (recovery, signing) = (Key::new(), Key::new());
        let too_far = feed_with(&[recovery.delegate(&signing, "2028-12-31")]);
        assert_eq!(
            check(&too_far, &signing, &recovery, TODAY),
            Err(SignatureError::BadDelegation)
        );
        let edge = TODAY
            .checked_add(jiff::Span::new().days(MAX_DELEGATION_DAYS))
            .unwrap()
            .to_string();
        let at_edge = feed_with(&[recovery.delegate(&signing, &edge)]);
        assert_eq!(check(&at_edge, &signing, &recovery, TODAY), Ok(()));
        for expires in [
            "2027-1-01",
            "2027-13-01",
            "20270101xx",
            "2027/01/01",
            " 2027-01-1",
        ] {
            let feed = feed_with(&[recovery.delegate(&signing, expires)]);
            assert_eq!(
                check(&feed, &signing, &recovery, TODAY),
                Err(SignatureError::BadDelegation),
                "{expires}"
            );
        }
        let many: Vec<String> = (0..MAX_DELEGATIONS + 1)
            .map(|_| recovery.delegate(&Key::new(), "2027-01-01"))
            .collect();
        for feed in [
            r#"{"schema_version":1,"signing_keys":"nope"}"#.to_string(),
            r#"{"schema_version":1,"signing_keys":[{"key":"00"}]}"#.to_string(),
            feed_with(&many),
        ] {
            assert_eq!(
                check(&feed, &recovery, &recovery, TODAY),
                Err(SignatureError::BadDelegation),
                "{feed}"
            );
        }
    }

    #[test]
    fn signature_line_must_be_exact_and_small() {
        let recovery = Key::new();
        let root = TrustRoot {
            recovery: recovery.public(),
        };
        let good = String::from_utf8(recovery.sign_feed(FEED)).unwrap();
        let line = good.trim_end();
        assert_eq!(
            verify_feed(FEED, line.as_bytes(), &root, TODAY),
            Ok(()),
            "newline optional"
        );
        for bad in [
            line.replacen("ed25519", "rsa", 1),
            format!("{line} extra"),
            format!(" {line}"),
            format!("{line}\n\n"),
            line.to_uppercase().replacen("ED25519", "ed25519", 1),
            line[..line.len() - 2].to_string(),
        ] {
            assert_eq!(
                verify_feed(FEED, bad.as_bytes(), &root, TODAY),
                Err(SignatureError::Malformed),
                "{bad:?}"
            );
        }
        let huge = vec![b'a'; MAX_SIGNATURE_BYTES + 1];
        assert_eq!(
            verify_feed(FEED, &huge, &root, TODAY),
            Err(SignatureError::TooLarge)
        );
        let big_feed = vec![b' '; MAX_FEED_BYTES + 1];
        assert_eq!(
            verify_feed(&big_feed, good.as_bytes(), &root, TODAY),
            Err(SignatureError::TooLarge)
        );
    }

    #[test]
    fn key_id_and_hex_helpers() {
        let id = key_id(&[7u8; 32]);
        assert_eq!(id.len(), 16);
        assert!(is_lower_hex(&id));
        assert_eq!(unhex::<2>("0aff"), Some([0x0a, 0xff]));
        assert_eq!(unhex::<2>("0AFF"), None, "uppercase is not canonical");
        assert_eq!(unhex::<2>("0af"), None);
        assert_eq!(hex(&[0x0a, 0xff]), "0aff");
        assert_eq!(parse_day("2027-02-28"), Some(date(2027, 2, 28)));
        assert_eq!(parse_day("2027-02-30"), None);
    }
}
