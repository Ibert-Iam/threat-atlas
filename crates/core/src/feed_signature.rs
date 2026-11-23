//! Detached Ed25519 signature for the update feed (docs/UPDATE-CHANNELS.md, section 4 and section 10,
//! decision 2). Apps reject an unsigned or wrongly signed feed and keep the installed version.
//!
//! Format, version 1:
//! - Signature file `feed.json.sig`: one line `ed25519 <key-id> <signature>`, where `key-id` is the first
//!   16 lowercase hex characters of SHA-256(public key) and `signature` is 128 lowercase hex characters.
//!   A trailing newline is allowed; nothing else is.
//! - Signed message: [`FEED_CONTEXT`] followed by the exact bytes of `feed.json`.
//! - Key rotation without a new app version: the feed may carry a top-level array
//!   `"signing_keys": [{"key": "<64 hex>", "recovery_signature": "<128 hex>"}]`. Each entry must be signed by
//!   the offline recovery key over [`KEY_CONTEXT`] followed by the 32 key bytes. One bad entry rejects the
//!   whole feed (fail closed).
//!
//! Accepted signers: the built-in signing keys, the recovery key itself, and rotated keys with a valid
//! recovery signature. The context strings keep a feed signature from ever counting as a key signature and
//! the other way round. No network, no file access and no key material lives here; callers pass bytes.
use crate::update_feed::MAX_FEED_BYTES;
use ring::signature::{UnparsedPublicKey, ED25519};
use sha2::{Digest, Sha256};

/// Prefix of every signed feed message.
pub const FEED_CONTEXT: &[u8] = b"threat-atlas-feed-v1\n";
/// Prefix of every recovery signature over a rotated signing key.
pub const KEY_CONTEXT: &[u8] = b"threat-atlas-signing-key-v1\n";
/// A signature file is one short line; anything much longer is not ours.
pub const MAX_SIGNATURE_BYTES: usize = 256;
/// More rotated keys than this in one feed is treated as tampering.
pub const MAX_ROTATED_KEYS: usize = 4;

/// The public keys an app trusts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustRoot {
    /// Offline key held only by the owner (R1). Signs rotations, and may sign a feed in an emergency.
    pub recovery: [u8; 32],
    /// Day-to-day feed signing keys held by the publisher.
    pub signing: Vec<[u8; 32]>,
}

/// The keys built into release builds. `None` until the owner has created the recovery key (R1) and the
/// publisher's signing key exists: callers must then treat feed-based updates as unavailable, never as
/// "accept anything".
pub fn official_trust_root() -> Option<TrustRoot> {
    None
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureError {
    /// Feed or signature file larger than allowed.
    TooLarge,
    /// No signature file, or not the `ed25519 <key-id> <signature>` line.
    Malformed,
    /// The key id names no trusted key.
    UnknownKey,
    /// The signature does not verify for the named key.
    BadSignature,
    /// A `signing_keys` entry is malformed or not signed by the recovery key.
    BadRotation,
}

/// Lowercase hex id of a public key: first 8 bytes of its SHA-256.
pub fn key_id(public_key: &[u8; 32]) -> String {
    hex(&Sha256::digest(public_key)[..8])
}

/// Verifies `feed` against the detached `signature` file. `Ok(())` means a trusted key signed exactly
/// these bytes; the caller still runs `update_feed::parse_feed` and every download check.
pub fn verify_feed(feed: &[u8], signature: &[u8], root: &TrustRoot) -> Result<(), SignatureError> {
    if feed.len() > MAX_FEED_BYTES || signature.len() > MAX_SIGNATURE_BYTES {
        return Err(SignatureError::TooLarge);
    }
    let (id, sig) = parse_signature_line(signature)?;
    let mut trusted = root.signing.clone();
    trusted.push(root.recovery);
    trusted.extend(rotated_keys(feed, &root.recovery)?);
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

/// Rotated signing keys announced in the feed, each checked against the recovery key.
fn rotated_keys(feed: &[u8], recovery: &[u8; 32]) -> Result<Vec<[u8; 32]>, SignatureError> {
    // An unparsable feed has no rotations; the signature check (and later parse_feed) still decide.
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(feed) else {
        return Ok(Vec::new());
    };
    let Some(entries) = value.get("signing_keys") else {
        return Ok(Vec::new());
    };
    let entries = entries.as_array().ok_or(SignatureError::BadRotation)?;
    if entries.len() > MAX_ROTATED_KEYS {
        return Err(SignatureError::BadRotation);
    }
    let verifier = UnparsedPublicKey::new(&ED25519, recovery);
    let mut keys = Vec::new();
    for entry in entries {
        let field = |name: &str| entry.get(name).and_then(serde_json::Value::as_str);
        let key = field("key")
            .and_then(unhex::<32>)
            .ok_or(SignatureError::BadRotation)?;
        let sig = field("recovery_signature")
            .and_then(unhex::<64>)
            .ok_or(SignatureError::BadRotation)?;
        let mut message = KEY_CONTEXT.to_vec();
        message.extend_from_slice(&key);
        verifier
            .verify(&message, &sig)
            .map_err(|_| SignatureError::BadRotation)?;
        keys.push(key);
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
        fn sign_key(&self, key: &[u8; 32]) -> String {
            let mut message = KEY_CONTEXT.to_vec();
            message.extend_from_slice(key);
            hex(self.0.sign(&message).as_ref())
        }
    }

    const FEED: &[u8] = br#"{"schema_version":1,"products":{}}"#;

    fn root(signing: &Key, recovery: &Key) -> TrustRoot {
        TrustRoot {
            recovery: recovery.public(),
            signing: vec![signing.public()],
        }
    }

    #[test]
    fn official_root_is_absent_until_r1() {
        assert_eq!(official_trust_root(), None);
    }

    #[test]
    fn signing_key_and_recovery_key_are_accepted() {
        let (signing, recovery) = (Key::new(), Key::new());
        let root = root(&signing, &recovery);
        assert_eq!(verify_feed(FEED, &signing.sign_feed(FEED), &root), Ok(()));
        assert_eq!(verify_feed(FEED, &recovery.sign_feed(FEED), &root), Ok(()));
    }

    #[test]
    fn unsigned_tampered_or_foreign_feeds_are_rejected() {
        let (signing, recovery, stranger) = (Key::new(), Key::new(), Key::new());
        let root = root(&signing, &recovery);
        let sig = signing.sign_feed(FEED);
        assert_eq!(
            verify_feed(FEED, b"", &root),
            Err(SignatureError::Malformed)
        );
        let tampered = br#"{"schema_version":1,"products":{"x":{}}}"#;
        assert_eq!(
            verify_feed(tampered, &sig, &root),
            Err(SignatureError::BadSignature)
        );
        assert_eq!(
            verify_feed(FEED, &stranger.sign_feed(FEED), &root),
            Err(SignatureError::UnknownKey)
        );
        // A stranger's signature presented under a trusted key id fails on the signature itself.
        let forged = String::from_utf8(stranger.sign_feed(FEED))
            .unwrap()
            .replace(&key_id(&stranger.public()), &key_id(&signing.public()));
        assert_eq!(
            verify_feed(FEED, forged.as_bytes(), &root),
            Err(SignatureError::BadSignature)
        );
    }

    #[test]
    fn signature_line_must_be_exact() {
        let (signing, recovery) = (Key::new(), Key::new());
        let root = root(&signing, &recovery);
        let good = String::from_utf8(signing.sign_feed(FEED)).unwrap();
        let line = good.trim_end();
        assert_eq!(
            verify_feed(FEED, line.as_bytes(), &root),
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
                verify_feed(FEED, bad.as_bytes(), &root),
                Err(SignatureError::Malformed),
                "{bad:?}"
            );
        }
        let huge = vec![b'a'; MAX_SIGNATURE_BYTES + 1];
        assert_eq!(
            verify_feed(FEED, &huge, &root),
            Err(SignatureError::TooLarge)
        );
        let big_feed = vec![b' '; MAX_FEED_BYTES + 1];
        assert_eq!(
            verify_feed(&big_feed, good.as_bytes(), &root),
            Err(SignatureError::TooLarge)
        );
    }

    #[test]
    fn rotated_key_needs_the_recovery_signature() {
        let (signing, recovery, next) = (Key::new(), Key::new(), Key::new());
        let root = root(&signing, &recovery);
        let entry = |by: &Key| {
            format!(
                r#"{{"schema_version":1,"products":{{}},"signing_keys":[{{"key":"{}","recovery_signature":"{}"}}]}}"#,
                hex(&next.public()),
                by.sign_key(&next.public())
            )
        };
        let rotated = entry(&recovery);
        assert_eq!(
            verify_feed(
                rotated.as_bytes(),
                &next.sign_feed(rotated.as_bytes()),
                &root
            ),
            Ok(())
        );
        // Without a rotation entry the new key is unknown.
        assert_eq!(
            verify_feed(FEED, &next.sign_feed(FEED), &root),
            Err(SignatureError::UnknownKey)
        );
        // A rotation signed by the old signing key (or anyone but the recovery key) rejects the feed.
        let by_signing = entry(&signing);
        assert_eq!(
            verify_feed(
                by_signing.as_bytes(),
                &signing.sign_feed(by_signing.as_bytes()),
                &root
            ),
            Err(SignatureError::BadRotation)
        );
        // A feed signature cannot be replayed as a key signature: contexts differ.
        let mut message = FEED_CONTEXT.to_vec();
        message.extend_from_slice(&next.public());
        let replay = format!(
            r#"{{"schema_version":1,"signing_keys":[{{"key":"{}","recovery_signature":"{}"}}]}}"#,
            hex(&next.public()),
            hex(recovery.0.sign(&message).as_ref())
        );
        assert_eq!(
            verify_feed(replay.as_bytes(), &next.sign_feed(replay.as_bytes()), &root),
            Err(SignatureError::BadRotation)
        );
    }

    #[test]
    fn malformed_or_oversized_rotation_lists_are_rejected() {
        let (signing, recovery) = (Key::new(), Key::new());
        let root = root(&signing, &recovery);
        let entry = |k: &Key| {
            format!(
                r#"{{"key":"{}","recovery_signature":"{}"}}"#,
                hex(&k.public()),
                recovery.sign_key(&k.public())
            )
        };
        let five: Vec<String> = (0..MAX_ROTATED_KEYS + 1)
            .map(|_| entry(&Key::new()))
            .collect();
        for feed in [
            r#"{"schema_version":1,"signing_keys":"nope"}"#.to_string(),
            r#"{"schema_version":1,"signing_keys":[{"key":"00"}]}"#.to_string(),
            format!(
                r#"{{"schema_version":1,"signing_keys":[{}]}}"#,
                five.join(",")
            ),
        ] {
            assert_eq!(
                verify_feed(feed.as_bytes(), &signing.sign_feed(feed.as_bytes()), &root),
                Err(SignatureError::BadRotation),
                "{feed}"
            );
        }
    }

    #[test]
    fn key_id_and_hex_helpers() {
        let key = [7u8; 32];
        let id = key_id(&key);
        assert_eq!(id.len(), 16);
        assert!(is_lower_hex(&id));
        assert_eq!(unhex::<2>("0aff"), Some([0x0a, 0xff]));
        assert_eq!(unhex::<2>("0AFF"), None, "uppercase is not canonical");
        assert_eq!(unhex::<2>("0af"), None);
        assert_eq!(hex(&[0x0a, 0xff]), "0aff");
    }
}
