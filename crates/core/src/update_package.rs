//! Download and verify step: the checks a host runs on an update package before it hands the file
//! to the normal installer. The signed feed is the only source of truth: the package must come from the
//! release URL the feed names, have exactly the announced size and the announced SHA-256. Pure functions;
//! the hosts do the HTTPS download, keep the file private and never install silently.
use crate::update_feed::{download_url_ok, Asset, Selected, MAX_ASSET_BYTES};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PackageError {
    /// The URL is not this repository's release download for the offered tag and file name.
    Url,
    /// The file name is not a plain name that can be written as one path segment.
    Name,
    /// Announced size is zero or above [`MAX_ASSET_BYTES`].
    TooLarge,
    /// The download is shorter or longer than announced (an interrupted or padded transfer).
    Size { expected: u64, got: u64 },
    /// The bytes do not hash to the announced SHA-256.
    Hash,
}

impl PackageError {
    /// Short text for the host's status line.
    pub fn text(&self) -> String {
        match self {
            Self::Url => "the download address is not an official release address".into(),
            Self::Name => "the file name is not allowed".into(),
            Self::TooLarge => "the announced size is not allowed".into(),
            Self::Size { expected, got } => {
                format!("the download is incomplete or wrong size ({got} of {expected} bytes)")
            }
            Self::Hash => "the file does not match the SHA-256 in the signed update list".into(),
        }
    }
}

/// Where to download from: `(host, path)` of the offered asset, after the same URL rules the feed parser
/// applies. Hosts follow HTTPS redirects from here (GitHub serves release files from a CDN host); the
/// SHA-256 check below is what makes the bytes trustworthy, not the host they came through.
pub fn download_target(offer: &Selected) -> Result<(&'static str, String), PackageError> {
    check_name(&offer.asset)?;
    if !download_url_ok(&offer.asset.url, &[offer.tag.as_str()], &offer.asset.name) {
        return Err(PackageError::Url);
    }
    if offer.asset.size == 0 || offer.asset.size > MAX_ASSET_BYTES {
        return Err(PackageError::TooLarge);
    }
    let path = offer
        .asset
        .url
        .strip_prefix("https://github.com")
        .ok_or(PackageError::Url)?;
    Ok(("github.com", path.to_string()))
}

/// The full check of downloaded bytes against the offer. Call it again on the saved file right before
/// starting the installer, so a file changed on disk in between is refused.
pub fn verify(offer: &Selected, bytes: &[u8]) -> Result<(), PackageError> {
    download_target(offer)?;
    let got = bytes.len() as u64;
    if got != offer.asset.size {
        return Err(PackageError::Size {
            expected: offer.asset.size,
            got,
        });
    }
    let digest = Sha256::digest(bytes);
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    if hex != offer.asset.sha256.to_ascii_lowercase() {
        return Err(PackageError::Hash);
    }
    Ok(())
}

/// A plain file name: letters, digits, `.`, `-`, `_`; no path parts, no leading dot, at most 128 bytes.
fn check_name(asset: &Asset) -> Result<(), PackageError> {
    let name = &asset.name;
    let ok = !name.is_empty()
        && name.len() <= 128
        && !name.starts_with('.')
        && !name.contains("..")
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'));
    ok.then_some(()).ok_or(PackageError::Name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::update_feed::Channel;

    const PAYLOAD: &[u8] = b"pretend installer bytes";

    fn offer(bytes: &[u8]) -> Selected {
        let name = "AtlasSOC-Setup-0.8.0-build16.exe".to_string();
        Selected {
            version: "0.8.0".into(),
            channel: Channel::Stable,
            tag: "atlassoc-v0.8.0".into(),
            build: Some(16),
            asset: Asset {
                platform: "windows-x64".into(),
                kind: "installer".into(),
                url: format!(
                    "https://github.com/Ibert-Iam/threat-atlas/releases/download/atlassoc-v0.8.0/{name}"
                ),
                name,
                sha256: Sha256::digest(bytes)
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect(),
                size: bytes.len() as u64,
            },
        }
    }

    #[test]
    fn good_package_passes_and_targets_the_release_url() {
        let o = offer(PAYLOAD);
        assert_eq!(verify(&o, PAYLOAD), Ok(()));
        let (host, path) = download_target(&o).unwrap();
        assert_eq!(host, "github.com");
        assert_eq!(
            path,
            "/Ibert-Iam/threat-atlas/releases/download/atlassoc-v0.8.0/AtlasSOC-Setup-0.8.0-build16.exe"
        );
        let mut upper = o.clone();
        upper.asset.sha256 = upper.asset.sha256.to_ascii_uppercase();
        assert_eq!(verify(&upper, PAYLOAD), Ok(()), "hex case does not matter");
    }

    #[test]
    fn wrong_hash_is_refused() {
        let o = offer(PAYLOAD);
        let mut tampered = PAYLOAD.to_vec();
        tampered[0] ^= 1;
        assert_eq!(verify(&o, &tampered), Err(PackageError::Hash));
    }

    #[test]
    fn interrupted_or_padded_download_is_refused_on_size() {
        let o = offer(PAYLOAD);
        let cut = &PAYLOAD[..PAYLOAD.len() - 3];
        assert_eq!(
            verify(&o, cut),
            Err(PackageError::Size {
                expected: PAYLOAD.len() as u64,
                got: cut.len() as u64
            })
        );
        let mut long = PAYLOAD.to_vec();
        long.push(0);
        assert!(matches!(verify(&o, &long), Err(PackageError::Size { .. })));
        assert!(matches!(verify(&o, &[]), Err(PackageError::Size { .. })));
    }

    #[test]
    fn wrong_host_or_path_is_refused() {
        let base = offer(PAYLOAD);
        for url in [
            "https://evil.example/Ibert-Iam/threat-atlas/releases/download/atlassoc-v0.8.0/AtlasSOC-Setup-0.8.0-build16.exe",
            "http://github.com/Ibert-Iam/threat-atlas/releases/download/atlassoc-v0.8.0/AtlasSOC-Setup-0.8.0-build16.exe",
            "https://github.com@evil.example/Ibert-Iam/threat-atlas/releases/download/atlassoc-v0.8.0/AtlasSOC-Setup-0.8.0-build16.exe",
            "https://github.com/other/threat-atlas/releases/download/atlassoc-v0.8.0/AtlasSOC-Setup-0.8.0-build16.exe",
            "https://github.com/Ibert-Iam/threat-atlas/releases/download/atlassoc-v9.9.9/AtlasSOC-Setup-0.8.0-build16.exe",
            "https://github.com/Ibert-Iam/threat-atlas/releases/download/atlassoc-v0.8.0/Other.exe",
        ] {
            let mut o = base.clone();
            o.asset.url = url.into();
            assert_eq!(verify(&o, PAYLOAD), Err(PackageError::Url), "{url}");
        }
    }

    #[test]
    fn bad_names_and_sizes_are_refused() {
        for name in [
            "",
            "../x.exe",
            "a/b.exe",
            ".hidden.exe",
            "a b.exe",
            "a\\b.exe",
        ] {
            let mut o = offer(PAYLOAD);
            o.asset.name = name.into();
            assert_eq!(download_target(&o), Err(PackageError::Name), "{name:?}");
        }
        let mut o = offer(PAYLOAD);
        o.asset.size = MAX_ASSET_BYTES + 1;
        assert_eq!(download_target(&o), Err(PackageError::TooLarge));
        o.asset.size = 0;
        assert_eq!(download_target(&o), Err(PackageError::TooLarge));
    }
}
