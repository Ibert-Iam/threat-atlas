# AtlasSOC Desktop 0.8.0-rc.2 — release candidate 2 (build 16)

**Status: pre-release, not the latest stable.** AtlasSOC Desktop 0.7.0 stays the stable version. This is a release
candidate for wider testing before 0.8.0. Report problems at <https://github.com/Ibert-Iam/threat-atlas/issues>
(never attach a key or token).

AtlasSOC is free and non-commercial. The data sources are licensed for non-commercial use; see
[Data licences](#data-licences).

## What is new since 0.8.0-rc.1

- **Settings → Updates on Windows and macOS.** A daily check of the signed update feed (Ed25519; offline recovery
  key with an expiring delegated signing key), channels **Stable / Release Candidates / Betas**, and a clear result
  for every outcome: unavailable, up to date, update available, withdrawn, or failed. A failed check is never
  shown as “up to date”.
- **Download only after a click, then verify.** The installer or app named in the feed is checked for exact size
  and SHA-256. On macOS it must also carry the official Developer ID, notarization and a Gatekeeper pass. The
  Windows installer opens in its normal window; the checked macOS app is shown in Finder. **Nothing installs
  silently.**
- **Stability:** the feed worker stops promptly even when DNS is slow.
- **Realtime:** sampled observation arcs are spread across incoming batches with at most one second of visual
  delay; receipt counters and source timestamps are unchanged.
- **Map:** time-zone labels now sit on their zone's meridian; the viewer's own zone shows the real local hour from
  the system clock, in gold (civil zone and daylight saving time).
- **Dependencies:** webpki-roots 1.0.12 (TLS root certificates) and tao 0.37.3 (Windows window layer).
- **Fixes:** help links point to the public repository.
- **Hardening:** dependency audit in CI; macOS update checks verify the app’s version, build and notarization; the
  feed generator requires one consistent build for macOS assets.
- **Not in this release:** Windows code signing. Windows packages stay unsigned; trusted Windows signing is not
  possible at present (paid certificate; open-source programmes declined).

## Platforms

| Platform | File | Signing |
|---|---|---|
| Windows 10/11 x64 | `AtlasSOC-Setup-0.8.0-build16.exe` (Just me or Everyone) and portable ZIP | **Unsigned.** SmartScreen or organisational policy may warn or block; do not disable protections. |
| macOS 14+ (Apple silicon and Intel) | `AtlasSOC-macOS-universal-v0.8.0-rc.2-build16` ZIP | Developer ID signed and notarised (Gatekeeper: *Notarized Developer ID*). |

Linux is not part of this release candidate; the existing 0.7.0 Linux preview is unchanged.

## Install and update

- **Windows:** run the installer and choose **Just me** (no administrator rights) or **Everyone**. It upgrades an
  AtlasSOC install in the same scope. In Settings → Updates, choose the channel, check now, then download. The
  normal installer window opens after verification; UAC appears for an all-users install.
- **macOS:** unzip and move `AtlasSOC.app` where you want it; quit the old app first. Updates are checked in
  Settings → Updates and the verified app is shown in Finder; nothing replaces a running app silently.
- Keep a copy of 0.7.0 if you want to go back. Settings and keys are kept unless you remove them.

## Data licences

Cloudflare Radar data is CC BY-NC 4.0 (attribution, non-commercial). The other sources have their own terms,
listed in Settings and in [OSINT-SOURCES.md](OSINT-SOURCES.md). A listing, score or report is context, not proof
that an address is malicious or that you are affected.

## Known limits

The full list is in [KNOWN-BUGS.md](KNOWN-BUGS.md). The main ones:

- Realtime arcs come in bursts rather than a continuous flow (visual only; the fix is planned for the next version).

- Windows is unsigned. Trusted Windows code signing is not possible for us at present: the certificate is paid and
  the open-source programmes declined us; the Certum procedure is kept for reference only.
- macOS: download and verification were tested end to end against the official signed feed (real package: size,
  SHA-256, Developer ID, Gatekeeper; a tampered hash is refused). Windows: the download and installer hand-over are
  unit-tested, and the installer itself opens in its normal window for the user.
- macOS acceptance passed on this build (Apple silicon). Intel Macs were not tested by hand; the app is universal.
- Screen-size handling follows the older fixed layout. On small or scaled laptop screens the bottom can be
  cropped; 1920x1080 base scaling and multi-screen are planned, not built.
- Keyed sources were checked live on macOS with the maintainer’s own keys. Some Windows key-entry paths and other
  Windows versions remain unverified.
- ransomware.live depends on the provider; a provider outage or expired certificate can show as “no data”.
- Team Cymru ASN, MaxMind GeoLite2 and RIPE RIS are not in this release.
- Soak evidence and exact platform acceptance are recorded in [QUALITY.md](QUALITY.md); this note does not claim
  more than those records.

## Support

Free software, voluntary tips only: <https://ko-fi.com/threatatlas>. Where the money goes: [SUPPORT.md](SUPPORT.md).
