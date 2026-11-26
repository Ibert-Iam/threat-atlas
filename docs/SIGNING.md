# Release signing

## Current project status

Windows artifacts are unsigned by owner decision of 24 November 2026. Trusted Windows code signing is not planned
for AtlasSOC RC2 or a later version, and no alternative signing route is proposed. Windows SmartScreen or
organisational policy may warn or block an unsigned download; do not disable OS security protections. A matching
SHA-256 proves agreement with the published file, not a trusted publisher identity.

macOS bundles are Developer ID signed when the release page says so. Never treat stable status as a substitute for
the signature stated on the exact asset.

## macOS
An Apple Developer Program account and Developer ID Application certificate with
its private key are needed to sign the app and screensaver. A Developer ID Installer
certificate is additionally needed if distributing a signed PKG installer.

Set MACOS_SIGN_IDENTITY to the Developer ID Application identity when running
scripts/build-macos.sh --universal. Without it the script uses local ad-hoc signing.
For public release submit a ZIP containing the signed bundles with:

    xcrun notarytool submit release.zip --keychain-profile YOUR_PROFILE --wait

Use a previously configured local Keychain profile or a securely stored App Store
Connect API key. Never commit key files, passwords or exported P12 certificates.
Review the notarization log, validate the final archive, and test it with Gatekeeper
on a clean Mac. ZIP files cannot themselves be stapled; distribute a supported
stapled app/DMG/PKG as appropriate. Test screensaver-host loading as well as the app.

## AtlasSOC Desktop (standalone app)
Same identities as above. macOS: `MACOS_SIGN_IDENTITY="Developer ID Application: ..." private-beta/cloudflare-macos/build.sh`
signs with hardened runtime and a timestamp; adding `MACOS_NOTARY_PROFILE=<profile>` also
notarizes and staples the app. Windows builds stay unsigned: no Authenticode step is configured,
and the release notes disclose that. Do not describe an unsigned build as publisher-verified.

References:
- https://developer.apple.com/help/account/certificates/create-developer-id-certificates/
- https://developer.apple.com/documentation/security/notarizing-macos-software-before-distribution
