# Screensaver 0.8.0 — shared saver core

This is the release note for the screensaver on the shared AtlasSOC saver core. Windows and macOS use the same view;
the macOS version runs inside Apple's screen-saver host.

## What changes

- The macOS screensaver now uses the shared saver core and the same SOC view as Windows.
- Optional OSINT cards from AtlasSOC appear when the corresponding **keyless** source is enabled. Off still means no
  request.
- The macOS screensaver never reads the Keychain and never asks for an API key. Keyed sources stay off.
- Cloudflare Radar and click-only lookups are not part of the screensaver.
- Screensaver attribution and privacy text are updated; see [SAVER-ATTRIBUTION.md](SAVER-ATTRIBUTION.md) and
  [PRIVACY.md](../PRIVACY.md).

## Upgrading from 0.4.x — one time only

The 0.4.x updaters pin the old release URLs and cannot follow the new signed feed. Install the 0.8.0 package
**manually once**; after that the 0.8.0 updater uses the signed feed. Keep a working 0.4.x copy until the new saver
has been previewed and tested in System Settings or Screen Saver Settings.

## Limits

- macOS preview and real-idle acceptance are not implied by the shared-core change.
- The sandboxed screen-saver host may not see AtlasSOC's `settings.json`; optional sources then remain off.
- Windows packages remain unsigned; macOS signing/notarization is stated on the exact release asset.
- Source freshness and provider availability remain provider-dependent.
