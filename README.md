# Threat Atlas update feed

Machine-readable pointer list for Threat Atlas and AtlasSOC updates (docs/UPDATE-CHANNELS.md on `main`).

- `feed.json`: channels, releases, hashes and download links. It never authorises an installation by itself: apps still check the SHA-256 and the operating-system signature of every download.
- `feed.json.sig`: detached Ed25519 signature (format v1). Apps trust only the owner's built-in recovery key; the publisher's signing key is delegated inside `feed.json` (`signing_keys`) with an expiry date.

Only the publisher (CL) changes this branch, with `scripts/sign_feed.py`. Do not edit these files by hand: any change breaks the signature and the apps reject the feed.
