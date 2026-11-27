# Screensaver on-screen attribution (0.8.0)

The shared-core screensaver shows only keyless sources. It never reads a credential store, so keyed sources
(abuse.ch ThreatFox/URLhaus, AlienVault OTX, AbuseIPDB, SSLMate Cert Spotter) are not available in the saver and
have no card here. The stable 0.4.8 screensaver has no OSINT cards at all.

| Card / source | On-screen line |
|---|---|
| GreyNoise base view | GreyNoise public threat map |
| CISA KEV + FIRST EPSS | CISA KEV · FIRST EPSS |
| Tor exits | Tor Project exit list |
| SANS ISC / DShield | SANS ISC / DShield · CC BY-NC-SA 4.0 |
| abuse.ch SSLBL | abuse.ch SSLBL · CC0 |
| ransomware.live | ransomware.live |
| Spamhaus DROP | Spamhaus DROP |
| Phishing.Database | Phishing.Database · MIT |

## Rules

- Show the source line on every card that displays data from that source; do not rely on a single footer line.
- Keep the licence marker where the source requires attribution (SANS ISC CC BY-NC-SA 4.0; Phishing.Database MIT).
- `Spamhaus` is used only as the factual data-source label; do not use it in marketing or promotional material.
- No keyed source is shown; there is no Keychain/credential request in the saver.
- Cloudflare Radar and click-only lookups are not part of the saver.
- No new logo is required. If a logo is used, only the approved Threat Atlas pack is allowed.
- Review this list with the privacy section before any saver release.
