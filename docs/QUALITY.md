# Quality and security review — 28 October 2026

Original review: 0.3.0; updated for published 0.4.0 and the 0.4.1 development line. This is a source review and automated checks,
not an independent penetration test or a guarantee that no bugs remain.

## Fixed in this review

- Remote intention strings previously had no length bound and were drawn in full.
  Enforce 32 bytes, reject control characters, and bound renderer text work.
- Arbitrary Unicode in remote country names could grow the glyph cache over a long
  session. Rendering now uses a bounded printable-ASCII glyph set with replacement
  characters; receipt records still retain valid Unicode for audit purposes.
- Feed-thread creation failure previously panicked inside the macOS host. It now
  reports an offline error. Catch recoverable Rust panics at the frame/create FFI
  boundary; allocation aborts and invalid caller pointers remain outside that guard.
- Windows embedded preview no longer explicitly hides the cursor.
- Make macOS Objective-C ownership explicit and prevent preview-window close from
  automatically releasing a window still owned by the delegate.
- Repair macOS workflow bundle names and clean generated bundles instead of merging
  stale embedded resources. Verify bundle signatures from a clean extraction of the distributable ZIP.
- Lock release dependency resolution, statically link the Windows CRT, restrict CI
  permissions and pin third-party GitHub Actions to exact commits.
- Keep private project history, share links, old binaries and Git objects out of the
  publishable source export. Ignore common credential/private-key file extensions.

## Latest implementation and CI validation

Official 0.4.0 (build 8) was published on 29 October 2026 from commit
`07ec0d8ca323eb97c1165c831f8def28112aea01`. All six automated checks passed
for that commit; final public asset hashes were verified against its checksums.
These results apply to that release, not automatically to later development commits.
Windows files remain unsigned; macOS bundles are ad-hoc signed and unnotarized.

Merged PR #8 added the UTC/system-local clock, publisher-verified opt-in updater,
PowerShell 5.1/7 regression tests, macOS first-frame/lifecycle repair, and screenshot
thumbnails. All six PR checks passed before merge: quality, Windows, macOS,
updater-tests, MSI package and MSI install/uninstall. Current CI also checks
version metadata consistency. Native Mac smoke checks cover drawing before window
attachment and animation, both preview modes, restart, and thumbnail validity.
These tests do not establish real idle/lock behavior or signed N → N+1 updates.
The repaired saver was installed locally; on-device Settings preview/thumbnail
acceptance after restart remains unconfirmed.

## Checks performed locally

- Ten Rust tests pass, including invalid coordinates/schema, overlong/control
  text, oversized messages, bounded buffers/glyph cache, staleness and route expiry.
- Rust formatting and Clippy with warnings denied pass for the host workspace and
  Windows x64 code (cross-target toolchain).
- Fresh universal macOS compilation and Windows x64 release compilation/linking.
- macOS bundle signature and principal-class loading/start/stop smoke checks.
- Live release audit passed: 37,398 receipts, 102 changed payloads in 30.24 seconds.
  `evidence/live-audit.json` contains the measured snapshots. This proves changing
  deliveries, not upstream event age or unique attacks.
- Built the per-user x64 MSI and inspected its architecture, registry scope,
  shortcuts, downgrade condition and upgrade rollback sequencing. Extracted its
  cabinet and verified the SCR hash matches the fresh Windows build. No executable
  custom actions are embedded. Install/uninstall does not write screensaver/lock
  preferences; selection is a separate user-launched shortcut.
- Source pattern scan for private links, local user paths and common secrets.
  This is a limited scan, not proof that a repository contains no secrets.

## Dependency advisories

RustSec database snapshot: 40f5be6fb12ed93fc591bf4ab23b7d793b3f2239,
1,381 advisories in the recorded snapshot; the current lockfile has 310 packages.
The evidence JSON files preserve the original 0.3.0 review and its 305-package lockfile. No reported vulnerabilities found.
Three informational advisories are explicitly reviewed in `.cargo/audit.toml`:

| Advisory | Dependency | Disposition |
|---|---|---|
| RUSTSEC-2024-0429 | glib 0.18.5 | Unsound Linux GTK iterator; absent from supported Windows and macOS build graphs. |
| RUSTSEC-2024-0370 | proc-macro-error 1.0.4 | Unmaintained macro on the Linux GTK dependency branch; not used by supported builds. |
| RUSTSEC-2026-0192 | ttf-parser 0.25.1 | Unmaintained fontdue dependency; parses only the immutable bundled font, never network/user fonts. Plan migration to a maintained font stack. |

chrono (RUSTSEC-2026-0543, unmaintained) was replaced by jiff in the core and its exception removed (#119).

Both unfiltered and reviewed audit outputs are included in `evidence/`.
The CI audit fails on new, unreviewed warnings/vulnerabilities. These exceptions
must be revisited when updating dependencies or adding Linux/custom-font support.
The PR/push audit runs in `build.yml`; `.github/workflows/audit.yml` runs the same
pinned `cargo-audit 0.22.2` daily at 04:17 UTC and can be started manually.

## Hardening round for 0.8.0-rc.1

Done 15-16 November 2026 for AtlasSOC Desktop 0.8.0-rc.1 (build 15), by the coding lead (self-review; an independent
review by the documentation owner covered PR #78/#79 key handling on 15 November and found it sound for the live OTX
path, with follow-ups that were fixed or documented). Numbers are from the measured runs named below; nothing here
is a guarantee that the program is free of faults.

**Robustness of the parsers.** `crates/core/tests/osint_parsers_robustness.rs` feeds every network-facing OSINT
parser (KEV, EPSS, SANS ISC, Tor list, URLhaus JSON and CSV, ThreatFox, SSLBL, AbuseIPDB, certificate watch, OTX,
Phishing.Database, Shodan InternetDB, Spamhaus DROP and ASN-DROP, Team Cymru text, ransomware.live) with 3,000
random inputs, 6,000 mutated real-looking payloads (truncate, bit-flip, insert, repeat, NUL bytes) and eight
pathological shapes (100,000-deep nesting, a 10,000-digit number, 200,000 rows, a 2 MB line, invalid UTF-8,
100,000 NUL bytes). Deterministic seeds. Result: no panic, no hang (0.6 s in a release build).

**`unsafe` audit.** `unsafe` appears only in the C ABI used by the macOS host (`lib.rs`, `osint_ffi.rs`) and in the
Win32 host code (`windows.rs`, `soc_host.rs`, `soc_radar.rs`, `soc_config.rs`). There is none in any parser, the
network layer or the data worker. Each exported function has a documented safety contract; strings are
null-checked and UTF-8 checked, output copies are bounded by the caller's capacity, and the worker start is
wrapped in `catch_unwind`.

**Keys.** The key lives in an in-memory map in the data worker; it is not part of any page, note, cache or state
file, and is never logged. On macOS it is stored in the Keychain (service `ThreatAtlas.OSINT`), on Windows in
Credential Manager (`AtlasSOC/OSINT/...`). A source that is off, or without its key, makes no request (tested in
`nothing_is_requested_while_every_source_is_off`). Release packages are checked with
`scripts/check-test-token-absent.py`.

**Dependencies.** The CI `quality` job runs the RustSec audit with the reviewed exceptions listed above and fails
on any new advisory.

**Performance.** Frame render time (release build, 60 records per frame, Apple silicon Mac with a CI build running
at the same time): mean 11.1 ms at 1440 px width, 12.6 ms at 1920, 13.2 ms at 2560 and 14.0 ms at 3840, against a
33 ms budget. Occasional single frames took up to about 50 ms while other builds ran. Steady-state memory of the
Windows app on a partner PC: 140 MB working set (88 MB private, 344 handles, 12 threads) five minutes after start.

**Live checks on macOS with the maintainer's own keys (15 November 2026).** OTX 4 pulses; URLhaus 1,000 recent
URLs; ThreatFox 1,496 indicators in 24 hours; AbuseIPDB score 0 for the maintainer's address and 24 of 100 (28
reports, data centre) for a VPN address; certificate watch for one domain with 0 new certificates after the
baseline. Windows: ransomware.live shows 100 incidents again after the provider fixed its certificate.

**Live checks on Windows hardware (15 November 2026, partner PC, RC1 build 15 from commit 6a1dbfb).** The user's own
OTX key entered through the Credential Manager box: 4 pulses and 444 indicators. The abuse.ch key (one entry for
ThreatFox and URLhaus): ThreatFox 1,674 new indicators in 24 hours; the key was still in Credential Manager
after a restart of the app. Key removal works (zero AtlasSOC entries remained afterwards) and the sources were
switched off again. AbuseIPDB and SSLMate key entry were not repeated on Windows. The ports heading now shortens
to fit the narrow column (seen as "TOP PORTS / DSHIELD").

**CI.** All checks green on each merged pull request, including Windows x64 build, installer upgrade and
uninstall test, macOS build, Linux build, updater tests and quality (format, Clippy with warnings as errors, tests,
audit).

**Soak.** One partner Windows 11 PC (RTX 3050, 1920x1080), default sources, all other user programs closed, the 0.8.0
build 14 candidate (the RC1 build 15 differs only by the release identity, the heading stamp, in-app links and
the ports-heading fix), 74 minutes continuous (15 November 2026, 16:55:12 to 18:09:27 local, one process, no
restart): working set 140 MB after 5 minutes and 137 MB after 74 minutes, private memory 88 to 89 MB, handles 344
to 348, threads 12 to 9, CPU time 586 s in total (about 13 % of one core on average). No crash, hang or dialog.
The owner set the soak length to one hour for RC1; this is not a multi-hour soak. A second PC was assigned a
30-minute soak; it is not part of this record unless its report is added to the release record.

## Security review RC2 (part 1)

Done 24 November 2026 for AtlasSOC 0.8.0-rc.2 (release gate 2), by the coding lead. This is the author-side
review; the independent review is a separate gate item. Nothing here is a guarantee that the program is free of
faults.

**Scope.** Every change merged between tag `atlassoc-v0.8.0-rc.1` (4434b91) and `main` at 4807d49 in `crates`,
`private-beta`, `scripts`, `.github` and `Cargo.lock` (56 files, about 6,600 lines added). Order of attention:
the update path (`update_feed.rs`, `update_check.rs`, `feed_signature.rs`, Windows `soc_updates.rs` and
`soc_update.rs`), the C interfaces (`saver_ffi.rs`, `saver.rs`, `osint_ffi.rs`), settings and state files
(`saver_config.rs`, `soc_config.rs`), OSINT parsers and the worker, WinHTTP (`soc_radar.rs`), key handling
(Credential Manager in `saver_host.rs`), the scripts (`get-latest.ps1`, `get-latest.sh`, `update_feed.py`,
`update-atlassoc.ps1`, `sign-release-windows.ps1`) and the workflows. Open pull requests #143, #146, #152, #155,
#156, #157, #158 and #159 were read only for what this code depends on (#148 is already merged and in scope).

**Method.** Manual reading of the full diff with a threat model of: a network attacker, a compromised or
replayed feed, a stolen delegated signing key, a malicious GitHub release (repository write access), hostile
OSINT payloads, and a host program misusing the C interface. Each finding below was traced to the code path
that reaches it. `cargo fmt --check`, `cargo test --workspace --locked` and `cargo clippy -D warnings` pass at
4807d49.

**What holds.** The feed signature check is strict and fails closed: only R1 or an unexpired R1-signed
delegation is trusted, delegations cannot reach more than 400 days ahead, domain-separation strings stop a feed
signature from counting as a delegation, the signature line format is exact and size-capped. The check order
(trust root, signature, parse, timestamp, rollback mark) is correct, the rollback mark only moves forward and
only after acceptance, and a failed download is reported as failed, never as up to date. Download URLs taken from the feed are
compared by parsed parts (owner, repository, tag, file name), not by prefix, in Rust, Python and PowerShell
alike. The saver reads the settings file with a size cap, drops unknown source ids, validates watch domains
again in the worker, and requests nothing while every source is off. Keys come from Credential Manager
in memory only; the C key callback is bounded by its capacity and its scratch buffer is cleared.

**Findings.**

| # | Severity | Where | Failure scenario | Fix | State |
|---|---|---|---|---|---|
| 1 | Medium | `crates/windows/src/soc_update.rs:173`, `scripts/update-atlassoc.ps1:49,119` | Settings → Updates offers a version from the signed feed, but "Install with the update script" ignores that offer: the script picks the newest release from the unauthenticated GitHub releases API and checks its SHA-256 against the digest GitHub itself reports. Anyone who can publish a release (a leaked repository token) gets that file installed, a withdrawn version can be installed, and the feed signature protects nothing at install time. Windows builds are not code-signed, so nothing else catches it. | Download exactly the asset the signed feed selected, check its size and the feed's SHA-256, and stop running the script from the app. | Open at 4807d49; fixed by PR #156 (download, verify, hand over to the installer; the app no longer runs the script). **The RC2 commit must contain #156.** |
| 2 | Low | `crates/windows/src/soc_radar.rs:404` | `https_get_public` follows any redirect, including HTTPS → HTTP, so a redirecting public source could be read over plain HTTP. No key travels on this path. | Refuse redirects that leave HTTPS. | Open at 4807d49; fixed by PR #156 (hardening part). |
| 3 | Low | `scripts/get-latest.sh:57`, `scripts/get-latest.ps1:92` | The download scripts still refuse to run without `--allow-unsigned-feed` / `-AllowUnsignedFeed` and then trust the feed by HTTPS alone. Now that the feed is signed, a user of the scripts gets less protection than the apps. Explicit opt-in, and documented. | Verify `feed.json.sig` in the scripts (or point users to the apps) once signing is live. | Open, follow-up. |
| 4 | Low | `scripts/get-latest.ps1:102,126` | The feed size cap is checked after the whole response is read, and the asset download has no size cap until it completes (the size and hash are checked afterwards, so nothing unverified is kept). A hostile server can only waste bandwidth and disk until the timeout. | Stream with a byte limit. | Open, follow-up. |
| 5 | Low | `crates/core/src/feed_signature.rs:184` | Delegation expiry uses the device clock. A device whose clock is set back keeps trusting an expired (possibly stolen) delegated key. Needs both a wrong clock and control of the published feed. | Accepted by design (no trusted time source); the rollback mark limits replay. | Accepted. |
| 6 | Low | `crates/core/src/saver.rs:162-216`, `crates/core/src/saver_ffi.rs:144` | Only `ta_saver_new`, `ta_saver_frame`, `ta_saver_worker_start` and `ta_saver_worker_reload` are wrapped in `catch_unwind`. A panic inside `set_intel`, `fit*`, `drop` or `worker_stop` aborts the host process (defined behaviour since Rust 1.81, so no memory unsafety). | Wrap the remaining exports, or document abort-on-panic. | Open, follow-up. |
| 7 | Low | `crates/core/src/saver_ffi.rs:38` | Resolved API keys are plain `String`s; they are not wiped from memory on drop. Readable only by a process with the same user's rights. | Optional: a zeroising wrapper. | Accepted. |
| 8 | Low | `crates/core/src/feed.rs:271` | A hung DNS lookup leaves its detached thread running; repeated reconnects during a long DNS outage add one thread each until the lookups return. Bounded by the reconnect back-off. | None needed now; noted for soak tests. | Accepted. |
| 9 | Info | `.github/workflows/audit.yml:15`, `build.yml`, `agent-health.yml` | `actions/checkout` keeps its default `persist-credentials: true`; most jobs have read-only `contents` permission. Two have `contents: write`: the manual `publish` job (`build.yml:115`) and `agent-health.yml:16`; where they check out the repository, a write token stays on the runner until the job ends. | Add `persist-credentials: false` where no push follows. | Open, hygiene. |

No High finding. One Medium, open at 4807d49 and closed for RC2 only if the RC2 commit contains PR #156.

**Dependencies on open pull requests.**
- #156 closes findings 1 and 2. #157 is stacked on #152 and #156 and contains the same Windows change, so #156
  should merge first and #157 then reduces to its macOS part.
- #155 adds a `test-feed` Cargo feature that reads a test trust root and feed path from the environment. It is
  safe only while release builds never enable that feature; a CI check that release artefacts are built without
  it is recommended.
- #143 and #159 change `update_check.rs` and add the signing tool and the daily feed check; #152 adds the macOS
  update FFI (`update_ffi.rs`) that #157 extends. These are outside part 1 and need their own review before
  merge.
- `scripts/update_feed.py` builds a feed without `signing_keys`; the signing step in #143 has to add the
  delegation, or apps will accept only a feed signed directly with R1.

## Hardening round for 0.8.0-rc.2 (Gate 3)

Candidate `1b52a34` (threat-atlas `main`, 26 Nov 2026). The scope is everything since `atlassoc-v0.8.0-rc.1` (`4434b91`).

**Numbers, before (rc.1) and after (rc.2 candidate):**

| Measure | rc.1 | rc.2 candidate | Note |
|---|---|---|---|
| Workspace tests (`cargo test --workspace`) | 185 | 284 (+6 in the robustness PR) | updater, download/verify, time zones, test-feed confinement |
| Update parser fuzz/property tests | – | 6 (random, mutated, pathological; 3 properties) | `crates/core/tests/update_parsers_robustness.rs` |
| macOS desktop app, 1 h soak, memory (RSS) | – | 162 → 101 MB, last-30-min median 115 MB, falling | `b7527a5`, M1, macOS 27.2.1 |
| macOS desktop app, 1 h soak, CPU (% of one core) | – | median 37 %; 63–97 % for about 8 min after start, then 30–46 % | the same run |
| Windows desktop app, soak (private memory) | – | peak 51.7 MB, stable, single instance; run cut short and passed on Robert's (owner) order, 26 Nov | `b7527a5`, Windows 11 Pro 26300; memory rule: never over 100 MB, under 70 MB fine, ~55 MB average |

**Windows note:** the Windows soak and acceptance ran on Billy's build of `b7527a5`. The release commit adds only tao 0.37.3, webpki-roots 1.0.12 and docs. CI on the release commit runs the Windows offline launch test and the installer install/upgrade/uninstall test on its own Windows build. Not run by hand: the menus (no input injection on the test host), an upgrade from the RC1 package, and Windows 10.

**CPU note:** an earlier run on `cbb9b28` held 70–100 % for 30 minutes and recovered on its own. The `b7527a5` run showed only an 8-minute peak after start. Both recover without intervention and memory does not grow. This is recorded as ⚠️ for a targeted look at Realtime arc pacing (PR 146) after RC2. It does not block.

**Unsafe audit:** 31 lines containing `unsafe` were added since rc.1.
- **FFI entry points** (`saver.rs`, `saver_ffi.rs`, `update_ffi.rs`): every entry point accepts null and documents its `# Safety` contract. Byte and string inputs are length-bounded or checked as UTF-8.
- **Windows** (`soc_host.rs`, `soc_update.rs`): Win32 calls (`MessageBoxW`, `IsWindow`, menus) only on handles the app created or checked.
- **Counting allocator:** in `examples/saver_memory.rs` only, never shipped.
- **Open:** Low finding 6 from part 1, `catch_unwind` missing on some saver FFI entry points. A follow-up; it does not block.

**Dependencies:** webpki-roots 1.0.12 and tao 0.37.3 merged into the candidate (Robert: no old frameworks).
- The RustSec audit and Dependabot are green.
- The one open Dependabot alert (glib, medium) is not compiled for any target: `cargo tree -i glib --target <t>` is empty for Windows, macOS (arm64 and x86_64) and Linux. It is only a Linux GTK lockfile entry of tao.
- `THIRD-PARTY-NOTICES.txt` is regenerated for the new versions.

**Security sub-tasks** (workflow 3a): every RC2 work package ✅ or ⚠️, with no 🚨 open (#101).

## Still requiring acceptance testing

- MSI installation, upgrade, rollback, user-launched setup and uninstallation on
  Windows beyond the CI lifecycle test. GitHub Actions has passed MSI installation,
  shortcut validation, preference preservation and uninstallation; signed upgrades,
  rollback failure injection and interactive user-launched setup still need acceptance.
- Latest-release interactive GUI behavior on both platforms after these changes. The owner
  confirmed the prior Windows and repaired macOS versions work. Those confirmations
  do not establish acceptance of this new release candidate.
- Actual idle activation, lock/sign-in transitions, multiple monitors, Intel Mac
  hardware, offline/resume behavior and extended memory/CPU soak testing.
- Provider authorization/terms for public distribution. Code licensing does not
  license the upstream feed. No automatic feed-freshness authenticity proof exists.
- DNS resolution is bounded to 5 s and the feed worker stops within 100 ms while DNS is
  pending (0.8.0-rc.2); a blocked resolver thread may still finish in the background.
- macOS releases are Developer ID signed and notarised (team 7NXP86HMVH); local
  development builds are ad-hoc. Windows builds stay unsigned (Robert, 24 Nov 2026); the
  update path verifies size and SHA-256 against the signed feed instead.

Re-run these checks after dependencies or implementation change. Keep prior
known-working releases available until the candidate passes platform acceptance.
