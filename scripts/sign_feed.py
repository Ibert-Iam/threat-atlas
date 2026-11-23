#!/usr/bin/env python3
"""Sign the update feed (WP1, docs/UPDATE-CHANNELS.md section 4 and section 10, decision 2).

    python3 -I scripts/sign_feed.py FEED.json --out-dir DIR [--delegations docs/feed-signing-delegations.json]

1. Validates FEED.json with scripts/update_feed.py (hashes, URLs, channel pointers, withdrawn tags).
2. Requires a `generated_at` timestamp (the apps' rollback guard uses it).
3. Copies the unexpired delegations into the feed as `signing_keys` and refuses to sign when none is valid;
   warns when the newest one expires within RENEW_DAYS.
4. Writes DIR/feed.json and asks the publisher's signer for DIR/feed.json.sig. The signer is the
   Keychain-backed tool on the publisher's Mac (ATLAS_FEED_SIGNER, default ~/.atlas-feed-signing/atlas-feed-key);
   no key material passes through this script.
5. Verifies the result with the apps' own Rust code (`cargo run --example verify_feed`) and deletes both
   outputs if that fails.
6. Prints a log line (feed SHA-256, time, key id) for the publisher's private handover.

Standard library only. Signs only Threat Atlas / AtlasSOC feed.json, never anything else.
"""
import argparse
import datetime as dt
import hashlib
import importlib.util
import json
import os
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
RENEW_DAYS = 21
DEFAULT_SIGNER = pathlib.Path.home() / ".atlas-feed-signing" / "atlas-feed-key"

_spec = importlib.util.spec_from_file_location("update_feed", pathlib.Path(__file__).with_name("update_feed.py"))
update_feed = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(update_feed)


def usable_delegations(delegations, today):
    """Unexpired entries, without the human 'note'. Format checks are left to the apps' verifier."""
    keep = []
    for entry in delegations.get("signing_keys", []):
        expires = dt.date.fromisoformat(entry["expires"])
        if expires >= today:
            keep.append({k: entry[k] for k in ("key", "expires", "recovery_signature")})
    return keep


def prepare(feed, delegations, today):
    """Return (feed with signing_keys, warnings). Raises ValueError when the feed must not be signed."""
    errors = update_feed.validate(feed)
    if errors:
        raise ValueError("feed does not validate: " + "; ".join(errors))
    stamp = feed.get("generated_at")
    try:
        dt.datetime.fromisoformat(str(stamp).replace("Z", "+00:00"))
    except ValueError:
        raise ValueError("feed has no valid generated_at") from None
    keys = usable_delegations(delegations, today)
    if not keys:
        raise ValueError("no unexpired delegation: the owner must sign a new one first")
    warnings = []
    newest = max(dt.date.fromisoformat(k["expires"]) for k in keys)
    if (newest - today).days <= RENEW_DAYS:
        warnings.append(f"delegation expires {newest}: prepare the renewal for the owner now")
    signed = dict(feed)
    signed["signing_keys"] = keys
    return signed, warnings


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("feed")
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--delegations", default=str(ROOT / "docs" / "feed-signing-delegations.json"))
    args = ap.parse_args(argv)

    today = dt.datetime.now(dt.timezone.utc).date()
    feed = json.loads(pathlib.Path(args.feed).read_text())
    delegations = json.loads(pathlib.Path(args.delegations).read_text())
    try:
        signed, warnings = prepare(feed, delegations, today)
    except ValueError as error:
        print(f"REFUSED: {error}", file=sys.stderr)
        return 1
    for warning in warnings:
        print(f"WARNING: {warning}", file=sys.stderr)

    out = pathlib.Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    feed_path, sig_path = out / "feed.json", out / "feed.json.sig"
    feed_path.write_text(json.dumps(signed, indent=2, ensure_ascii=False) + "\n")

    signer = os.environ.get("ATLAS_FEED_SIGNER", str(DEFAULT_SIGNER))
    result = subprocess.run([signer, "sign-feed", str(feed_path)], capture_output=True, text=True)
    if result.returncode != 0 or not result.stdout.startswith("ed25519 "):
        feed_path.unlink(missing_ok=True)
        print("REFUSED: signer failed: " + result.stderr.strip(), file=sys.stderr)
        return 1
    sig_path.write_text(result.stdout.strip() + "\n")

    check = subprocess.run(
        ["cargo", "run", "-q", "--locked", "-p", "threat-atlas-core", "--example", "verify_feed", "--",
         str(feed_path), str(sig_path)],
        cwd=ROOT, capture_output=True, text=True)
    if check.returncode != 0:
        feed_path.unlink(missing_ok=True)
        sig_path.unlink(missing_ok=True)
        print("REFUSED: the apps would reject this feed: " + (check.stderr or check.stdout).strip(), file=sys.stderr)
        return 1

    digest = hashlib.sha256(feed_path.read_bytes()).hexdigest()
    key_id = sig_path.read_text().split()[1]
    when = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    print(f"SIGNED feed sha256={digest} generated_at={signed['generated_at']} key={key_id} at={when}")
    print(check.stdout.strip())
    return 0


if __name__ == "__main__":
    sys.exit(main())
