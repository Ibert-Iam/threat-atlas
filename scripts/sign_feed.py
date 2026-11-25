#!/usr/bin/env python3
"""Sign the update feed (WP1, docs/UPDATE-CHANNELS.md section 4 and section 10, decision 2).

    python3 -I scripts/sign_feed.py FEED.json --out-dir DIR [--delegations docs/feed-signing-delegations.json]

1. Validates FEED.json with scripts/update_feed.py (hashes, URLs, channel pointers, withdrawn tags).
2. Requires a `generated_at` field; its exact rules (timezone, at most 24 h ahead) are checked by the apps' own
   acceptance path in step 5, not by a looser Python parser.
3. Copies the unexpired delegations into the feed as `signing_keys` and refuses to sign when none is valid;
   warns when the newest one expires within RENEW_DAYS.
4. Writes feed.json in a fresh staging folder next to DIR and asks the publisher's signer for feed.json.sig. The signer is the
   Keychain-backed tool on the publisher's Mac (ATLAS_FEED_SIGNER, default ~/.atlas-feed-signing/atlas-feed-key);
   no key material passes through this script.
5. Verifies the staged pair with the apps' own acceptance path (`cargo run --example verify_feed`, which calls
   `update_check::accept_feed`). Only after full success does it replace DIR/feed.json and DIR/feed.json.sig;
   on any failure (signer or cargo missing, non-zero exit, rejected feed) the last good pair in DIR is untouched.
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
import shutil
import subprocess
import sys
import tempfile

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
    if not isinstance(feed.get("generated_at"), str):
        raise ValueError("feed has no generated_at (its format is checked by the apps' verifier)")
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
    stage = pathlib.Path(tempfile.mkdtemp(prefix=".sign-staging-", dir=out))
    keep_stage = False
    try:
        staged_feed, staged_sig = stage / "feed.json", stage / "feed.json.sig"
        staged_feed.write_text(json.dumps(signed, indent=2, ensure_ascii=False) + "\n")
        ok, detail = run_signer(staged_feed)
        if not ok:
            print("REFUSED: signer failed: " + detail, file=sys.stderr)
            return 1
        staged_sig.write_text(detail + "\n")
        ok, detail = run_verifier(staged_feed, staged_sig)
        if not ok:
            print("REFUSED: the apps would reject this feed: " + detail, file=sys.stderr)
            return 1
        # Full success: replace the published pair. The signature goes last so a reader never sees a new
        # signature next to an old feed; if either step fails, the last good pair is put back.
        try:
            replace_pair(staged_feed, staged_sig, out, stage)
        except OSError as error:
            print("REFUSED: could not replace the published pair (the last good pair is in place): " + str(error),
                  file=sys.stderr)
            return 1
        except RestoreFailed as error:
            keep_stage = True
            print(f"REFUSED: could not replace the published pair, and could not put the last good pair back: "
                  f"{error}. Its copy is in {stage} (old-feed.json, old-feed.json.sig); do not publish {out}.",
                  file=sys.stderr)
            return 1
    finally:
        if not keep_stage:
            shutil.rmtree(stage, ignore_errors=True)

    feed_path, sig_path = out / "feed.json", out / "feed.json.sig"
    digest = hashlib.sha256(feed_path.read_bytes()).hexdigest()
    key_id = sig_path.read_text().split()[1]
    when = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    print(f"SIGNED feed sha256={digest} generated_at={signed['generated_at']} key={key_id} at={when}")
    print(detail)
    return 0


class RestoreFailed(Exception):
    """The old pair could not be put back; its only copy is in the staging folder."""


def replace_pair(new_feed, new_sig, out, stage):
    """Moves the new feed and signature into OUT, or leaves OUT as it was. The old pair is copied (not moved)
    into STAGE first, so a failure there touches nothing. A failure or Ctrl-C while the new files move in puts
    the old pair back; when that fails too, RestoreFailed is raised and STAGE must be kept. A kill -9 between
    the two moves is not covered: the old pair is then in the staging folder."""
    backups = []
    for target in (out / "feed.json", out / "feed.json.sig"):
        backup = stage / ("old-" + target.name)
        backups.append((target, backup if target.exists() else None))
        if target.exists():
            shutil.copy2(target, backup)
    try:
        os.replace(new_feed, out / "feed.json")
        os.replace(new_sig, out / "feed.json.sig")
    except BaseException as cause:
        problems = []
        for target, backup in backups:
            try:
                if backup is not None:
                    os.replace(backup, target)
                elif target.exists():
                    target.unlink()
            except BaseException as error:  # also a second Ctrl-C: the backup must survive it
                problems.append(str(error) or type(error).__name__)
        if problems:
            raise RestoreFailed("; ".join(problems)) from cause
        raise


def run_signer(feed_path):
    """(ok, signature line or error). Never raises: a missing signer is a refusal, not a crash."""
    signer = os.environ.get("ATLAS_FEED_SIGNER", str(DEFAULT_SIGNER))
    try:
        result = subprocess.run([signer, "sign-feed", str(feed_path)], capture_output=True, text=True)
    except OSError as error:
        return False, f"cannot run signer: {error}"
    line = result.stdout.strip()
    if result.returncode != 0 or not line.startswith("ed25519 "):
        return False, (result.stderr.strip() or "no signature line")
    return True, line


def run_verifier(feed_path, sig_path):
    """(ok, verifier output). The apps' own acceptance path; never raises."""
    try:
        check = subprocess.run(
            ["cargo", "run", "-q", "--locked", "-p", "threat-atlas-core", "--example", "verify_feed", "--",
             str(feed_path), str(sig_path)],
            cwd=ROOT, capture_output=True, text=True)
    except OSError as error:
        return False, f"cannot run verifier: {error}"
    return check.returncode == 0, (check.stdout if check.returncode == 0 else (check.stderr or check.stdout)).strip()

if __name__ == "__main__":
    sys.exit(main())
