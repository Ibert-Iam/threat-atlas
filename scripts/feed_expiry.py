#!/usr/bin/env python3
"""Daily feed check helper: when do the apps stop accepting the published feed?

    feed_expiry.py feed.json feed.json.sig [--today YYYY-MM-DD] [--warn-days 21]

Prints the latest expiry of the delegations for the key that signed the feed; other keys in the feed do not
count. Exit 0 when it is more than --warn-days away, 3 when it is within that window (renew with Robert's R1
key and sign again), 4 when that key has no delegation valid today. A feed signed directly by the R1 key also
gives 4. Signatures are not checked here; verify_feed does that. Standard library only.
"""
import argparse
import datetime as dt
import hashlib
import json
import sys


def key_id(key_hex):
    return hashlib.sha256(bytes.fromhex(key_hex)).hexdigest()[:16]


def latest_expiry(feed, signer, today):
    days = []
    for entry in feed.get("signing_keys") or []:
        try:
            if key_id(entry["key"]) != signer:
                continue
            day = dt.date.fromisoformat(entry["expires"])
        except (KeyError, TypeError, ValueError):
            continue
        if day >= today:
            days.append(day)
    return max(days) if days else None


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("feed")
    ap.add_argument("signature")
    ap.add_argument("--today", type=dt.date.fromisoformat, default=dt.datetime.now(dt.timezone.utc).date())
    ap.add_argument("--warn-days", type=int, default=21)
    args = ap.parse_args(argv)
    with open(args.feed, encoding="utf-8") as handle:
        feed = json.load(handle)
    with open(args.signature, encoding="utf-8") as handle:
        fields = handle.read().split()
    if len(fields) != 3 or fields[0] != "ed25519":
        print("FAIL the signature file does not name a signing key")
        return 4
    signer = fields[1]
    expiry = latest_expiry(feed, signer, args.today)
    if expiry is None:
        print(f"FAIL signing key {signer} has no delegation valid today; renew it with the R1 key and sign again")
        return 4
    left = (expiry - args.today).days
    if left <= args.warn_days:
        print(f"WARN the delegation of signing key {signer} expires {expiry} ({left} days); "
              "renew it with the R1 key and sign again")
        return 3
    print(f"OK delegation of signing key {signer} valid until {expiry} ({left} days)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
