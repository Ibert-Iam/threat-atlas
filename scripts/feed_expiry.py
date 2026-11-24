#!/usr/bin/env python3
"""Daily feed check helper: when does the published feed stop being signable?

    feed_expiry.py feed.json [--today YYYY-MM-DD] [--warn-days 21]

Prints the latest expiry of the signing-key delegations in the feed. Exit 0 when it is more than
--warn-days away, 3 when it is within that window (renew with Robert's R1 key), 4 when no delegation is
valid today (the next signed feed would be refused). Standard library only.
"""
import argparse
import datetime as dt
import json
import sys


def latest_expiry(feed, today):
    days = []
    for entry in feed.get("signing_keys") or []:
        try:
            day = dt.date.fromisoformat(entry["expires"])
        except (KeyError, TypeError, ValueError):
            continue
        if day >= today:
            days.append(day)
    return max(days) if days else None


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("feed")
    ap.add_argument("--today", type=dt.date.fromisoformat, default=dt.datetime.now(dt.timezone.utc).date())
    ap.add_argument("--warn-days", type=int, default=21)
    args = ap.parse_args(argv)
    with open(args.feed, encoding="utf-8") as handle:
        feed = json.load(handle)
    expiry = latest_expiry(feed, args.today)
    if expiry is None:
        print("FAIL no signing-key delegation is valid today; renew it with the R1 key before the next feed")
        return 4
    left = (expiry - args.today).days
    if left <= args.warn_days:
        print(f"WARN the signing-key delegation expires {expiry} ({left} days); renew it with the R1 key")
        return 3
    print(f"OK delegation valid until {expiry} ({left} days)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
