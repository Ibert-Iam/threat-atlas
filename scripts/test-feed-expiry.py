#!/usr/bin/env python3
"""Tests for feed_expiry.py (run: python3 -I scripts/test-feed-expiry.py)."""
import json
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import feed_expiry as fe  # noqa: E402


class Expiry(unittest.TestCase):
    def run_on(self, keys, today):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump({"signing_keys": keys}, f)
        return fe.main([f.name, "--today", today])

    def test_far_expiry_is_ok(self):
        self.assertEqual(self.run_on([{"expires": "2027-02-21"}], "2026-11-24"), 0)

    def test_warns_three_weeks_ahead(self):
        self.assertEqual(self.run_on([{"expires": "2027-02-21"}], "2027-01-31"), 3)
        self.assertEqual(self.run_on([{"expires": "2027-02-21"}], "2027-01-30"), 0)

    def test_expired_or_missing_fails(self):
        self.assertEqual(self.run_on([{"expires": "2027-02-21"}], "2027-02-22"), 4)
        self.assertEqual(self.run_on([], "2026-11-24"), 4)
        self.assertEqual(self.run_on([{"expires": "garbage"}], "2026-11-24"), 4)

    def test_latest_valid_delegation_counts(self):
        keys = [{"expires": "2026-12-01"}, {"expires": "2027-05-01"}]
        self.assertEqual(self.run_on(keys, "2026-11-24"), 0)


if __name__ == "__main__":
    unittest.main()
