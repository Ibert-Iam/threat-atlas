#!/usr/bin/env python3
"""Offline tests for scripts/sign_feed.py: refusal rules and delegation handling (no signing, no network)."""
import datetime as dt
import importlib.util
import json
import pathlib
import unittest

HERE = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("sign_feed", HERE / "sign_feed.py")
sf = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sf)

SAMPLE = json.loads((HERE.parent / "crates" / "core" / "testdata" / "update-feed-sample.json").read_text())
DELEGATIONS = json.loads((HERE.parent / "docs" / "feed-signing-delegations.json").read_text())
TODAY = dt.date(2026, 11, 23)


class SignFeedTests(unittest.TestCase):
    def test_committed_delegation_is_well_formed(self):
        [entry] = DELEGATIONS["signing_keys"]
        self.assertEqual(len(entry["key"]), 64)
        self.assertEqual(len(entry["recovery_signature"]), 128)
        dt.date.fromisoformat(entry["expires"])

    def test_valid_feed_gets_signing_keys_without_notes(self):
        signed, warnings = sf.prepare(SAMPLE, DELEGATIONS, TODAY)
        self.assertEqual(warnings, [])
        self.assertEqual(len(signed["signing_keys"]), 1)
        self.assertNotIn("note", signed["signing_keys"][0])
        self.assertNotIn("signing_keys", SAMPLE, "the input feed is not modified")

    def test_expired_delegations_are_dropped_and_none_left_refuses(self):
        later = dt.date(2027, 2, 22)
        self.assertEqual(sf.usable_delegations(DELEGATIONS, later), [])
        with self.assertRaisesRegex(ValueError, "no unexpired delegation"):
            sf.prepare(SAMPLE, DELEGATIONS, later)
        # The expiry day itself still counts.
        self.assertEqual(len(sf.usable_delegations(DELEGATIONS, dt.date(2027, 2, 21))), 1)

    def test_renewal_warning_three_weeks_ahead(self):
        _, warnings = sf.prepare(SAMPLE, DELEGATIONS, dt.date(2027, 2, 1))
        self.assertTrue(any("renewal" in w for w in warnings))

    def test_invalid_or_unstamped_feeds_are_refused(self):
        broken = dict(SAMPLE, schema_version=99)
        with self.assertRaisesRegex(ValueError, "does not validate"):
            sf.prepare(broken, DELEGATIONS, TODAY)
        unstamped = {k: v for k, v in SAMPLE.items() if k != "generated_at"}
        with self.assertRaisesRegex(ValueError, "generated_at"):
            sf.prepare(unstamped, DELEGATIONS, TODAY)


if __name__ == "__main__":
    unittest.main()
