#!/usr/bin/env python3
"""Tests for feed_expiry.py (run: python3 -I scripts/test-feed-expiry.py)."""
import contextlib
import io
import json
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import feed_expiry as fe  # noqa: E402

KEY, OTHER = "11" * 32, "22" * 32


def entry(expires, key=KEY):
    return {"key": key, "expires": expires}


class Expiry(unittest.TestCase):
    def run_on(self, keys, today, signature=None):
        if signature is None:
            signature = f"ed25519 {fe.key_id(KEY)} {'0' * 128}\n"
        with tempfile.TemporaryDirectory() as folder, contextlib.redirect_stdout(io.StringIO()):
            feed, sig = pathlib.Path(folder, "feed.json"), pathlib.Path(folder, "feed.json.sig")
            feed.write_text(json.dumps({"signing_keys": keys}))
            sig.write_text(signature)
            return fe.main([str(feed), str(sig), "--today", today])

    def test_key_id_matches_the_apps(self):
        # The published signing key and its id, as in docs/feed-signing-delegations.json and feed_signature.rs.
        root = pathlib.Path(__file__).resolve().parent.parent
        published = json.loads((root / "docs" / "feed-signing-delegations.json").read_text())
        self.assertIn("524c828be6e1600b", [fe.key_id(k["key"]) for k in published["signing_keys"]])

    def test_far_expiry_is_ok(self):
        self.assertEqual(self.run_on([entry("2027-02-21")], "2026-11-24"), 0)

    def test_warns_three_weeks_ahead(self):
        self.assertEqual(self.run_on([entry("2027-02-21")], "2027-01-31"), 3)
        self.assertEqual(self.run_on([entry("2027-02-21")], "2027-01-30"), 0)

    def test_valid_through_its_last_day_then_fails(self):
        self.assertEqual(self.run_on([entry("2027-02-21")], "2027-02-21"), 3)
        self.assertEqual(self.run_on([entry("2027-02-21")], "2027-02-22"), 4)

    def test_missing_or_malformed_fails(self):
        for keys in ([], [entry("garbage")], [entry("2027-02-21", "zz")], [{"expires": "2027-02-21"}], ["x"]):
            with self.subTest(keys=keys):
                self.assertEqual(self.run_on(keys, "2026-11-24"), 4)

    def test_latest_delegation_of_the_signing_key_counts(self):
        self.assertEqual(self.run_on([entry("2026-12-01"), entry("2027-05-01")], "2026-11-24"), 0)

    def test_another_key_does_not_hide_the_signing_keys_expiry(self):
        keys = [entry("2026-12-01"), entry("2028-01-01", OTHER)]
        self.assertEqual(self.run_on(keys, "2026-11-24"), 3)
        self.assertEqual(self.run_on(keys, "2026-12-02"), 4)

    def test_signature_without_a_key_fails(self):
        for signature in ("", "ed25519", f"rsa {fe.key_id(KEY)} 00", f"ed25519 {fe.key_id(KEY)} 00 extra"):
            with self.subTest(signature=signature):
                self.assertEqual(self.run_on([entry("2027-02-21")], "2026-11-24", signature), 4)


if __name__ == "__main__":
    unittest.main()
