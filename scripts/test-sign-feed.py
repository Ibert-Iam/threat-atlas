#!/usr/bin/env python3
"""Offline tests for scripts/sign_feed.py: refusal rules and delegation handling (no signing, no network)."""
import contextlib
import datetime as dt
import importlib.util
import io
import json
import os
import pathlib
import tempfile
import unittest
from unittest import mock

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



class OutputPreservationTests(unittest.TestCase):
    """MAC review of #143: a failed run must never destroy the last accepted pair."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = pathlib.Path(self.tmp.name)
        self.out = root / "out"
        self.out.mkdir()
        (self.out / "feed.json").write_text("LAST GOOD FEED")
        (self.out / "feed.json.sig").write_text("LAST GOOD SIG")
        self.feed = root / "unsigned.json"
        self.feed.write_text(json.dumps(SAMPLE))
        far = {"signing_keys": [dict(DELEGATIONS["signing_keys"][0], expires="2099-12-31")]}
        self.deleg = root / "deleg.json"
        self.deleg.write_text(json.dumps(far))

    def tearDown(self):
        self.tmp.cleanup()

    def run_main(self):
        return sf.main([str(self.feed), "--out-dir", str(self.out), "--delegations", str(self.deleg)])

    def assert_untouched(self):
        self.assertEqual((self.out / "feed.json").read_text(), "LAST GOOD FEED")
        self.assertEqual((self.out / "feed.json.sig").read_text(), "LAST GOOD SIG")
        self.assertEqual(sorted(p.name for p in self.out.iterdir()), ["feed.json", "feed.json.sig"],
                         "no staging folder left behind")

    def test_signer_failure_keeps_last_pair(self):
        with mock.patch.object(sf, "run_signer", return_value=(False, "boom")):
            self.assertEqual(self.run_main(), 1)
        self.assert_untouched()

    def test_missing_signer_executable_keeps_last_pair(self):
        with mock.patch.dict(os.environ, {"ATLAS_FEED_SIGNER": str(pathlib.Path(self.tmp.name) / "nope")}):
            self.assertEqual(self.run_main(), 1)
        self.assert_untouched()

    def test_verifier_rejection_keeps_last_pair(self):
        with mock.patch.object(sf, "run_signer", return_value=(True, "ed25519 0000000000000000 " + "0" * 128)), \
             mock.patch.object(sf, "run_verifier", return_value=(False, "FAIL FromTheFuture")):
            self.assertEqual(self.run_main(), 1)
        self.assert_untouched()

    def test_success_replaces_both_and_cleans_staging(self):
        line = "ed25519 0000000000000000 " + "0" * 128
        with mock.patch.object(sf, "run_signer", return_value=(True, line)), \
             mock.patch.object(sf, "run_verifier", return_value=(True, "OK")):
            self.assertEqual(self.run_main(), 0)
        self.assertEqual((self.out / "feed.json.sig").read_text(), line + "\n")
        self.assertIn("signing_keys", json.loads((self.out / "feed.json").read_text()))
        self.assertEqual(sorted(p.name for p in self.out.iterdir()), ["feed.json", "feed.json.sig"])

    def test_failure_on_second_replace_restores_last_pair(self):
        line = "ed25519 0000000000000000 " + "0" * 128
        real = os.replace
        def flaky(src, dst):
            if str(dst).endswith("feed.json.sig") and "LAST GOOD" not in pathlib.Path(src).read_text():
                raise OSError("disk full")
            return real(src, dst)
        with mock.patch.object(sf, "run_signer", return_value=(True, line)), \
             mock.patch.object(sf, "run_verifier", return_value=(True, "OK")), \
             mock.patch.object(sf.os, "replace", side_effect=flaky):
            self.assertEqual(self.run_main(), 1)
        self.assert_untouched()


    def run_failing(self, error, copy=None, move=()):
        """Runs main with the given copy number and move numbers raising `error`; returns stderr."""
        line = "ed25519 0000000000000000 " + "0" * 128
        real = {"copy2": sf.shutil.copy2, "replace": os.replace}
        count = {"copy2": 0, "replace": 0}

        def flaky(name, failing):
            def call(src, dst):
                count[name] += 1
                if count[name] in failing:
                    raise error
                return real[name](src, dst)
            return call
        stderr = io.StringIO()
        with mock.patch.object(sf, "run_signer", return_value=(True, line)), \
             mock.patch.object(sf, "run_verifier", return_value=(True, "OK")), \
             mock.patch.object(sf.shutil, "copy2", side_effect=flaky("copy2", (copy,))), \
             mock.patch.object(sf.os, "replace", side_effect=flaky("replace", move)), \
             contextlib.redirect_stderr(stderr):
            if isinstance(error, OSError):
                self.assertEqual(self.run_main(), 1)
            else:
                with self.assertRaises(type(error)):
                    self.run_main()
        return stderr.getvalue()

    def test_failure_or_interrupt_at_every_step_keeps_the_last_pair(self):
        for error in (OSError("disk full"), KeyboardInterrupt()):
            for step in ({"copy": 1}, {"copy": 2}, {"move": (1,)}, {"move": (2,)}):
                with self.subTest(error=error, step=step):
                    self.run_failing(error, **step)
                    self.assert_untouched()

    def test_failure_without_an_old_pair_leaves_nothing_behind(self):
        for old in ((), ("feed.json",), ("feed.json.sig",)):
            for step in (1, 2):
                with self.subTest(old=old, step=step):
                    for name in ("feed.json", "feed.json.sig"):
                        (self.out / name).unlink(missing_ok=True)
                    for name in old:
                        (self.out / name).write_text("OLD")
                    self.run_failing(OSError("disk full"), move=(step,))
                    self.assertEqual({p.name: p.read_text() for p in self.out.iterdir()}, {n: "OLD" for n in old})

    def test_a_second_interrupt_during_the_restore_keeps_the_backup(self):
        line = "ed25519 0000000000000000 " + "0" * 128
        real, moves = os.replace, []

        def interrupted(src, dst):
            moves.append(dst)
            if len(moves) in (2, 3):
                raise KeyboardInterrupt
            return real(src, dst)
        with mock.patch.object(sf, "run_signer", return_value=(True, line)), \
             mock.patch.object(sf, "run_verifier", return_value=(True, "OK")), \
             mock.patch.object(sf.os, "replace", side_effect=interrupted), \
             contextlib.redirect_stderr(io.StringIO()) as stderr:
            self.assertEqual(self.run_main(), 1)
        [stage] = [p for p in self.out.iterdir() if p.is_dir()]
        self.assertEqual((stage / "old-feed.json").read_text(), "LAST GOOD FEED")
        self.assertIn("KeyboardInterrupt", stderr.getvalue())

    def test_a_failed_restore_keeps_the_backup_and_says_where(self):
        for failing, left in (((2, 3), "old-feed.json"), ((2, 4), "old-feed.json.sig")):
            with self.subTest(failing=failing):
                (self.out / "feed.json").write_text("LAST GOOD FEED")
                (self.out / "feed.json.sig").write_text("LAST GOOD SIG")
                stderr = self.run_failing(OSError("disk full"), move=failing)
                [stage] = [p for p in self.out.iterdir() if p.is_dir()]
                self.assertIn(str(stage), stderr)
                self.assertNotIn("is in place", stderr)
                self.assertTrue((stage / left).read_text().startswith("LAST GOOD"))
                sf.shutil.rmtree(stage)


if __name__ == "__main__":
    unittest.main()
