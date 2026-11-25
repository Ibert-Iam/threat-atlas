#!/usr/bin/env python3
"""Offline tests for scripts/update_feed.py: channel resolution, fallback, withdrawal, validation."""
import copy
import importlib.util
import json
import pathlib
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("update_feed", pathlib.Path(__file__).with_name("update_feed.py"))
uf = importlib.util.module_from_spec(spec)
spec.loader.exec_module(uf)

H = "a" * 64


def rel(tag, pre=False, draft=False, assets=("Setup-X.exe",), when="2026-11-01T00:00:00Z"):
    ver = tag.split("-v", 1)[-1] if tag.startswith("atlassoc") else tag[1:]
    return {"tag_name": tag, "draft": draft, "prerelease": pre, "published_at": when,
            "assets": [{"name": f"AtlasSOC-{n.replace('X', ver)}", "size": 100, "digest": "sha256:" + H}
                       for n in assets]}


RELEASES = [
    rel("atlassoc-v0.7.0"),
    rel("atlassoc-v0.8.0-rc.1", pre=True),
    rel("atlassoc-v0.8.0-rc.2", pre=True),
    rel("atlassoc-v0.8.0-beta.1", pre=True),
    rel("atlassoc-v0.9.0-beta.1", pre=True),
    rel("atlassoc-v0.9.0-rc.9", pre=True, draft=True),  # drafts are ignored
    rel("v0.4.8", assets=("Windows-vX.zip",)),           # another product's tag
]


def feed(withdrawn=()):
    return uf.build_feed(RELEASES, {"products": {"atlassoc": {"withdrawn": list(withdrawn)}}}, now="2026-11-16T00:00:00Z")


def ver(block, channel, platform=None):
    r = uf.resolve(block, channel, platform)
    return r and r["version"]


class VersionTests(unittest.TestCase):
    def test_precedence(self):
        order = ["0.8.0-beta.1", "0.8.0-beta.2", "0.8.0-rc.1", "0.8.0", "0.8.1-beta.1", "0.10.0"]
        self.assertEqual(sorted(order, key=uf.parse_version), order)

    def test_rejects_bad_versions(self):
        for bad in ("1.0", "v1.0.0", "1.0.0-alpha.1", "1.0.0-rc", "1.0.0+x", "01.0.0", "1.00.0", "1.0.01", "0.8.0-rc.01"):
            with self.assertRaises(ValueError):
                uf.parse_version(bad)


class ResolutionTests(unittest.TestCase):
    def setUp(self):
        self.block = feed()["products"]["atlassoc"]

    def test_stable_only_stable(self):
        self.assertEqual(ver(self.block, "stable"), "0.7.0")

    def test_rc_prefers_newest_of_rc_and_stable(self):
        self.assertEqual(ver(self.block, "rc"), "0.8.0-rc.2")

    def test_beta_prefers_newest_of_all_three(self):
        self.assertEqual(ver(self.block, "beta"), "0.9.0-beta.1")

    def test_newer_stable_beats_old_rc_and_beta(self):
        releases = RELEASES + [rel("atlassoc-v1.0.0")]
        block = uf.build_feed(releases, now="x")["products"]["atlassoc"]
        for ch in uf.CHANNELS:
            self.assertEqual(ver(block, ch), "1.0.0")

    def test_drafts_and_other_products_ignored(self):
        versions = [r["version"] for r in self.block["releases"]]
        self.assertNotIn("0.9.0-rc.9", versions)
        self.assertEqual(uf.build_feed(RELEASES, now="x")["products"]["screensaver"]["channels"]["stable"]["version"], "0.4.8")

    def test_pointers_match_channel_newest(self):
        ch = self.block["channels"]
        self.assertEqual((ch["stable"]["version"], ch["rc"]["version"], ch["beta"]["version"]),
                         ("0.7.0", "0.8.0-rc.2", "0.9.0-beta.1"))

    def test_platform_filter_skips_releases_without_the_platform(self):
        releases = [rel("atlassoc-v0.7.0"), rel("atlassoc-v0.8.0-rc.1", pre=True, assets=("macOS-X.zip",))]
        block = uf.build_feed(releases, now="x")["products"]["atlassoc"]
        self.assertEqual(ver(block, "rc", "windows-x64"), "0.7.0")
        self.assertEqual(ver(block, "rc", "macos-universal"), "0.8.0-rc.1")


class KindFallbackTests(unittest.TestCase):
    def test_kind_filter_falls_back_to_an_older_release_that_has_the_file(self):
        releases = [rel("atlassoc-v0.7.0"), rel("atlassoc-v0.8.0-rc.1", pre=True, assets=("Windows-X.zip",))]
        block = uf.build_feed(releases, now="x")["products"]["atlassoc"]
        self.assertEqual(ver(block, "rc", "windows-x64"), "0.8.0-rc.1")
        self.assertEqual(uf.resolve(block, "rc", "windows-x64", "installer")["version"], "0.7.0")


class DownloadUrlTests(unittest.TestCase):
    TAGS = {"atlassoc-v0.7.0", "atlassoc-v0.7.0-linux"}
    GOOD = "https://github.com/Ibert-Iam/threat-atlas/releases/download/atlassoc-v0.7.0/AtlasSOC-Setup-0.7.0.exe"

    def ok(self, url, name="AtlasSOC-Setup-0.7.0.exe"):
        return uf.download_url_ok(url, self.TAGS, name)

    def test_accepts_the_exact_release_download_url(self):
        self.assertTrue(self.ok(self.GOOD))

    def test_rejects_dot_dot_and_encoded_traversal(self):
        base = "https://github.com/Ibert-Iam/threat-atlas/releases/download/"
        for bad in (base + "../../../evil/x/atlassoc-v0.7.0/AtlasSOC-Setup-0.7.0.exe",
                    base + "%2e%2e/%2e%2e/evil/atlassoc-v0.7.0/AtlasSOC-Setup-0.7.0.exe",
                    base + "atlassoc-v0.7.0/../AtlasSOC-Setup-0.7.0.exe"):
            self.assertFalse(self.ok(bad), bad)

    def test_rejects_other_hosts_userinfo_ports_queries_and_schemes(self):
        for bad in ("https://github.com@evil.example/Ibert-Iam/threat-atlas/releases/download/atlassoc-v0.7.0/AtlasSOC-Setup-0.7.0.exe",
                    "https://evil.example/Ibert-Iam/threat-atlas/releases/download/atlassoc-v0.7.0/AtlasSOC-Setup-0.7.0.exe",
                    "https://github.com:8443/Ibert-Iam/threat-atlas/releases/download/atlassoc-v0.7.0/AtlasSOC-Setup-0.7.0.exe",
                    self.GOOD + "?x=1", self.GOOD + "#frag",
                    self.GOOD.replace("https", "http"),
                    self.GOOD.replace("Ibert-Iam", "other-org"),
                    self.GOOD.replace("/", "\\", 3),
                    "https://github.com/Ibert-Iam/threat-atlas/releases/download/atlassoc-v9.9.9/AtlasSOC-Setup-0.7.0.exe"):
            self.assertFalse(self.ok(bad), bad)

    def test_rejects_the_old_owner_name(self):
        # The old account name is an empty reserved organisation; it must never be accepted again.
        self.assertFalse(self.ok(self.GOOD.replace("Ibert-Iam", "ibert-ai")))

    def test_rejects_name_mismatch_and_non_strings(self):
        self.assertFalse(self.ok(self.GOOD, "Other.exe"))
        self.assertFalse(self.ok(None))

    def test_validate_reports_a_traversal_url(self):
        f = feed()
        r = f["products"]["atlassoc"]["releases"][0]
        r["assets"][0]["url"] = "https://github.com/Ibert-Iam/threat-atlas/releases/download/../../../evil/x/" + r["tag"] + "/" + r["assets"][0]["name"]
        self.assertTrue(any("url must be" in p for p in uf.validate(f)))


class WithdrawalTests(unittest.TestCase):
    def test_withdrawn_beta_falls_back_to_rc(self):
        block = feed(["0.9.0-beta.1"])["products"]["atlassoc"]
        self.assertEqual(ver(block, "beta"), "0.8.0-rc.2")
        self.assertEqual(block["channels"]["beta"]["version"], "0.8.0-beta.1")

    def test_withdrawn_rc_falls_back_to_previous_rc_then_stable(self):
        self.assertEqual(ver(feed(["0.8.0-rc.2"])["products"]["atlassoc"], "rc"), "0.8.0-rc.1")
        self.assertEqual(ver(feed(["0.8.0-rc.2", "0.8.0-rc.1"])["products"]["atlassoc"], "rc"), "0.7.0")

    def test_everything_pulled_gives_nothing_for_stable(self):
        self.assertIsNone(ver(feed(["0.7.0"])["products"]["atlassoc"], "stable"))

    def test_withdrawn_survives_regeneration(self):
        old = feed(["0.8.0-rc.2"])
        again = uf.build_feed(RELEASES, old, now="y")
        self.assertEqual(again["products"]["atlassoc"]["withdrawn"], ["0.8.0-rc.2"])


class ValidationTests(unittest.TestCase):
    def setUp(self):
        self.feed = feed()

    def problems(self, mutate):
        f = copy.deepcopy(self.feed)
        mutate(f["products"]["atlassoc"])
        return uf.validate(f)

    def test_generated_feed_is_valid(self):
        self.assertEqual(uf.validate(self.feed), [])

    def test_rejects_foreign_host(self):
        def m(b): b["releases"][0]["assets"][0]["url"] = "https://evil.example/x.exe"
        self.assertTrue(any("url must be" in p for p in self.problems(m)))

    def test_rejects_other_repository_and_other_tag(self):
        def m1(b): b["releases"][0]["assets"][0]["url"] = "https://github.com/other/repo/releases/download/t/x"
        def m2(b):
            a = b["releases"][0]["assets"][0]
            a["url"] = a["url"].replace(b["releases"][0]["tag"], "atlassoc-v9.9.9")
        self.assertTrue(self.problems(m1))
        self.assertTrue(self.problems(m2))

    def test_rejects_an_asset_larger_than_the_cap(self):
        def m(b): b["releases"][0]["assets"][0]["size"] = uf.MAX_ASSET_BYTES + 1
        self.assertTrue(any("size" in p for p in self.problems(m)))

    def test_rejects_bad_hash_and_size(self):
        def m(b):
            b["releases"][0]["assets"][0]["sha256"] = "ZZ"
            b["releases"][0]["assets"][0]["size"] = 0
        self.assertEqual(len([p for p in self.problems(m) if "sha256" in p or "size" in p]), 2)

    def test_rejects_wrong_pointer(self):
        def m(b): b["channels"]["rc"] = {"version": "0.8.0-rc.1", "tag": "atlassoc-v0.8.0-rc.1"}
        self.assertTrue(any("not the newest" in p for p in self.problems(m)))

    def test_rejects_pointer_to_withdrawn_or_wrong_channel(self):
        def m1(b): b["withdrawn"] = ["0.7.0"]
        def m2(b): b["channels"]["stable"] = {"version": "0.8.0-rc.2", "tag": "atlassoc-v0.8.0-rc.2"}
        self.assertTrue(any("withdrawn" in p for p in self.problems(m1)))
        self.assertTrue(any("rc version" in p or "points to a" in p for p in self.problems(m2)))

    def test_rejects_channel_mismatch_and_bad_schema(self):
        def m(b): b["releases"][0]["channel"] = "stable"
        self.assertTrue(any("does not match" in p for p in self.problems(m)))
        bad = copy.deepcopy(self.feed)
        bad["schema_version"] = 2
        self.assertTrue(uf.validate(bad))
        self.assertTrue(uf.validate({"schema_version": 1}))

    def test_cli_validate_and_resolve(self):
        with tempfile.TemporaryDirectory() as d:
            path = pathlib.Path(d) / "feed.json"
            path.write_text(json.dumps(self.feed))
            self.assertEqual(uf.main(["validate", str(path)]), 0)
            self.assertEqual(uf.main(["resolve", str(path), "--product", "atlassoc", "--channel", "beta"]), 0)
            path.write_text(json.dumps({"schema_version": 1, "products": {"atlassoc": {"releases": [], "channels": {"stable": {"version": "1.0.0", "tag": "x"}}}}}))
            self.assertEqual(uf.main(["validate", str(path)]), 1)
            path.write_bytes(b" " * (uf.MAX_FEED_BYTES + 1))
            self.assertEqual(uf.main(["validate", str(path)]), 1)


class BuildTests(unittest.TestCase):
    """The macOS app refuses a download whose build differs from the feed's, so the feed must be exact."""

    def made(self, *assets, product="atlassoc", withdrawn=()):
        tag = "atlassoc-v0.8.0" if product == "atlassoc" else "v0.8.0"
        f = uf.build_feed([rel(tag, assets=assets)], {"products": {product: {"withdrawn": list(withdrawn)}}}, now="x")
        return f["products"][product]["releases"][0]["build"], uf.validate(f)

    def test_agreeing_names_give_the_build(self):
        self.assertEqual(self.made("macOS-vX-build16-signed.zip", "Setup-X-build16.exe", "SHA256SUMS.txt"), (16, []))

    def test_disagreeing_names_are_refused_in_either_order(self):
        for names in (("macOS-vX-build16.zip", "Setup-X-build15.exe"), ("Setup-X-build15.exe", "macOS-vX-build16.zip"),
                      ("macOS-vX-build16-signed.zip", "macOS-vX-build15.zip"), ("macOS-vX-build15-build16.zip",)):
            build, problems = self.made(*names)
            self.assertIsNone(build, names)
            self.assertTrue(any("do not agree" in p for p in problems), names)

    def test_linux_side_release_with_another_build_is_refused(self):
        f = uf.build_feed([rel("atlassoc-v0.8.0", assets=("macOS-vX-build16.zip",)),
                           rel("atlassoc-v0.8.0-linux", assets=("Linux-build17.tar.gz",))], now="x")
        self.assertTrue(any("do not agree" in p for p in uf.validate(f)))

    def test_macos_file_without_its_own_build_is_refused(self):
        for mac in ("macOS-vX.zip", "macOS-vX-rebuild16.zip", "macOS-vX-build16b.zip"):
            _, problems = self.made(mac, "Setup-X-build16.exe")
            self.assertTrue(any("must name its build" in p for p in problems), mac)

    def test_other_files_and_the_screensaver_may_leave_the_build_out(self):
        self.assertEqual(self.made("Setup-X.exe"), (None, []))
        self.assertEqual(self.made("macOS-signed.zip", product="screensaver"), (None, []))

    def test_edited_or_out_of_range_build_is_refused(self):
        f = uf.build_feed([rel("atlassoc-v0.8.0", assets=("macOS-vX-build16.zip",))], now="x")
        for bad in (15, None, True, "16", 16.0, 0, -1, 2**32):
            f["products"]["atlassoc"]["releases"][0]["build"] = bad
            self.assertTrue(any("build" in p for p in uf.validate(f)), bad)
        f = uf.build_feed([rel("atlassoc-v0.8.0", assets=("macOS-vX-build1.zip",))], now="x")
        self.assertEqual(uf.validate(f), [])
        for equal_to_one in (True, 1.0):
            f["products"]["atlassoc"]["releases"][0]["build"] = equal_to_one
            self.assertTrue(any("must be null" in p for p in uf.validate(f)), equal_to_one)
        f["products"]["atlassoc"].update(withdrawn=["0.8.0"], channels={})
        f["products"]["atlassoc"]["releases"][0]["build"] = 2**32
        self.assertTrue(any("must be null" in p for p in uf.validate(f)), "a withdrawn release must stay readable")
        self.assertTrue(self.made("macOS-vX-build0.zip")[1])
        self.assertTrue(self.made("macOS-vX-build4294967296.zip")[1])
        self.assertEqual(self.made("macOS-vX-build4294967295.zip"), (2**32 - 1, []))

    def test_a_badly_named_release_can_still_be_withdrawn(self):
        self.assertEqual(self.made("macOS-vX-build16.zip", "Setup-X-build15.exe", withdrawn=["0.8.0"]), (None, []))
        self.assertEqual(self.made("macOS-vX.zip", withdrawn=["0.8.0"])[1], [])
        self.assertEqual(self.made("macOS-vX-build4294967296.zip", withdrawn=["0.8.0"]), (None, []))

    def test_from_github_writes_no_feed_when_builds_disagree(self):
        with tempfile.TemporaryDirectory() as d:
            src, out = pathlib.Path(d) / "releases.json", pathlib.Path(d) / "feed.json"
            src.write_text(json.dumps([rel("atlassoc-v0.8.0", assets=("macOS-vX-build16.zip", "Setup-X-build15.exe"))]))
            self.assertEqual(uf.main(["from-github", "--out", str(out), "--releases-json", str(src)]), 1)
            self.assertFalse(out.exists())


class SharedFixtureTests(unittest.TestCase):
    """The same cases are checked by scripts/test-get-latest.ps1 against the PowerShell resolver."""

    def test_sample_feed_is_valid_and_every_case_resolves_as_recorded(self):
        fixtures = pathlib.Path(__file__).with_name("fixtures")
        sample = json.loads((fixtures / "update-feed-sample.json").read_text())
        cases = json.loads((fixtures / "update-feed-cases.json").read_text())["cases"]
        self.assertEqual(uf.validate(sample), [])
        self.assertGreaterEqual(len(cases), 15)
        for c in cases:
            rel = uf.resolve(sample["products"][c["product"]], c["channel"], c["platform"])
            asset = rel and uf.pick_asset(rel, c["platform"], "auto")
            self.assertEqual((rel and rel["version"], asset and asset["name"]), (c["version"], c["asset"]), c)

    def test_withdrawn_version_is_never_picked(self):
        sample = json.loads(pathlib.Path(__file__).with_name("fixtures").joinpath("update-feed-sample.json").read_text())
        self.assertIn("0.8.0-rc.2", sample["products"]["atlassoc"]["withdrawn"])
        for ch in uf.CHANNELS:
            self.assertNotEqual(ver(sample["products"]["atlassoc"], ch, "windows-x64"), "0.8.0-rc.2")


class FixtureCopyTests(unittest.TestCase):
    """The Rust core tests read byte-identical copies of the shared fixtures from crates/core/testdata."""

    def test_rust_copies_match_the_shared_fixtures(self):
        root = pathlib.Path(__file__).resolve().parent.parent
        for name in ("update-feed-sample.json", "update-feed-cases.json"):
            copy = root / "crates" / "core" / "testdata" / name
            if copy.exists():
                self.assertEqual(copy.read_bytes(), (root / "scripts" / "fixtures" / name).read_bytes(), name)


if __name__ == "__main__":
    unittest.main()
