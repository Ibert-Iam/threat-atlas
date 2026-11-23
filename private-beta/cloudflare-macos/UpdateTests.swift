import Foundation
// Offline tests for Settings > Updates (WP4). No network: the core is called with fixed bytes.
// Run (after build.sh, which writes RadarLicense.generated.swift and builds the core):
// xcrun swiftc -parse-as-library -import-objc-header RadarCoreFFI.h LicenseConsent.swift UpdateController.swift \
//   <out>/RadarLicense.generated.swift UpdateTests.swift ../../target/aarch64-apple-darwin/release/libthreat_atlas_core.a \
//   -framework Security -framework CoreFoundation -framework SystemConfiguration -liconv -o /private/tmp/update-tests && /private/tmp/update-tests
@main struct UpdateTests {
    static func check(_ ok: Bool, _ what: String) { precondition(ok, what); print("ok  \(what)") }

    static func main() {
        let base: [String: Any] = ["product": "atlassoc", "version": "0.8.0-rc.1", "build": 15, "channel": "rc",
                                   "platform": "macos-universal", "kind": "portable", "now": 1_795_435_200]
        var failed = base
        failed["download_failed"] = true
        failed["state"] = ["newest_feed": "2026-11-22T10:00:00Z"]
        let r1 = UpdateController.run(feed: Data(), signature: Data(), request: failed)!
        check(r1.result == "failed" && r1.reason == "download", "a failed download is reported as failed")
        check(r1.text.hasPrefix("Could not download"), "and says so in plain words")
        check(r1.state?["newest_feed"] as? String == "2026-11-22T10:00:00Z", "rollback mark kept")

        let feed = Data(#"{"schema":1,"generated_at":"2026-11-23T10:00:00Z","products":{}}"#.utf8)
        let sig = Data("ed25519 0123456789abcdef \(String(repeating: "00", count: 64))\n".utf8)
        let r2 = UpdateController.run(feed: feed, signature: sig, request: base)!
        check(r2.result == "failed" && r2.reason == "signature" && r2.offer == nil && !r2.newer, "a tampered feed is refused")

        var bad = base
        bad["channel"] = "nightly"
        check(UpdateController.run(feed: feed, signature: sig, request: bad)?.reason == "request", "an unknown channel is a request error")

        let j = UpdateController.jitter(for: "/Users/x/Library/Application Support/ThreatAtlasPrivateRadar")
        check(j == UpdateController.jitter(for: "/Users/x/Library/Application Support/ThreatAtlasPrivateRadar") && (0...3600).contains(j),
              "daily offset is stable and at most an hour")

        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("update-tests-" + UUID().uuidString)
        let c = UpdateController(directory: dir)
        check(c.isDue(), "never checked: due")
        c.checkNow()
        check(!c.started && !c.checking, "nothing is checked before start() (licence consent)")
        check(atlasFeedVersion.hasPrefix(radarLicenseTerms.version), "feed version comes from the build identity")
        check(["stable", "rc", "beta"].contains(atlasBuildChannel), "build channel is a feed channel")
        try? FileManager.default.removeItem(at: dir)
        print("PASS: update check over the core, offline")
    }
}
