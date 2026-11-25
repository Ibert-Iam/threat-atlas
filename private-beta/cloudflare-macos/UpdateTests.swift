import Foundation
// Offline tests for Settings > Updates (WP4). Only a throwaway server on 127.0.0.1 (python3) is contacted;
// the core is called with fixed bytes.
// Run (after build.sh, which writes RadarLicense.generated.swift and builds the core):
// xcrun swiftc -parse-as-library -import-objc-header RadarCoreFFI.h LicenseConsent.swift UpdateController.swift \
//   <out>/RadarLicense.generated.swift UpdateTests.swift ../../target/aarch64-apple-darwin/release/libthreat_atlas_core.a \
//   -framework Security -framework CoreFoundation -framework SystemConfiguration -liconv -o /private/tmp/update-tests && /private/tmp/update-tests
@main struct UpdateTests {
    static func check(_ ok: Bool, _ what: String) { precondition(ok, what); print("ok  \(what)") }

    /// Local HTTP fixture. Streams "/endless" until the client hangs up and counts the bytes it managed to send.
    static let server = #"""
    import gzip, os, sys, threading, time
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    sent = [0]; hits = [0]
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def reply(self, body, length=None, code=200, **headers):
            self.send_response(code)
            for k, v in headers.items(): self.send_header(k.replace("_", "-"), v)
            if length is not None: self.send_header("Content-Length", str(length))
            self.end_headers(); self.wfile.write(body)
        def do_GET(self):
            p = self.path
            if p == "/cap": self.reply(b"x" * 256, 256)
            elif p == "/over": self.reply(b"x" * 257, 257)
            elif p == "/over-nolength": self.reply(b"x" * 257)
            elif p == "/cap-nolength": self.reply(b"x" * 256)
            elif p == "/truncated": self.reply(b"x" * 100, 200)
            elif p == "/understated": self.reply(b"x" * 1000, 100)
            elif p == "/error": self.reply(b"x", 1, 500)
            elif p == "/redirect": self.reply(b"", 0, 302, Location="/redirected")
            elif p == "/redirected": hits[0] += 1; self.reply(b"x", 1)
            elif p == "/gzip":
                body = gzip.compress(b"x" * 1000000)
                self.reply(body, len(body), Content_Encoding="gzip")
            elif p == "/endless":
                self.send_response(200); self.end_headers()
                try:
                    while sent[0] < 500000000: self.wfile.write(b"x" * 65536); sent[0] += 65536
                except OSError: pass
            elif p == "/hold": time.sleep(3); self.reply(b"x", 1)
            elif p == "/count": b = ("%d %d" % (sent[0], hits[0])).encode(); self.reply(b, len(b))
            else: self.reply(b"", 0, 404)
    s = ThreadingHTTPServer(("127.0.0.1", 0), H); s.daemon_threads = True
    # Ends with the test process, also when a check fails and it aborts.
    threading.Thread(target=lambda: (sys.stdin.read(), os._exit(0)), daemon=True).start()
    print(s.server_port, flush=True); s.serve_forever()
    """#

    @MainActor static func transfers() async throws {
        let process = Process()
        let pipe = Pipe()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        process.arguments = ["python3", "-I", "-c", server]
        process.standardOutput = pipe
        process.standardInput = Pipe()
        try process.run()
        defer { process.terminate() }
        let port = String(decoding: pipe.fileHandleForReading.availableData, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
        func at(_ path: String) -> URL { URL(string: "http://127.0.0.1:\(port)/\(path)")! }
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("update-tests-" + UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: dir) }

        // Caps and transport, on the real session (its redirect delegate and timeouts).
        let session = UpdateController(directory: dir).session
        func get(_ path: String, cap: Int = 256) async -> Data? { await UpdateController.fetch(at(path), cap: cap, session: session) }
        var got = await get("cap"); check(got?.count == 256, "a reply of exactly the cap is accepted")
        got = await get("cap-nolength"); check(got?.count == 256, "also without Content-Length")
        got = await get("over"); check(got == nil, "one byte over the cap is refused")
        got = await get("over-nolength"); check(got == nil, "also without Content-Length")
        got = await get("gzip"); check(got == nil, "a small compressed reply that expands past the cap is refused")
        got = await get("truncated"); check(got == nil, "a reply shorter than its Content-Length is refused")
        got = await get("understated"); check((got?.count ?? 0) <= 256, "an understated Content-Length never passes the cap")
        got = await get("error"); check(got == nil, "a server error is refused")
        got = await get("endless", cap: UpdateController.maxFeedBytes); check(got == nil, "an endless reply is stopped")
        got = await get("redirect"); check(got == nil, "a redirect is refused")
        try await Task.sleep(nanoseconds: 500_000_000)
        let counts = String(decoding: await get("count") ?? Data(), as: UTF8.self).split(separator: " ").compactMap { Int($0) }
        check(counts.count == 2 && counts[0] < 100_000_000, "the transfer itself was stopped (\(counts.first ?? -1) bytes sent)")
        check(counts.count == 2 && counts[1] == 0, "the redirect target was never contacted")

        // Channel changes while a check is held open by the server.
        UserDefaults.standard.removeObject(forKey: UpdateController.channelKey)
        defer { UserDefaults.standard.removeObject(forKey: UpdateController.channelKey) }
        let offer = UpdateResponse(json: Data(#"{"result":"available","newer":true,"offer":{"version":"0.9.0-beta.1","channel":"beta","tag":"atlassoc-v0.9.0-beta.1","release_page":"https://github.com/Ibert-Iam/threat-atlas/releases/tag/atlassoc-v0.9.0-beta.1"}}"#.utf8))!
        let c = UpdateController(directory: dir, feed: at("hold"), signature: at("hold"))
        c.channel = "beta"
        c.apply(offer)
        check(c.activeOffer?.version == "0.9.0-beta.1", "a finished check offers its version")
        c.channel = "stable"
        check(c.activeOffer == nil && c.response == nil, "a channel change drops the old offer, even before start()")
        func settle() async throws { while c.checking { try await Task.sleep(nanoseconds: 50_000_000) } }
        c.start()
        try await settle()
        check(c.response?.result == "failed" && c.activeOffer == nil, "a failed check offers nothing")
        c.channel = "beta"; try await settle(); c.apply(offer)
        c.checkNow()
        check(c.checking && c.activeOffer == nil, "no offer can be used while a check runs")
        try await settle(); c.apply(offer)
        c.channel = "stable"
        check(c.checking && c.response == nil && c.activeOffer == nil, "Beta to Stable: the Beta offer is gone while the check is held")
        let began = Date()
        c.channel = "rc"; c.channel = "beta"; c.channel = "stable"
        try await settle()
        check(Date().timeIntervalSince(began) >= 3, "rapid changes: a cancelled older check does not end the newest one")
        check(c.response?.result == "failed" && c.activeOffer == nil, "and only the newest result is shown")
    }

    static func main() async throws {

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
        try await transfers()
        print("PASS: update check over the core, offline")
    }
}
