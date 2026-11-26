import Foundation
import AppKit

/// Settings → Updates (WP4). Downloads the signed update feed over HTTPS (no redirects, size capped) and
/// hands both files to the shared core (`ta_update_check`), which does every check: signature, feed rules,
/// freshness, rollback. This class only downloads, saves the small state file and publishes the result.
/// It never installs anything; an offered version opens its release page.
final class UpdateController: NSObject, ObservableObject, URLSessionTaskDelegate {
    static let shared = UpdateController()

    static let officialFeedURL = URL(string: "https://raw.githubusercontent.com/Ibert-Iam/threat-atlas/update-feed/feed.json")!
    static let officialSignatureURL = URL(string: "https://raw.githubusercontent.com/Ibert-Iam/threat-atlas/update-feed/feed.json.sig")!
    /// The feed this build reads, as the core decides it (`ta_update_source`): always the official feed,
    /// except in a `test-feed` build (updater tests, WP9) given ATLAS_TEST_FEED_PATH and ATLAS_TEST_ROOT.
    /// Anything unexpected from the core falls back to the official feed.
    static let source: (feed: URL, signature: URL, test: Bool) = {
        let official = (officialFeedURL, officialSignatureURL, false)
        let needed = ta_update_source(nil, 0)
        guard needed > 0, needed <= 4096 else { return official }
        var buffer = [UInt8](repeating: 0, count: needed)
        guard ta_update_source(&buffer, needed) == needed,
              let json = try? JSONSerialization.jsonObject(with: Data(buffer)) as? [String: Any],
              let feedText = json["feed"] as? String, let signatureText = json["signature"] as? String,
              let feed = URL(string: feedText), let signature = URL(string: signatureText),
              feed.scheme == "https", signature.scheme == "https",
              feed.host == officialFeedURL.host, signature.host == officialFeedURL.host else { return official }
        return (feed, signature, (json["test"] as? Bool) ?? false)
    }()
    static var feedURL: URL { source.feed }
    static var signatureURL: URL { source.signature }
    /// True only in a test-feed build reading a test feed; Settings then says so on its first line.
    static var testFeed: Bool { source.test }
    static let maxFeedBytes = 1_000_000
    static let maxSignatureBytes = 256
    static let channelKey = "AtlasSOC.UpdateChannel"
    /// Daily, plus a stable per-user offset of up to an hour; an hour after a failed check.
    static let day: TimeInterval = 24 * 60 * 60
    static let retryAfterFailure: TimeInterval = 60 * 60
    /// Developer ID team of the official builds (Robert Ibert). A different team is refused (docs/UPDATES.md).
    static let expectedTeam = "7NXP86HMVH"
    static let appName = "AtlasSOC.app"

    /// "build" follows the channel of this build; otherwise "stable", "rc" or "beta".
    @Published var channel: String {
        didSet {
            guard channel != oldValue else { return }
            UserDefaults.standard.set(channel, forKey: Self.channelKey)
            // The old result belongs to the old channel; it must not stay on offer (also if this check fails).
            response = nil
            dropDownload()
            checkNow()
        }
    }
    @Published private(set) var checking = false
    @Published private(set) var download: DownloadState = .idle
    @Published private(set) var response: UpdateResponse?
    @Published private(set) var state: [String: Any] = [:]

    /// Set by `start()` after licence consent; nothing is downloaded before that.
    private(set) var started = false
    /// Only the newest check may publish its result (a channel change while one runs starts a new one).
    private var generation = 0
    /// The running check; a newer one cancels it.
    private var running: Task<Void, Never>?
    private var downloading: Task<Void, Never>?
    /// Only the newest download may publish its result.
    private var downloadGeneration = 0
    private let feedSource: URL
    private let signatureSource: URL
    private let stateURL: URL
    private let updatesURL: URL
    /// Held while this app itself runs from a download folder, so no instance deletes it.
    private let ownFolder: FolderLock?
    /// Release downloads: GitHub redirects to its file host, so HTTPS redirects are allowed here (never to
    /// plain HTTP). The bytes are trusted only after the core's SHA-256 check against the signed feed.
    private lazy var downloadSession: URLSession = {
        let config = URLSessionConfiguration.ephemeral
        config.httpCookieStorage = nil
        config.urlCache = nil
        config.timeoutIntervalForRequest = 60
        return URLSession(configuration: config, delegate: HTTPSOnlyRedirects(), delegateQueue: nil)
    }()
    private let jitter: TimeInterval
    private var timer: Timer?
    private(set) lazy var session: URLSession = {
        let config = URLSessionConfiguration.ephemeral
        config.httpCookieStorage = nil
        config.urlCache = nil
        config.timeoutIntervalForRequest = 30
        // Whole transfer, so a slow trickle cannot keep a check open.
        config.timeoutIntervalForResource = 60
        return URLSession(configuration: config, delegate: self, delegateQueue: nil)
    }()

    /// The parameters are for the offline tests; the app always uses the defaults.
    init(directory: URL? = nil, feed: URL = UpdateController.feedURL, signature: URL = UpdateController.signatureURL,
         bundle: URL = Bundle.main.bundleURL) {
        feedSource = feed
        signatureSource = signature
        let base = directory ?? FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("ThreatAtlasPrivateRadar", isDirectory: true)
        try? FileManager.default.createDirectory(at: base, withIntermediateDirectories: true)
        // A test feed keeps its own state, so it never moves a real installation's rollback mark.
        stateURL = base.appendingPathComponent(Self.testFeed && directory == nil ? "update-check-test.json" : "update-check.json")
        updatesURL = base.appendingPathComponent("updates", isDirectory: true)
        ownFolder = Self.downloadFolder(of: bundle, in: updatesURL).flatMap(FolderLock.init)
        Self.cleanUp(updatesURL)
        jitter = Self.jitter(for: base.path)
        channel = UserDefaults.standard.string(forKey: Self.channelKey) ?? "build"
        super.init()
        if let data = try? Data(contentsOf: stateURL), data.count <= 4096,
           let saved = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
            state = saved
        }
    }

    /// A stable per-installation offset in 0...3600 s (FNV-1a over the path; Swift's hashValue changes per launch).
    static func jitter(for seed: String) -> TimeInterval {
        var hash: UInt64 = 0xcbf2_9ce4_8422_2325
        for byte in seed.utf8 { hash = (hash ^ UInt64(byte)) &* 0x0100_0000_01b3 }
        return TimeInterval(hash % 3601)
    }

    /// Call only after the licence was accepted (the app's consent gate).
    func start() {
        guard timer == nil else { return }
        started = true
        if isDue() { checkNow() }
        timer = Timer.scheduledTimer(withTimeInterval: 600, repeats: true) { [weak self] _ in
            guard let self, !self.checking, self.isDue() else { return }
            self.checkNow()
        }
    }

    func isDue(now: Date = Date()) -> Bool {
        guard let text = state["last_check"] as? String, let last = ISO8601DateFormatter().date(from: text) else { return true }
        let age = now.timeIntervalSince(last)
        let wait = (state["last_result"] as? String) == "failed" ? Self.retryAfterFailure : Self.day + jitter
        return age < 0 || age >= wait
    }

    /// Starts a check; does nothing before `start()` (licence consent). Main thread only.
    func checkNow() {
        guard started else { return }
        generation += 1
        let mine = generation
        checking = true
        running?.cancel()
        let (session, feedSource, signatureSource) = (session, feedSource, signatureSource)
        running = Task {
            let feed = await Self.fetch(feedSource, cap: Self.maxFeedBytes, session: session)
            let signature = await Self.fetch(signatureSource, cap: Self.maxSignatureBytes, session: session)
            await MainActor.run {
                guard mine == self.generation else { return }
                self.finish(feed: feed, signature: signature)
            }
        }
    }

    /// The body of a 200 reply of at most `cap` bytes, else nil. The cap counts decoded bytes as they arrive and
    /// stops the transfer at the first byte over it, whatever Content-Length says.
    static func fetch(_ url: URL, cap: Int, session: URLSession) async -> Data? {
        var request = URLRequest(url: url)
        request.cachePolicy = .reloadIgnoringLocalCacheData
        guard let (stream, reply) = try? await session.bytes(for: request) else { return nil }
        guard (reply as? HTTPURLResponse)?.statusCode == 200, reply.expectedContentLength <= Int64(cap) else {
            stream.task.cancel()
            return nil
        }
        var data = Data()
        do {
            for try await byte in stream {
                guard data.count < cap else {
                    stream.task.cancel()
                    return nil
                }
                data.append(byte)
            }
        } catch {
            return nil
        }
        return data
    }

    @MainActor private func finish(feed: Data?, signature: Data?) {
        let request: [String: Any] = [
            "product": "atlassoc", "version": atlasFeedVersion, "build": Int(radarLicenseTerms.build) ?? 0,
            "channel": channel == "build" ? atlasBuildChannel : channel,
            "platform": "macos-universal", "kind": "portable",
            "now": Int(Date().timeIntervalSince1970), "state": state,
            "download_failed": feed == nil || signature == nil,
        ]
        let reply = Self.run(feed: feed ?? Data(), signature: signature ?? Data(), request: request)
        if let reply {
            apply(reply)
            if let newState = reply.state {
                state = newState
                if let data = try? JSONSerialization.data(withJSONObject: newState, options: [.prettyPrinted, .sortedKeys]) {
                    try? data.write(to: stateURL, options: .atomic)
                }
            }
        }
        checking = false
    }

    /// Publishes a result for the current channel.
    func apply(_ reply: UpdateResponse) { response = reply }

    /// The offer the user may act on: only from a finished check of the selected channel, never while one runs.
    var activeOffer: UpdateResponse.Offer? { checking ? nil : response?.offer }

    /// The active offer when it is newer and has a package to download.
    var downloadableOffer: UpdateResponse.Offer? {
        guard response?.newer == true, let offer = activeOffer, offer.asset != nil else { return nil }
        return offer
    }

    /// One pure call into the core; asks for the size first, then fills a buffer of that size.
    static func run(feed: Data, signature: Data, request: [String: Any]) -> UpdateResponse? {
        guard let body = try? JSONSerialization.data(withJSONObject: request),
              let text = String(data: body, encoding: .utf8) else { return nil }
        return feed.withUnsafeBytes { f in
            signature.withUnsafeBytes { s in
                let fp = f.bindMemory(to: UInt8.self).baseAddress, sp = s.bindMemory(to: UInt8.self).baseAddress
                let needed = ta_update_check(fp, feed.count, sp, signature.count, text, nil, 0)
                var buffer = [UInt8](repeating: 0, count: needed)
                let written = ta_update_check(fp, feed.count, sp, signature.count, text, &buffer, needed)
                guard written == needed else { return nil }
                return UpdateResponse(json: Data(buffer))
            }
        }
    }

    /// The checked app, only while the latest result still offers exactly that version (same tag and SHA-256);
    /// a withdrawal, channel switch or newer release makes an earlier download stale.
    var readyApp: URL? {
        guard case .ready(let ready) = download, let offer = downloadableOffer,
              offer.version == ready.version, offer.tag == ready.tag, offer.asset?.sha256 == ready.sha256 else { return nil }
        return ready.app
    }

    /// Downloads the offered package, checks it in the core against the signed feed, unpacks it and checks the
    /// app's Developer ID team and Gatekeeper assessment. Nothing is installed: the app is shown in Finder.
    func downloadOffer() {
        guard started, let offer = downloadableOffer, let raw = offer.raw, let asset = offer.asset else { return }
        if case .running = download { return }
        download = .running(offer.version)
        downloadGeneration += 1
        let mine = downloadGeneration
        let (session, folder) = (downloadSession, updatesURL)
        downloading = Task {
            let result = await Self.fetchAndCheck(offer: offer, raw: raw, asset: asset, session: session, updates: folder)
            await MainActor.run {
                guard mine == self.downloadGeneration else { return }
                self.download = result
            }
        }
    }

    /// Stops a running download and forgets its result; it belongs to the old channel.
    private func dropDownload() {
        downloadGeneration += 1
        downloading?.cancel()
        downloading = nil
        download = .idle
    }

    func revealReady() {
        if let app = readyApp { NSWorkspace.shared.activateFileViewerSelecting([app]) }
    }

    static func fetchAndCheck(offer: UpdateResponse.Offer, raw: String, asset: UpdateResponse.Asset,
                              session: URLSession, updates: URL,
                              bundleID: String? = Bundle.main.bundleIdentifier) async -> DownloadState {
        if Task.isCancelled { return .failed("the download failed or was interrupted") }
        let fm = FileManager.default
        cleanUp(updates)
        let folder = updates.appendingPathComponent(UUID().uuidString, isDirectory: true)
        // Its own folder only: a newer download may already use the parent.
        func fail(_ why: String) -> DownloadState { try? fm.removeItem(at: folder); return .failed(why) }
        guard let url = URL(string: asset.url), url.scheme == "https" else { return fail("the download address is not allowed") }
        do { try fm.createDirectory(at: folder, withIntermediateDirectories: true) } catch { return fail("cannot create the download folder") }
        guard let lock = FolderLock(folder) else { return fail("cannot create the download folder") }
        let zip = folder.appendingPathComponent(asset.name)
        // Streamed to disk in chunks; the transfer stops as soon as it would pass the announced size, so a
        // wrong or hostile response never fills the disk beyond it.
        do {
            var request = URLRequest(url: url)
            request.cachePolicy = .reloadIgnoringLocalCacheData
            let (stream, reply) = try await session.bytes(for: request)
            guard (reply as? HTTPURLResponse)?.statusCode == 200 else { stream.task.cancel(); return fail("the server did not send the file") }
            if reply.expectedContentLength > 0, UInt64(reply.expectedContentLength) != asset.size {
                stream.task.cancel()
                return fail("the download is incomplete or wrong size (\(reply.expectedContentLength) of \(asset.size) bytes)")
            }
            guard fm.createFile(atPath: zip.path, contents: nil), let handle = try? FileHandle(forWritingTo: zip) else {
                stream.task.cancel(); return fail("cannot write the download")
            }
            defer { try? handle.close() }
            var buffer = Data()
            buffer.reserveCapacity(1 << 16)
            var total: UInt64 = 0
            for try await byte in stream {
                total += 1
                if total > asset.size { stream.task.cancel(); return fail("the download is larger than announced") }
                buffer.append(byte)
                if buffer.count == 1 << 16 { try handle.write(contentsOf: buffer); buffer.removeAll(keepingCapacity: true) }
            }
            try handle.write(contentsOf: buffer)
        } catch {
            return fail("the download failed or was interrupted")
        }
        let size = (try? fm.attributesOfItem(atPath: zip.path)[.size] as? NSNumber)?.uint64Value ?? 0
        guard size == asset.size, let data = try? Data(contentsOf: zip, options: .mappedIfSafe) else {
            return fail("the download is incomplete or wrong size (\(size) of \(asset.size) bytes)")
        }
        let code = raw.withCString { offerJSON in
            data.withUnsafeBytes { ta_update_verify_package(offerJSON, $0.bindMemory(to: UInt8.self).baseAddress, data.count) }
        }
        guard code == 0 else { return fail(Self.packageText(code)) }
        let unpacked = folder.appendingPathComponent("app", isDirectory: true)
        guard run("/usr/bin/ditto", ["-x", "-k", zip.path, unpacked.path]).status == 0 else { return fail("the package could not be unpacked") }
        let apps = (try? fm.contentsOfDirectory(at: unpacked, includingPropertiesForKeys: nil))?.filter { $0.pathExtension == "app" } ?? []
        guard apps.count == 1, let app = apps.first else { return fail("the package does not contain exactly one app") }
        if let why = checkApp(app, version: offer.version, build: offer.build, bundleID: bundleID) { return fail(why) }
        if Task.isCancelled { return fail("the download failed or was interrupted") }
        return .ready(ReadyDownload(version: offer.version, tag: offer.tag, sha256: asset.sha256, app: app, lock: lock))
    }

    /// nil when the app is the official one: same bundle identifier as this app, a valid strict code
    /// signature, the official Developer ID team, notarized, a Gatekeeper pass, and the offered version and build.
    /// Otherwise the reason.
    static func checkApp(_ app: URL, version: String, build: UInt32?, bundleID: String? = Bundle.main.bundleIdentifier) -> String? {
        guard let bundleID, Bundle(url: app)?.bundleIdentifier == bundleID else { return "the app has a different bundle identifier" }
        guard run("/usr/bin/codesign", ["--verify", "--deep", "--strict", app.path]).status == 0 else {
            return "the app's code signature is not valid"
        }
        // codesign evaluates the requirement on the certificates. Its printed details are never parsed: they
        // contain the path, so a crafted name could add lines to them.
        guard run("/usr/bin/codesign", ["--verify", "--strict", "-R", "=" + officialRequirement(bundleID), app.path]).status == 0 else {
            return "the app is not signed with the official Developer ID (\(expectedTeam))"
        }
        guard app.lastPathComponent == appName else { return "the app has an unexpected name" }
        // Also asked of codesign: spctl accepts anything while Gatekeeper is turned off.
        guard run("/usr/bin/codesign", ["--verify", "--strict", "-R", "=notarized", app.path]).status == 0 else {
            return "the app is not notarized by Apple"
        }
        guard run("/usr/sbin/spctl", ["--assess", "--type", "execute", app.path]).status == 0 else {
            return "Gatekeeper does not accept the app"
        }
        guard isOffered(app, version: version, build: build) else { return "the app is not the offered version and build" }
        return nil
    }

    /// True when the app's own version and build are the offered ones, so an older official app cannot pass as an
    /// update. Info.plist holds the version without its pre-release part (0.8.0 for 0.8.0-rc.2); the build tells
    /// those apart, so an offer without a build is refused. Call after the signature check, which covers Info.plist.
    static func isOffered(_ app: URL, version: String, build: UInt32?) -> Bool {
        guard let build,
              let data = try? Data(contentsOf: app.appendingPathComponent("Contents/Info.plist")),
              let info = (try? PropertyListSerialization.propertyList(from: data, format: nil)) as? [String: Any] else { return false }
        let core = version.split(separator: "-", maxSplits: 1).first.map(String.init)
        return info["CFBundleShortVersionString"] as? String == core && info["CFBundleVersion"] as? String == String(build)
    }

    /// Apple-issued Developer ID Application certificate of the official team, and this app's identifier.
    static func officialRequirement(_ bundleID: String) -> String {
        "identifier \"\(bundleID)\" and anchor apple generic"
            + " and certificate 1[field.1.2.840.113635.100.6.2.6] exists"
            + " and certificate leaf[field.1.2.840.113635.100.6.1.13] exists"
            + " and certificate leaf[subject.OU] = \"\(expectedTeam)\""
    }

    /// The download folder under `updates` that `bundle` lies in, if any.
    static func downloadFolder(of bundle: URL, in updates: URL) -> URL? {
        let base = updates.resolvingSymlinksInPath().pathComponents
        let path = bundle.resolvingSymlinksInPath().pathComponents
        guard path.count > base.count, Array(path.prefix(base.count)) == base else { return nil }
        return updates.appendingPathComponent(path[base.count], isDirectory: true)
    }

    /// Removes download folders nobody uses: no instance holds the lock, as the one that downloaded it or as
    /// the app running from it. A folder without a lock file may be just being made, so it is kept for an hour.
    static func cleanUp(_ updates: URL) {
        let fm = FileManager.default
        for folder in (try? fm.contentsOfDirectory(at: updates, includingPropertiesForKeys: [.creationDateKey])) ?? [] {
            let fd = open(FolderLock.file(in: folder).path, O_RDWR | O_CLOEXEC)
            guard fd >= 0 else {
                let made = (try? folder.resourceValues(forKeys: [.creationDateKey]))?.creationDate ?? Date()
                if Date().timeIntervalSince(made) > 3600 { try? fm.removeItem(at: folder) }
                continue
            }
            if flock(fd, LOCK_EX | LOCK_NB) == 0 { try? fm.removeItem(at: folder) }
            close(fd)
        }
    }

    static func packageText(_ code: Int32) -> String {
        switch code {
        case 1: return "the download address is not an official release address"
        case 2: return "the file name is not allowed"
        case 3: return "the announced size is not allowed"
        case 4: return "the download is incomplete or wrong size"
        case 5: return "the file does not match the SHA-256 in the signed update list"
        default: return "the update offer could not be read"
        }
    }

    /// Runs a system tool and returns its exit status and combined output (codesign writes details to stderr).
    static func run(_ tool: String, _ args: [String]) -> (status: Int32, output: String) {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: tool)
        process.arguments = args
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        do { try process.run() } catch { return (-1, "") }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        return (process.terminationStatus, String(decoding: data, as: UTF8.self))
    }

    /// Refuse every redirect: the feed location is pinned.
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
        completionHandler(nil)
    }

    /// The lines Settings shows: result, then last check (and last success after a failure).
    var lines: [String] {
        var out = [checking ? "Checking for updates…" : (response?.text ?? "Not checked yet")]
        if Self.testFeed { out.insert("TEST FEED: \(Self.feedURL.path)", at: 0) }
        out.append("Last check: " + Self.short(state["last_check"] as? String))
        switch download {
        case .idle: break
        case .running(let version): out.append("Downloading \(version)…")
        case .ready(let ready): if readyApp != nil { out.append("\(ready.version) downloaded and checked: Developer ID (\(Self.expectedTeam)) and Gatekeeper passed") }
        case .failed(let why): out.append("Download stopped: \(why)")
        }
        if (state["last_result"] as? String) == "failed" {
            out.append("Last successful check: " + Self.short(state["last_success"] as? String))
        }
        return out
    }

    static func short(_ text: String?) -> String {
        guard let text, let date = ISO8601DateFormatter().date(from: text) else { return "never" }
        let f = DateFormatter()
        f.dateFormat = "yyyy-MM-dd HH:mm"
        f.timeZone = TimeZone(identifier: "UTC")
        return f.string(from: date) + " UTC"
    }
}

struct ReadyDownload: Equatable { let version: String; let tag: String; let sha256: String; let app: URL; let lock: FolderLock }

/// A shared lock on a download folder, held as long as this object lives. Any process holding one keeps
/// `UpdateController.cleanUp` (in every instance) from removing the folder.
final class FolderLock: Equatable {
    private let fd: Int32
    static func file(in folder: URL) -> URL { folder.appendingPathComponent(".lock") }

    init?(_ folder: URL) {
        fd = open(Self.file(in: folder).path, O_RDWR | O_CREAT | O_CLOEXEC, 0o600)
        guard fd >= 0 else { return nil }
        guard flock(fd, LOCK_SH | LOCK_NB) == 0 else { return nil }
    }

    deinit { if fd >= 0 { close(fd) } }
    static func == (a: FolderLock, b: FolderLock) -> Bool { a === b }
}

enum DownloadState: Equatable {
    case idle
    case running(String)
    case ready(ReadyDownload)
    case failed(String)
}

/// Follows HTTPS redirects only (GitHub release file host); a redirect to anything else stops the download.
final class HTTPSOnlyRedirects: NSObject, URLSessionTaskDelegate {
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
        completionHandler(request.url?.scheme == "https" ? request : nil)
    }
}

/// The core's answer, decoded loosely: unknown values fall back to "failed".
struct UpdateResponse {
    struct Asset { let name: String; let url: String; let sha256: String; let size: UInt64 }
    struct Offer {
        let version: String; let build: UInt32?; let channel: String; let tag: String; let releasePage: URL?
        let asset: Asset?
        /// The offer object as JSON, handed back to the core for the package check.
        let raw: String?
    }
    let result: String
    let reason: String
    let offer: Offer?
    let newer: Bool
    let state: [String: Any]?

    init?(json: Data) {
        guard let o = try? JSONSerialization.jsonObject(with: json) as? [String: Any] else { return nil }
        result = o["result"] as? String ?? "failed"
        reason = o["reason"] as? String ?? ""
        newer = o["newer"] as? Bool ?? false
        state = o["state"] as? [String: Any]
        if let x = o["offer"] as? [String: Any], let v = x["version"] as? String, let t = x["tag"] as? String {
            let a = x["asset"] as? [String: Any]
            let asset = a.flatMap { a -> Asset? in
                guard let n = a["name"] as? String, let u = a["url"] as? String, let h = a["sha256"] as? String,
                      let z = (a["size"] as? NSNumber)?.uint64Value else { return nil }
                return Asset(name: n, url: u, sha256: h, size: z)
            }
            let raw = (try? JSONSerialization.data(withJSONObject: x)).flatMap { String(data: $0, encoding: .utf8) }
            offer = Offer(version: v, build: (x["build"] as? NSNumber).flatMap { UInt32(exactly: $0) }, channel: x["channel"] as? String ?? "", tag: t,
                          releasePage: (x["release_page"] as? String).flatMap(URL.init(string:)), asset: asset, raw: raw)
        } else {
            offer = nil
        }
    }

    var text: String {
        switch result {
        case "unavailable": return "Update checks are not available in this build"
        case "up-to-date": return "You have the newest version for this channel"
        case "available": return "Update available: \(offer?.version ?? "?") (\(UpdateResponse.channelName(offer?.channel)))"
        case "withdrawn":
            if let offer { return "This version was withdrawn. Safer choice: \(offer.version) (\(UpdateResponse.channelName(offer.channel)))" }
            return "This version was withdrawn. No safer version is offered yet"
        default:
            return reason == "download" ? "Could not download the update list; your version is unchanged"
                : "The update list did not pass its checks; your version is unchanged"
        }
    }

    static func channelName(_ id: String?) -> String {
        switch id {
        case "stable": return "Stable"
        case "rc": return "Release Candidates"
        case "beta": return "Betas"
        default: return "unknown channel"
        }
    }
}
