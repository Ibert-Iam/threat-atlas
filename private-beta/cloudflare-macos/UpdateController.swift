import Foundation

/// Settings → Updates (WP4). Downloads the signed update feed over HTTPS (no redirects, size capped) and
/// hands both files to the shared core (`ta_update_check`), which does every check: signature, feed rules,
/// freshness, rollback. This class only downloads, saves the small state file and publishes the result.
/// It never installs anything; an offered version opens its release page.
final class UpdateController: NSObject, ObservableObject, URLSessionTaskDelegate {
    static let shared = UpdateController()

    static let feedURL = URL(string: "https://raw.githubusercontent.com/Ibert-Iam/threat-atlas/update-feed/feed.json")!
    static let signatureURL = URL(string: "https://raw.githubusercontent.com/Ibert-Iam/threat-atlas/update-feed/feed.json.sig")!
    static let maxFeedBytes = 1_000_000
    static let maxSignatureBytes = 256
    static let channelKey = "AtlasSOC.UpdateChannel"
    /// Daily, plus a stable per-user offset of up to an hour; an hour after a failed check.
    static let day: TimeInterval = 24 * 60 * 60
    static let retryAfterFailure: TimeInterval = 60 * 60

    /// "build" follows the channel of this build; otherwise "stable", "rc" or "beta".
    @Published var channel: String {
        didSet {
            guard channel != oldValue else { return }
            UserDefaults.standard.set(channel, forKey: Self.channelKey)
            checkNow()
        }
    }
    @Published private(set) var checking = false
    @Published private(set) var response: UpdateResponse?
    @Published private(set) var state: [String: Any] = [:]

    /// Set by `start()` after licence consent; nothing is downloaded before that.
    private(set) var started = false
    /// Only the newest check may publish its result (a channel change while one runs starts a new one).
    private var generation = 0
    private let stateURL: URL
    private let jitter: TimeInterval
    private var timer: Timer?
    private lazy var session: URLSession = {
        let config = URLSessionConfiguration.ephemeral
        config.httpCookieStorage = nil
        config.urlCache = nil
        config.timeoutIntervalForRequest = 30
        return URLSession(configuration: config, delegate: self, delegateQueue: nil)
    }()

    init(directory: URL? = nil) {
        let base = directory ?? FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("ThreatAtlasPrivateRadar", isDirectory: true)
        try? FileManager.default.createDirectory(at: base, withIntermediateDirectories: true)
        stateURL = base.appendingPathComponent("update-check.json")
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
        Task {
            let feed = await fetch(Self.feedURL, cap: Self.maxFeedBytes)
            let signature = await fetch(Self.signatureURL, cap: Self.maxSignatureBytes)
            await MainActor.run {
                guard mine == self.generation else { return }
                self.finish(feed: feed, signature: signature)
            }
        }
    }

    private func fetch(_ url: URL, cap: Int) async -> Data? {
        var request = URLRequest(url: url)
        request.cachePolicy = .reloadIgnoringLocalCacheData
        guard let (data, reply) = try? await session.data(for: request),
              (reply as? HTTPURLResponse)?.statusCode == 200, data.count <= cap else { return nil }
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
            response = reply
            if let newState = reply.state {
                state = newState
                if let data = try? JSONSerialization.data(withJSONObject: newState, options: [.prettyPrinted, .sortedKeys]) {
                    try? data.write(to: stateURL, options: .atomic)
                }
            }
        }
        checking = false
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

    /// Refuse every redirect: the feed location is pinned.
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
        completionHandler(nil)
    }

    /// The lines Settings shows: result, then last check (and last success after a failure).
    var lines: [String] {
        var out = [checking ? "Checking for updates…" : (response?.text ?? "Not checked yet")]
        out.append("Last check: " + Self.short(state["last_check"] as? String))
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

/// The core's answer, decoded loosely: unknown values fall back to "failed".
struct UpdateResponse {
    struct Offer { let version: String; let channel: String; let tag: String; let releasePage: URL? }
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
            offer = Offer(version: v, channel: x["channel"] as? String ?? "", tag: t,
                          releasePage: (x["release_page"] as? String).flatMap(URL.init(string:)))
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
