import Foundation
import SwiftUI

/// The same five outcomes as `crates/core/src/update_check.rs`, through the C ABI.
private enum UpdateOutcome: Int32 {
    case unavailable = 0
    case upToDate = 1
    case available = 2
    case withdrawn = 3
    case failed = 4
}

struct UpdateSection: View {
    @State private var status = "Not checked"
    @State private var detail = ""
    @State private var downloadURL: URL?
    @State private var checking = false

    private var installedVersion: String {
        let v = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "?"
        let b = Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? "?"
        return "\(v) (build \(b))"
    }

    private var channel: Int32 {
        let version = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? ""
        if version.contains("-beta") { return 2 }
        if version.contains("-rc") { return 1 }
        return 0
    }

    private var stateURL: URL {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        return base.appendingPathComponent("ThreatAtlas/update-state.json")
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Installed: AtlasSOC \(installedVersion).")
                .font(.callout).foregroundStyle(.secondary)
            Text(status).font(.callout).foregroundStyle(statusColor)
            if !detail.isEmpty {
                Text(detail).font(.caption).foregroundStyle(.secondary).textSelection(.enabled)
            }
            HStack {
                Button(checking ? "Checking…" : "Check for updates") { checkNow() }
                    .disabled(checking)
                if let downloadURL {
                    Button("Open download…") { NSWorkspace.shared.open(downloadURL) }
                }
                Button("Release notes…") {
                    NSWorkspace.shared.open(URL(string: "https://github.com/Ibert-Iam/threat-atlas/releases")!)
                }
            }
            Text("The check fetches only feed.json and feed.json.sig from GitHub. It sends no account, token or telemetry. Nothing installs without your approval.")
                .font(.caption2).foregroundStyle(.secondary)
        }
    }

    private var statusColor: Color {
        switch status {
        case "Update available", "This version was withdrawn": return .accentColor
        case "Check failed": return .orange
        case "Updates are not configured": return .secondary
        default: return .primary
        }
    }

    private func checkNow() {
        checking = true
        status = "Checking…"
        detail = ""
        downloadURL = nil
        Task {
            do {
                let (feed, sig) = try await fetchFeed()
                let installed = installedVersion
                let channelCode = channel
                let text = try await Task.detached { () -> (UpdateOutcome, String, URL?) in
                    try runCheck(feed: feed, sig: sig, installedVersion: installed, channel: channelCode)
                }.value
                await MainActor.run {
                    status = text.0.label
                    detail = text.1
                    downloadURL = text.2
                    checking = false
                }
            } catch {
                await MainActor.run {
                    status = "Check failed"
                    detail = error.localizedDescription
                    checking = false
                }
            }
        }
    }

    private func fetchFeed() async throws -> (Data, Data) {
        let feedURL = URL(string: "https://raw.githubusercontent.com/Ibert-Iam/threat-atlas/update-feed/feed.json")!
        let sigURL = URL(string: "https://raw.githubusercontent.com/Ibert-Iam/threat-atlas/update-feed/feed.json.sig")!
        async let feed = data(feedURL, limit: 1_000_000)
        async let sig = data(sigURL, limit: 256)
        return try await (feed, sig)
    }

    private func data(_ url: URL, limit: Int) async throws -> Data {
        var request = URLRequest(url: url)
        request.timeoutInterval = 20
        request.cachePolicy = .reloadIgnoringLocalCacheData
        let (data, response) = try await URLSession.shared.data(for: request)
        guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
            throw NSError(domain: "UpdateCheck", code: 1, userInfo: [NSLocalizedDescriptionKey: "GitHub returned an error"])
        }
        guard !data.isEmpty, data.count <= limit else {
            throw NSError(domain: "UpdateCheck", code: 2, userInfo: [NSLocalizedDescriptionKey: "Unexpected update file size"])
        }
        return data
    }
}

private extension UpdateOutcome {
    var label: String {
        switch self {
        case .unavailable: return "Updates are not configured"
        case .upToDate: return "Up to date"
        case .available: return "Update available"
        case .withdrawn: return "This version was withdrawn"
        case .failed: return "Check failed"
        }
    }
}

private func cString<T>(_ tuple: T) -> String {
    withUnsafePointer(to: tuple) { pointer in
        String(cString: UnsafeRawPointer(pointer).assumingMemoryBound(to: CChar.self))
    }
}

private func runCheck(feed: Data, sig: Data, installedVersion: String, channel: Int32) throws -> (UpdateOutcome, String, URL?) {
    let state: String
    if let saved = try? String(contentsOf: FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0].appendingPathComponent("ThreatAtlas/update-state.json"), encoding: .utf8) {
        state = saved
    } else {
        state = ""
    }
    var result = TaUpdateResult()
    var stateBuffer = [CChar](repeating: 0, count: 4096)
    let rc = feed.withUnsafeBytes { feedBytes in
        sig.withUnsafeBytes { sigBytes in
            installedVersion.withCString { version in
                "atlassoc".withCString { product in
                    "macos-universal".withCString { platform in
                        state.withCString { stateText in
                            ta_update_check(
                                feedBytes.bindMemory(to: UInt8.self).baseAddress, feed.count,
                                sigBytes.bindMemory(to: UInt8.self).baseAddress, sig.count,
                                version, product, platform, channel, 1,
                                Int64(Date().timeIntervalSince1970), stateText,
                                &result, &stateBuffer, stateBuffer.count)
                        }
                    }
                }
            }
        }
    }
    guard rc == 0 else {
        throw NSError(domain: "UpdateCheck", code: 3, userInfo: [NSLocalizedDescriptionKey: "Update check rejected its input"])
    }
    let stateText = withUnsafePointer(to: &stateBuffer) {
        String(cString: UnsafeRawPointer($0).assumingMemoryBound(to: CChar.self))
    }
    let dir = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0].appendingPathComponent("ThreatAtlas")
    try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    try? stateText.write(to: dir.appendingPathComponent("update-state.json"), atomically: true, encoding: .utf8)

    let outcome = UpdateOutcome(rawValue: result.outcome) ?? .failed
    let version = cString(result.version)
    let message = cString(result.message)
    let url = cString(result.url)
    let detail = version.isEmpty ? message : "\(message): \(version)"
    return (outcome, detail, URL(string: url))
}
