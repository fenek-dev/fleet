import Foundation

/// End-to-end test hooks. Everything real lives under `FLEET_TEST_HOOKS`,
/// which only the Debug configuration defines; in Release the type is an
/// inert stub, so no hook string or code path exists in the binary.
///
/// Runtime switches (Debug only): a data directory that isolates one app
/// instance completely, a software signer that auto-approves every
/// biometric prompt and logs it, and export of the SSH public keys.
enum TestHooks {
#if FLEET_TEST_HOOKS
    private static let env = ProcessInfo.processInfo.environment

    /// Per-instance data directory: every app file, the Keychain
    /// replacement and the UserDefaults store live under it.
    static let dataDir: URL? = {
        guard let p = env["FLEET_DATA_DIR"], !p.isEmpty else { return nil }
        return URL(fileURLWithPath: p, isDirectory: true).resolvingSymlinksInPath()
    }()

    /// Software keys, every biometric prompt auto-approved (and logged).
    static let signer: Bool = env["FLEET_TEST_SIGNER"] == "1"

    /// With the signer on, MCP pairing prompts are answered automatically
    /// too (unsigned parents need one per connection). `FLEET_TEST_AUTO_PAIR=0`
    /// keeps the pairing sheet for UI tests of it.
    static let autoPairing: Bool = signer && env["FLEET_TEST_AUTO_PAIR"] != "0"

    /// `FLEET_TEST_AGENT_ARTIFACT=<path>`: "Choose…" in the install step
    /// picks this file instead of opening the file panel.
    static let agentArtifact: URL? = {
        guard let p = env["FLEET_TEST_AGENT_ARTIFACT"], !p.isEmpty else { return nil }
        return URL(fileURLWithPath: p)
    }()

    /// `FLEET_TEST_SERVER_PASSWORD=<pw>`: prefills the one-time password
    /// field in Add server (UI tests of the password setup; the value is a
    /// fixture of the test server, never a real password).
    static let serverPassword: String? = {
        guard let p = env["FLEET_TEST_SERVER_PASSWORD"], !p.isEmpty else { return nil }
        return p
    }()

    private static let logLock = NSLock()

    /// True (and logs) when the test signer stands in for a Touch ID
    /// prompt for `reason`.
    static func approve(_ reason: String) -> Bool {
        guard signer else { return false }
        guard let dir = dataDir else { return true }
        let line = "TEST-APPROVE " + reason.replacingOccurrences(of: "\n", with: " ") + "\n"
        logLock.lock()
        defer { logLock.unlock() }
        try? FileManager.default.createDirectory(
            at: dir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let url = dir.appendingPathComponent("approvals.log")
        if !FileManager.default.fileExists(atPath: url.path) {
            FileManager.default.createFile(atPath: url.path, contents: nil,
                                           attributes: [.posixPermissions: 0o600])
        }
        if let h = try? FileHandle(forWritingTo: url) {
            _ = try? h.seekToEnd()
            try? h.write(contentsOf: Data(line.utf8))
            try? h.close()
        }
        return true
    }

    /// Writes `<dataDir>/<name>` (0600) for testers to read.
    static func export(_ name: String, _ text: String) {
        guard let dir = dataDir else { return }
        try? FileManager.default.createDirectory(
            at: dir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let url = dir.appendingPathComponent(name)
        try? Data((text + "\n").utf8).write(to: url, options: .atomic)
        chmod(url.path, 0o600)
    }

    /// File-backed stand-in for the Keychain: `<dataDir>/keys/<service>__<account>`.
    enum FileKeychain {
        private static func url(_ dir: URL, _ service: String, _ account: String) -> URL {
            let safe = { (s: String) in
                String(s.map { $0.isLetter || $0.isNumber || $0 == "." || $0 == "-" ? $0 : "_" })
            }
            return dir.appendingPathComponent("keys", isDirectory: true)
                .appendingPathComponent(safe(service) + "__" + safe(account))
        }

        private static func ensure(_ dir: URL) throws {
            try FileManager.default.createDirectory(
                at: dir.appendingPathComponent("keys", isDirectory: true),
                withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        }

        static func load(_ dir: URL, _ service: String, _ account: String) -> Data? {
            try? Data(contentsOf: url(dir, service, account))
        }

        static func exists(_ dir: URL, _ service: String, _ account: String) -> Bool {
            FileManager.default.fileExists(atPath: url(dir, service, account).path)
        }

        /// `replace: false` refuses an existing item, like `SecItemAdd`
        /// (returns false).
        static func store(_ dir: URL, _ service: String, _ account: String, _ data: Data,
                          replace: Bool) throws -> Bool {
            try ensure(dir)
            let u = url(dir, service, account)
            if !replace && FileManager.default.fileExists(atPath: u.path) { return false }
            try data.write(to: u, options: .atomic)
            chmod(u.path, 0o600)
            return true
        }

        static func delete(_ dir: URL, _ service: String, _ account: String) {
            try? FileManager.default.removeItem(at: url(dir, service, account))
        }
    }
#else
    static var dataDir: URL? { nil }
    static var signer: Bool { false }
    static var autoPairing: Bool { false }
    static var agentArtifact: URL? { nil }
    static var serverPassword: String? { nil }
    static func approve(_ reason: String) -> Bool { false }
    static func export(_ name: String, _ text: String) {}
#endif
}
