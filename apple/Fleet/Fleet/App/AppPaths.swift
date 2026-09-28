import Foundation

/// Every on-disk location the app uses, in one place. Normally
/// `~/Library/Application Support/Fleet` (0700); Debug test builds can
/// redirect all of it (see `TestHooks.dataDir`).
enum AppPaths {
    /// The data directory, created 0700.
    static func dataDir() throws -> URL {
        let dir: URL
        if let override = TestHooks.dataDir {
            dir = override
        } else {
            dir = try FileManager.default.url(
                for: .applicationSupportDirectory, in: .userDomainMask,
                appropriateFor: nil, create: true
            ).appendingPathComponent("Fleet", isDirectory: true)
        }
        try FileManager.default.createDirectory(
            at: dir, withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700])
        return dir
    }

    static func file(_ name: String) throws -> URL {
        try dataDir().appendingPathComponent(name)
    }

    static func cachePath() throws -> String { try file("cache.sqlite").path }
    static func vulnsPath() throws -> String { try file("vulns.sqlite").path }
    static func mcpSocketPath() throws -> String { try file("mcp.sock").path }

    /// UserDefaults for the app's own settings (`@AppStorage`, sync token).
    /// Test builds with a data directory keep them in a plist inside it.
    nonisolated(unsafe) static let defaults: UserDefaults = {
        #if FLEET_TEST_HOOKS
        if let dir = TestHooks.dataDir,
           let d = UserDefaults(suiteName: dir.appendingPathComponent("defaults").path)
        {
            return d
        }
        #endif
        return .standard
    }()
}
