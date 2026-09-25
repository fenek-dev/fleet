import Foundation
import Observation

/// Fleet intelligence state (design §2.4, §2.7): the vulnerability feed
/// database and latest scan reports, and the timeline service. The feeds
/// update on the core's own thread, daily while the app runs.
@Observable
@MainActor
final class IntelStore {
    /// Latest vulnerability report per server id.
    private(set) var reports: [String: VulnReportRow] = [:]
    private(set) var status: VulnStatusRow?
    private(set) var scanning = false
    private(set) var lastError: String?

    @ObservationIgnored private(set) var vulns: VulnService?
    /// Verified events per server, kept for the app's lifetime.
    @ObservationIgnored let timeline = TimelineService()
    @ObservationIgnored private var periodic: Task<Void, Never>?

    /// Opens `vulns.sqlite` next to the cache and starts the daily feed
    /// updates.
    func open() {
        guard vulns == nil else { return }
        do {
            let s = try VulnService.open(path: try Self.dbPath())
            vulns = s
            s.startDaily()
            refreshStatus()
        } catch {
            lastError = error.fleetMessage
        }
    }

    func refreshStatus() {
        guard let vulns else { return }
        status = try? vulns.status()
    }

    /// Checks both feeds now.
    func updateFeeds() async {
        guard let vulns else { return }
        do {
            status = try await vulns.updateNow()
            lastError = nil
        } catch {
            lastError = error.fleetMessage
            refreshStatus()
        }
    }

    @discardableResult
    func scan(_ core: FleetCore, serverId: String) async throws -> VulnReportRow? {
        guard let vulns else { return nil }
        let r = try await core.vulnScan(vulns: vulns, serverId: serverId)
        reports[serverId] = r
        return r
    }

    /// Scans every connected server.
    func scanFleet(_ core: FleetCore) async {
        guard let vulns, !scanning else { return }
        scanning = true
        defer { scanning = false }
        do {
            for r in try await core.vulnScanFleet(vulns: vulns) where r.error == nil {
                reports[r.serverId] = r
            }
        } catch {
            lastError = error.fleetMessage
        }
    }

    /// Scans the fleet shortly after launch, then every six hours (feeds
    /// change daily; package inventories change with upgrades).
    func startPeriodicScans(_ bridge: CoreBridge) {
        guard periodic == nil else { return }
        // Weak captures, re-checked each round: strong references live only
        // for one scan, never across the sleep, and the loop ends with them.
        periodic = Task { [weak self, weak bridge] in
            try? await Task.sleep(for: .seconds(60))
            while !Task.isCancelled {
                do {
                    guard let self, let bridge else { return }
                    if let api = bridge.api {
                        self.refreshStatus()
                        await self.scanFleet(api)
                    }
                }
                try? await Task.sleep(for: .seconds(6 * 3600))
            }
        }
    }

    /// Vulnerable package count for the fleet table; -1 when not scanned.
    func vulnerableCount(_ serverId: String) -> Int {
        guard let r = reports[serverId], r.error == nil, r.distro != nil else { return -1 }
        return Int(r.vulnerablePackages)
    }

    private static func dbPath() throws -> String {
        let dir = try FileManager.default.url(
            for: .applicationSupportDirectory, in: .userDomainMask,
            appropriateFor: nil, create: true
        ).appendingPathComponent("Fleet", isDirectory: true)
        try FileManager.default.createDirectory(
            at: dir, withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700])
        return dir.appendingPathComponent("vulns.sqlite").path
    }
}
