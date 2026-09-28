import Foundation
import Observation

/// Per-server facts for the fleet overview (agent version, uptime, package
/// updates, CPU history) and the "While you were away" digest. Refreshed
/// while the overview is visible; kept for the app's lifetime so returning
/// to the overview shows the last numbers at once.
@Observable
@MainActor
final class FleetFactsStore {
    static let shared = FleetFactsStore()

    private(set) var facts: [String: FleetFactsRow] = [:]
    private(set) var digest: DigestRow?
    private(set) var loadingDigest = false
    /// When the operator was last active before this launch.
    let previousActiveMs: UInt64

    @ObservationIgnored private var fetchedAt: [String: Date] = [:]
    @ObservationIgnored private var inflight = Set<String>()
    @ObservationIgnored private var digestAt: Date?
    @ObservationIgnored private var stamp: Task<Void, Never>?
    private static let activeKey = "fleet.lastActiveMs"
    private static let staleAfter: TimeInterval = 300

    private init() {
        let stored = UserDefaults.standard.double(forKey: Self.activeKey)
        let now = Date().timeIntervalSince1970 * 1000
        // Nothing stored (first launch) or older than a week: last 24 h.
        let floor = now - 7 * 86_400_000
        previousActiveMs = UInt64(stored > floor ? stored : now - 86_400_000)
    }

    /// Records activity once a minute so the next launch knows how long the
    /// operator was away.
    func startActivityStamp() {
        guard stamp == nil else { return }
        stamp = Task {
            while !Task.isCancelled {
                UserDefaults.standard.set(Date().timeIntervalSince1970 * 1000,
                                          forKey: Self.activeKey)
                try? await Task.sleep(for: .seconds(60))
            }
        }
    }

    /// Reads facts of connected servers whose numbers are missing or stale.
    func refresh(_ core: CoreBridge, force: Bool = false) async {
        guard let api = core.api else { return }
        let ids = core.servers.filter { $0.state == .ready }.map(\.id)
        let due = ids.filter { id in
            guard !inflight.contains(id) else { return false }
            if force { return true }
            guard let at = fetchedAt[id] else { return true }
            return Date().timeIntervalSince(at) > Self.staleAfter
        }
        // Small waves: each server runs four requests.
        for wave in stride(from: 0, to: due.count, by: 6) {
            let slice = Array(due[wave..<min(wave + 6, due.count)])
            slice.forEach { inflight.insert($0) }
            await withTaskGroup(of: (String, FleetFactsRow?).self) { group in
                for id in slice {
                    group.addTask { (id, try? await api.fleetFacts(serverId: id)) }
                }
                for await (id, row) in group {
                    inflight.remove(id)
                    if let row {
                        facts[id] = row
                        fetchedAt[id] = .now
                    }
                }
            }
        }
    }

    /// Timeline highlights since the operator was last here.
    func refreshDigest(_ core: CoreBridge, intel: IntelStore, force: Bool = false) async {
        guard let api = core.api, !loadingDigest else { return }
        if !force, let at = digestAt, Date().timeIntervalSince(at) < Self.staleAfter { return }
        loadingDigest = true
        defer { loadingDigest = false }
        guard let row = try? await api.timelineFleet(timeline: intel.timeline, limit: 2000) else {
            return
        }
        digest = fleetDigest(items: row.items, sinceMs: previousActiveMs)
        digestAt = .now
    }

    func facts(_ id: String) -> FleetFactsRow? { facts[id] }

    // MARK: fleet totals

    /// Servers with a package list read.
    private var known: [FleetFactsRow] { facts.values.filter { $0.updates != nil } }

    var securityUpdateTotal: Int { known.reduce(0) { $0 + Int($1.securityUpdates ?? 0) } }
    var securityUpdateServers: Int { known.filter { ($0.securityUpdates ?? 0) > 0 }.count }
    var rebootRequiredCount: Int { facts.values.filter(\.rebootRequired).count }
}
