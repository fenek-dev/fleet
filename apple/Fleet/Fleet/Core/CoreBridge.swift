import Foundation
import Observation

/// Main-actor model over the Rust `FleetCore`. The core's listener runs on
/// the core thread; `Listener` hops every update to the main actor.
@Observable
@MainActor
final class CoreBridge {
    enum Status: Equatable {
        case starting
        case running
        /// No fleet/device id yet: the table works, nothing connects.
        case notEnrolled
        case failed(String)
    }

    private(set) var status: Status = .starting
    private(set) var servers: [ServerRow] = []
    private(set) var groups: [GroupRow] = []
    /// Open alerts, keyed by server + rule + subject.
    private(set) var alerts: [String: AgentEventRow] = [:]
    private(set) var hostKeyPrompts: [HostKeyPrompt] = []
    private(set) var failures: [String: String] = [:]
    private(set) var usesSoftwareKeys = false

    @ObservationIgnored private var core: FleetCore?

    var onlineCount: Int { servers.filter { $0.state == .ready }.count }
    var criticalCount: Int {
        alerts.values.filter { $0.alert?.severity == .critical }.count
    }

    /// Opens the cache and starts the manager. Errors land in `status`.
    func open(keys: SecureEnclaveKeys, keyStore: KeyStore) {
        usesSoftwareKeys = keys.usesSoftwareKeys
        do {
            let path = try Self.cachePath()
            let core = try FleetCore.open(cachePath: path, signer: keys, keyStore: keyStore)
            self.core = core
            reload()
            do {
                try core.start(listener: Listener(bridge: self))
                status = .running
            } catch FleetError.NotEnrolled {
                status = .notEnrolled
            }
        } catch {
            status = .failed(String(describing: error))
        }
    }

    func fail(_ message: String) {
        status = .failed(message)
    }

    func reload() {
        guard let core else { return }
        do {
            servers = try core.listServers()
            groups = try core.listGroups()
        } catch {
            status = .failed(String(describing: error))
        }
    }

    func setLocked(_ locked: Bool) {
        core?.setSessionKind(kind: locked ? .monitor : .device)
    }

    func addServer(_ s: NewServer) throws {
        guard let core else { return }
        _ = try core.addServer(server: s)
        reload()
    }

    func addGroup(_ name: String) throws {
        guard let core else { return }
        _ = try core.addGroup(name: name)
        reload()
    }

    func removeServer(_ id: String) throws {
        try core?.removeServer(serverId: id)
        reload()
    }

    func reconnect(_ id: String) {
        try? core?.reconnect(serverId: id)
    }

    func resolveHostKey(_ prompt: HostKeyPrompt, accept: Bool) {
        hostKeyPrompts.removeAll { $0 == prompt }
        if accept {
            try? core?.acceptHostKey(serverId: prompt.serverId)
        } else {
            try? core?.rejectHostKey(serverId: prompt.serverId)
        }
    }

    func systemInfo(_ id: String) async throws -> SystemInfoRow {
        guard let core else { throw FleetError.NotStarted }
        return try await core.systemInfo(serverId: id)
    }

    func agentHealth(_ id: String) async throws -> AgentHealthRow {
        guard let core else { throw FleetError.NotStarted }
        return try await core.agentHealth(serverId: id)
    }

    // MARK: listener updates

    fileprivate func apply(_ change: StateChange) {
        if let i = servers.firstIndex(where: { $0.id == change.serverId }) {
            servers[i].state = change.state
        }
        failures[change.serverId] = change.failure
    }

    fileprivate func apply(_ event: AgentEventRow) {
        guard let alert = event.alert else { return }
        let key = "\(event.serverId)|\(alert.ruleId)|\(alert.subject)"
        if alert.cleared {
            alerts[key] = nil
        } else {
            alerts[key] = event
        }
    }

    fileprivate func apply(_ prompt: HostKeyPrompt) {
        if !hostKeyPrompts.contains(prompt) { hostKeyPrompts.append(prompt) }
    }

    private static func cachePath() throws -> String {
        let dir = try FileManager.default.url(
            for: .applicationSupportDirectory, in: .userDomainMask,
            appropriateFor: nil, create: true
        ).appendingPathComponent("Fleet", isDirectory: true)
        try FileManager.default.createDirectory(
            at: dir, withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700])
        return dir.appendingPathComponent("cache.sqlite").path
    }
}

/// Runs on the core thread; must return quickly.
private final class Listener: CoreListener {
    private let bridge: CoreBridge

    init(bridge: CoreBridge) { self.bridge = bridge }

    func onState(change: StateChange) {
        Task { @MainActor [bridge] in bridge.apply(change) }
    }

    func onHostKey(prompt: HostKeyPrompt) {
        Task { @MainActor [bridge] in bridge.apply(prompt) }
    }

    func onEvent(event: AgentEventRow) {
        Task { @MainActor [bridge] in bridge.apply(event) }
    }

    func onResync() {
        Task { @MainActor [bridge] in bridge.reload() }
    }
}
