import CryptoKit
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
        /// No fleet/device id yet: onboarding (create a fleet) comes first.
        case notEnrolled
        case failed(String)
    }

    private(set) var status: Status = .starting
    /// Ad-hoc build: the core opens after the first unlock of this run.
    var awaitingFirstUnlock = false
    private(set) var servers: [ServerRow] = []
    private(set) var groups: [GroupRow] = []
    /// Open alerts, keyed by server + rule + subject.
    private(set) var alerts: [String: AgentEventRow] = [:]
    private(set) var hostKeyPrompts: [HostKeyPrompt] = []
    private(set) var failures: [String: String] = [:]
    private(set) var usesSoftwareKeys = false
    private(set) var fleetName: String?
    /// A security failure that needs the operator (cache integrity, missing
    /// or invalidated keys). Shown as an alert and a persistent banner.
    private(set) var securityAlert: String?
    /// The alert was dismissed (the banner stays).
    var securityAlertSeen = false
    /// Bumped on every live agent event; `lastEventServer` names its
    /// server (the timeline catches up on it).
    private(set) var eventTick = 0
    private(set) var lastEventServer: String?
    /// Fleet-level alerts: Mac added/revoked, recovery pending, removed
    /// from the fleet, pin changes, sync conflicts (design §5.10, §7.6).
    private(set) var fleetAlerts: [FleetAlertRow] = []
    /// Bumped when synced data or the roster changed (views reload).
    private(set) var fleetRevision = 0
    /// iCloud sync (created on open).
    @ObservationIgnored private(set) var sync: SyncCoordinator?

    @ObservationIgnored private var core: FleetCore?
    @ObservationIgnored private var keys: SecureEnclaveKeys?

    /// The Rust core, for typed calls from the server tabs. `nil` until
    /// `open` succeeded.
    var api: FleetCore? { core }

    var onlineCount: Int { servers.filter { $0.state == .ready }.count }
    var criticalCount: Int {
        alerts.values.filter { $0.alert?.severity == .critical }.count
    }

    /// Opens the cache and starts the manager. Errors land in `status`.
    func open(keys: SecureEnclaveKeys, keyStore: KeyStore) {
        usesSoftwareKeys = keys.usesSoftwareKeys
        self.keys = keys
        do {
            let path = try Self.cachePath()
            let core = try FleetCore.open(cachePath: path, signer: keys, keyStore: keyStore)
            self.core = core
            core.setSyncSecrets(secrets: SyncKeychain(software: keys.usesSoftwareKeys))
            core.setFleetListener(listener: FleetEvents(bridge: self))
            sync = SyncCoordinator(bridge: self)
            // Keys may be generated only before enrollment; afterwards a
            // missing key is an error, never a silent replacement.
            keys.creationAllowed = !core.isEnrolled()
            reload()
            startManager()
        } catch {
            report(error)
            status = .failed(error.fleetMessage)
        }
    }

    /// Starts the connection manager; after enrollment too.
    func startManager() {
        guard let core else { return }
        fleetName = core.fleetName()
        do {
            try core.start(listener: Listener(bridge: self))
            keys?.creationAllowed = false
            status = .running
            sync?.start()
            #if FLEET_TEST_HOOKS
            exportTestKeys()
            #endif
        } catch FleetError.NotEnrolled {
            status = .notEnrolled
        } catch FleetError.AlreadyStarted {
            status = .running
            sync?.start()
        } catch {
            report(error)
            status = .failed(String(describing: error))
        }
    }

    /// Raises the security alert for errors that mean tampering or lost
    /// keys; other errors are left to the caller.
    func report(_ error: Error) {
        guard let e = error as? FleetError else { return }
        switch e {
        case .CacheIntegrity, .CacheKeyMissing, .Keys(error: .Missing), .Keys(error: .Invalidated):
            securityAlert = e.fleetMessage
            securityAlertSeen = false
        default:
            break
        }
    }

    #if FLEET_TEST_HOOKS
    /// Test hook: writes `<dataDir>/ssh_pubkey` and `monitor_ssh_pubkey`
    /// (OpenSSH lines) so testers can authorize this Mac without the UI.
    private func exportTestKeys() {
        if let k = try? core?.sshPublicKey() { TestHooks.export("ssh_pubkey", k) }
        if let raw = try? keys?.publicKey(role: .monitorSsh),
           let pk = try? P256.Signing.PublicKey(compressedRepresentation: raw)
        {
            func str(_ d: Data) -> Data {
                var n = UInt32(d.count).bigEndian
                return Data(bytes: &n, count: 4) + d
            }
            let blob = str(Data("ecdsa-sha2-nistp256".utf8)) + str(Data("nistp256".utf8))
                + str(pk.x963Representation)
            TestHooks.export("monitor_ssh_pubkey",
                             "ecdsa-sha2-nistp256 \(blob.base64EncodedString()) fleet-monitor")
        }
    }
    #endif

    func fail(_ message: String) {
        status = .failed(message)
    }

    func reload() {
        guard let core else { return }
        do {
            servers = try core.listServers()
            groups = try core.listGroups()
        } catch {
            report(error)
            status = .failed(error.fleetMessage)
        }
    }

    func setLocked(_ locked: Bool) {
        core?.setSessionKind(kind: locked ? .monitor : .device)
    }

    @discardableResult
    func addServer(_ s: NewServer) throws -> ServerRow? {
        guard let core else { return nil }
        let row = try core.addServer(server: s)
        reload()
        return row
    }

    func addGroup(_ name: String) throws {
        guard let core else { return }
        _ = try core.addGroup(name: name)
        reload()
    }

    func renameGroup(_ id: String, _ name: String) throws {
        try core?.renameGroup(groupId: id, name: name)
        reload()
    }

    /// Servers in the group become ungrouped.
    func removeGroup(_ id: String) throws {
        try core?.removeGroup(groupId: id)
        reload()
    }

    /// Group (nil = none) and tags of an existing server.
    func setPlacement(_ id: String, groupId: String?, tags: [String]) throws {
        try core?.setServerPlacement(serverId: id, groupId: groupId, tags: tags)
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
            // Pins exactly the fingerprints this prompt showed.
            do {
                try core?.acceptHostKey(serverId: prompt.serverId, fingerprint: prompt.fingerprint,
                                        jumpFingerprints: prompt.jumps.map(\.fingerprint))
            } catch {
                report(error)
                failures[prompt.serverId] = error.fleetMessage
            }
        } else {
            try? core?.rejectHostKey(serverId: prompt.serverId)
        }
        reload()
    }

    func sshPublicKey() -> String? {
        try? core?.sshPublicKey()
    }

    func systemInfo(_ id: String) async throws -> SystemInfoRow {
        guard let core else { throw FleetError.NotStarted }
        return try await core.systemInfo(serverId: id)
    }

    func agentHealth(_ id: String) async throws -> AgentHealthRow {
        guard let core else { throw FleetError.NotStarted }
        return try await core.agentHealth(serverId: id)
    }

    // MARK: multi-Mac

    /// New enclave keys may be created (joining or recovering a fleet).
    func allowKeyCreation(_ allowed: Bool) {
        keys?.creationAllowed = allowed
    }

    var usesSoftwareEnclave: Bool { keys?.usesSoftwareKeys ?? false }

    func dismissFleetAlert(_ a: FleetAlertRow) {
        fleetAlerts.removeAll { $0 == a }
    }

    fileprivate func apply(_ a: FleetAlertRow) {
        if !fleetAlerts.contains(a) { fleetAlerts.append(a) }
    }

    fileprivate func syncChanged() {
        fleetRevision += 1
        reload()
    }

    // MARK: listener updates

    fileprivate func apply(_ change: StateChange) {
        if let i = servers.firstIndex(where: { $0.id == change.serverId }) {
            servers[i].state = change.state
        } else {
            reload()
        }
        failures[change.serverId] = change.failure
    }

    fileprivate func apply(_ event: AgentEventRow) {
        lastEventServer = event.serverId
        eventTick &+= 1
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

    fileprivate func apply(_ m: ServerMetricsRow) {
        guard let i = servers.firstIndex(where: { $0.id == m.serverId }) else { return }
        servers[i].cpuPercent = m.cpuPercent
        servers[i].memPercent = m.memPercent
        servers[i].diskPercent = m.diskPercent
        servers[i].lastSeenMs = m.timeMs
    }

    private static func cachePath() throws -> String {
        try AppPaths.cachePath()
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

    func onMetrics(row: ServerMetricsRow) {
        Task { @MainActor [bridge] in bridge.apply(row) }
    }
}

/// Fleet alerts and sync changes, on the core thread; hops to main.
private final class FleetEvents: FleetListener {
    private let bridge: CoreBridge

    init(bridge: CoreBridge) { self.bridge = bridge }

    func onFleetAlert(alert: FleetAlertRow) {
        Task { @MainActor [bridge] in bridge.apply(alert) }
    }

    func onSyncChanged() {
        Task { @MainActor [bridge] in bridge.syncChanged() }
    }
}

extension Error {
    /// Operator-facing wording for core errors (Rust sends fixed codes).
    var fleetMessage: String {
        guard let e = self as? FleetError else { return "Request failed." }
        switch e {
        case .NotStarted, .NotEnrolled: return "Not connected: this Mac is not enrolled."
        case .NotReady(let state): return "Not connected (\(state.label))."
        case .Locked: return "Unlock Fleet first."
        case .Timeout: return "The server did not answer in time."
        case .Agent(let code): return agentCodeMessage(code)
        case .UnexpectedReply: return "The agent sent an unexpected answer."
        case .UnknownServer: return "Server not managed yet (agent keys not pinned)."
        case .InvalidArgument(let field): return "Invalid \(field)."
        case .Cancelled: return "Cancelled."
        case .HostKeyNotConfirmed: return "Confirm the server's host key first."
        case .SshKeyRefused: return "The server refused this Mac's SSH key. Add it to the user's authorized_keys."
        case .PasswordRefused: return "The server refused the password."
        case .PasswordLoginUnavailable(let m): return m
        case .SudoPasswordRequired: return "sudo needs a password on this server. Enter the user's password (used once, not stored)."
        case .SudoPasswordRefused: return "sudo refused the password. Check it and try again."
        case .HostKeyChanged: return "The server's host key changed. Check the server before trusting it."
        case .Ssh(let m): return "SSH failed: \(m)"
        case .Install(let m): return "Install failed: \(m)"
        case .FileNotFound: return "No such file."
        case .FilePermissionDenied: return "Permission denied."
        case .FileChanged: return "The file changed on the server since it was opened."
        case .FileTooLarge(let size): return "File too large to edit (\(Format.bytes(size)))."
        case .File(let m): return "File operation failed: \(m)"
        case .Enrollment(let reason): return "Enrollment: \(reason)."
        case .Stream(let m): return "Stream failed: \(m)"
        case .VulnData(let m): return "Vulnerability data: \(m)"
        case .Session(let m): return "Session error: \(m)"
        case .HostKeyMismatch: return "The host key differs from the fingerprint you confirmed. Nothing was pinned."
        case .HostKeyAlreadyPinned: return "This server already has a pinned host key. Use Replace host key to change it."
        case .CacheIntegrity(let what):
            return "The local database was modified outside Fleet (\(what) failed its integrity check). Pins can't be trusted; restore it or re-enroll."
        case .CacheKeyMissing:
            return "The database integrity key is missing from the Keychain. Pins can't be verified; restore the Keychain item or re-enroll."
        case .Keys(error: .Missing):
            return "A Fleet key is missing from the Keychain. It was not replaced: restore it, or have another Mac (or the recovery code) enroll this Mac again."
        case .Keys(error: .Invalidated):
            return "The root key was invalidated (Touch ID fingerprints changed). Create a new root key and have another Mac or the recovery code approve it."
        case .Keys: return "Key store unavailable."
        case .Roster(let reason): return "Roster: \(reason)."
        case .Sync(let reason): return "Sync: \(reason)."
        case .Recovery(let reason): return "Recovery: \(reason)."
        case .Provision(let reason): return "Provisioning: \(reason)."
        case .PolicyOutOfDate: return "Policy out of date, refresh."
        default: return "Request failed."
        }
    }
}
