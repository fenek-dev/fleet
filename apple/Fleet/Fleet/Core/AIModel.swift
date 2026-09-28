import AppKit
import Foundation
import LocalAuthentication
import Observation

/// AI access (design §8): the MCP socket, the pause switch, paired
/// clients and the operator's prompts.
///
/// Pairing a new client and approving a wide bulk action take Touch ID
/// here before the answer goes to Rust (which refuses such approvals
/// unless the answer says Touch ID was taken, and checks the prompt's
/// digest). Elevated operations and escalations get their Touch ID from
/// the root key itself when Rust signs the approval (the prompt names the
/// AI client, the operation and the server count), so this sheet only
/// confirms them.
@Observable
@MainActor
final class AIModel {
    private(set) var paused = false
    private(set) var clients: [McpClientRow] = []
    /// Open prompts, oldest first; the sheet shows the first.
    private(set) var prompts: [McpPromptRow] = []
    private(set) var socketError: String?
    private(set) var socketPath: String?

    var current: McpPromptRow? { prompts.first }

    @ObservationIgnored private var core: FleetCore?
    @ObservationIgnored private var server: McpSocketServer?

    /// Once the core is running: delegate, pause state, socket.
    func start(core: FleetCore) {
        guard self.core == nil else { return }
        self.core = core
        core.mcpSetDelegate(delegate: Delegate(model: self))
        paused = core.mcpPaused()
        reloadClients()
        do {
            let path = try McpSocketServer.defaultPath()
            let server = McpSocketServer(path: path) { peer in core.mcpConnect(peer: peer) }
            try server.start()
            self.server = server
            socketPath = path
        } catch {
            socketError = "Couldn't open the MCP socket (\(error))."
        }
    }

    func stop() {
        server?.stop()
        server = nil
    }

    func setPaused(_ p: Bool) {
        guard let core else { return }
        do {
            try core.mcpSetPaused(paused: p)
        } catch {
            socketError = error.fleetMessage
        }
        paused = core.mcpPaused()
        if paused { prompts.removeAll() }
    }

    func reloadClients() {
        clients = (try? core?.mcpClients()) ?? []
    }

    func revoke(_ client: McpClientRow) {
        try? core?.mcpRevokeClient(key: client.key)
        reloadClients()
    }

    /// Touch ID first where this app is the only check (pairing, wide
    /// non-Elevated bulk), then the answer to Rust with the prompt's digest
    /// (Rust also refuses such approvals unless `userVerified`).
    func answer(_ prompt: McpPromptRow, approve: Bool) async {
        var ok = approve
        var verified = false
        if approve, let reason = Self.touchIdReason(prompt) {
            ok = await Self.touchId(reason)
            verified = ok
        }
        _ = core?.mcpResolvePrompt(
            id: prompt.id, approved: ok, digest: prompt.digest, userVerified: verified)
        prompts.removeAll { $0.id == prompt.id }
        if case .pairing = prompt.kind { reloadClients() }
    }

    private static func touchIdReason(_ p: McpPromptRow) -> String? {
        switch p.kind {
        case .pairing(let name, _, let parent, _, let everyTime):
            return everyTime
                ? "allow \(name) (\(parent)) to use Fleet for this session"
                : "allow \(name) (\(parent)) to use Fleet"
        case .approval(let client, _, let op, _, let servers, let elevated, _):
            return elevated
                ? nil : "approve \(op) on \(servers.count) servers for \(client)"
        }
    }

    private static func touchId(_ reason: String) async -> Bool {
        if TestHooks.approve("mcp-approval: " + reason) { return true }
        let ctx = LAContext()
        do {
            return try await ctx.evaluatePolicy(
                .deviceOwnerAuthenticationWithBiometrics, localizedReason: reason)
        } catch {
            return false
        }
    }

    fileprivate func show(_ p: McpPromptRow) {
        if TestHooks.autoPairing, case .pairing = p.kind {
            Task { @MainActor [weak self] in await self?.answer(p, approve: true) }
            return
        }
        // One pairing prompt at a time (Rust enforces it too): a second
        // one is declined rather than queued behind the first.
        if case .pairing = p.kind, prompts.contains(where: {
            if case .pairing = $0.kind { return true } else { return false }
        }) {
            _ = core?.mcpResolvePrompt(
                id: p.id, approved: false, digest: p.digest, userVerified: false)
            return
        }
        prompts.append(p)
        NSApp.activate()
    }

    fileprivate func closed(_ id: UInt64) {
        prompts.removeAll { $0.id == id }
    }
}

/// Called on the core thread; hops to the main actor.
private final class Delegate: McpDelegate, @unchecked Sendable {
    private weak var model: AIModel?

    init(model: AIModel) { self.model = model }

    func onPrompt(prompt: McpPromptRow) {
        Task { @MainActor [weak model] in model?.show(prompt) }
    }

    func onPromptClosed(id: UInt64) {
        Task { @MainActor [weak model] in model?.closed(id) }
    }
}
