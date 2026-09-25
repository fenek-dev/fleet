import SwiftUI

extension GameRow: Identifiable { public var id: String { name } }
extension GameBackupRow: Identifiable {}

// MARK: - Mesh

/// Picks members for a fleet-level WireGuard mesh; the core plans the
/// addresses, joins, and distributes public keys (`mesh_orch`).
struct MeshCreateSheet: View {
    @Environment(CoreBridge.self) private var core
    @Environment(\.dismiss) private var dismiss
    let first: ServerRow
    @State private var picked: Set<String> = []
    @State private var endpoints: [String: String] = [:]
    @State private var network = "10.8.0.0/24"
    @State private var port = "51820"
    @State private var running = false
    @State private var result: MeshRunRow?
    @State private var error: String?
    @State private var pending: PendingAction?

    private var candidates: [ServerRow] { core.servers.filter(\.agentPinned) }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("WireGuard mesh").font(.system(size: 15, weight: .semibold))
            Text("Each member gets an address in the network. Keys are generated on the servers; only public keys travel. Every step is auto-reverted and confirmed from a fresh connection. Managed firewalls get a UDP rule for the port.")
                .font(.caption11).foregroundStyle(Color.textMuted)
            HStack {
                TextField("Network", text: $network).frame(width: 160)
                TextField("UDP port", text: $port).frame(width: 90)
            }
            .textFieldStyle(.roundedBorder)
            List(candidates, id: \.id) { s in
                HStack {
                    Toggle(isOn: Binding(get: { picked.contains(s.id) },
                                         set: { if $0 { picked.insert(s.id) } else { picked.remove(s.id) } })) {
                        Text(s.name)
                    }
                    Spacer()
                    TextField("public IP (optional)", text: Binding(get: { endpoints[s.id] ?? "" },
                                                                    set: { endpoints[s.id] = $0 }))
                        .textFieldStyle(.roundedBorder).frame(width: 180)
                }
            }
            .frame(minHeight: 200)
            if let error { Text(error).foregroundStyle(Tone.critical.text).font(.secondary) }
            if let r = result {
                ScrollView {
                    VStack(alignment: .leading, spacing: 2) {
                        ForEach(Indexed.wrap(r.steps)) { st in
                            let name = core.servers.first { $0.id == st.value.serverId }?.name ?? st.value.serverId
                            Text("✓ \(name) · \(st.value.step): \(st.value.detail)").font(.secondary)
                        }
                        if let e = r.error {
                            Text("Stopped: \(e)").font(.secondary).foregroundStyle(Tone.critical.text)
                        } else {
                            Text("Mesh ready.").font(.secondary).foregroundStyle(Tone.ok.text)
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
                .frame(maxHeight: 140)
            }
            HStack {
                if running { ProgressView().controlSize(.small); Text("Working…").font(.secondary) }
                Spacer()
                Button(result == nil ? "Cancel" : "Close") { dismiss() }.disabled(running)
                Button("Create mesh…") { ask() }
                    .buttonStyle(.borderedProminent).tint(.accent)
                    .disabled(running || picked.count < 2 || UInt16(port) == nil)
            }
        }
        .padding(20)
        .frame(minWidth: 560, minHeight: 480)
        .onAppear {
            picked.insert(first.id)
            for s in candidates where s.host.first?.isNumber == true || s.host.contains(":") {
                endpoints[s.id] = s.host
            }
        }
        .confirmAction($pending)
    }

    private func ask() {
        let members = candidates.filter { picked.contains($0.id) }.map {
            MeshMemberArgs(serverId: $0.id, endpoint: endpoints[$0.id].flatMap { $0.isEmpty ? nil : $0 })
        }
        let (net, p) = (network, UInt16(port) ?? 51820)
        pending = PendingAction(title: "Build a mesh of \(members.count) servers?",
                                message: "Network \(net), UDP \(p). Existing members keep their address.",
                                button: "Create") {
            guard let api = core.api else { return }
            running = true
            Task {
                defer { running = false }
                do {
                    result = try await api.meshCreate(network: net, listenPort: p, members: members)
                    error = nil
                } catch {
                    self.error = error.fleetMessage
                }
            }
        }
    }
}

struct MeshTab: View {
    @Environment(CoreBridge.self) private var core
    let server: ServerRow
    @State private var status: MeshStatusRow?
    @State private var creating = false
    @State private var loading = false
    @State private var error: String?
    @State private var pending: PendingAction?
    @State private var revert = AutoRevertModel()

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                TabHeader(title: "Mesh", loading: loading, error: error, refresh: { Task { await load() } }) {
                    Button("Create or extend mesh…", systemImage: "point.3.connected.trianglepath.dotted") {
                        creating = true
                    }
                }
                AutoRevertBanner(model: revert, what: "Mesh membership changed", retry: retryConfirm)
                if let s = status {
                    AdminSection(title: "This server") {
                        if s.joined {
                            Button("Leave…") { askLeave() }.controlSize(.small)
                        }
                    } content: {
                        StatusPill(label: s.joined ? "joined" : "not in a mesh", tone: s.joined ? .ok : .neutral)
                        if let a = s.address { LabeledContent("Address", value: a) }
                        if let p = s.listenPort { LabeledContent("Listen port", value: "udp/\(p)") }
                        if let k = s.publicKey {
                            LabeledContent("Public key") { Text(k).font(.mono(11)).textSelection(.enabled) }
                        }
                    }
                    AdminSection(title: "Peers") {
                        ForEach(Indexed.wrap(s.peers)) { p in
                            HStack {
                                Text(p.value.allowedIps.joined(separator: ", ")).font(.mono(11))
                                    .frame(width: 160, alignment: .leading)
                                Text(p.value.endpoint ?? "dials out").frame(width: 170, alignment: .leading)
                                Text(p.value.publicKey.prefix(12) + "…").font(.mono(11))
                                    .foregroundStyle(Color.textSecondary)
                                Spacer()
                                let fresh = p.value.lastHandshakeMs.map {
                                    Date().timeIntervalSince1970 * 1000 - Double($0) < 180_000
                                } ?? false
                                StatusPill(label: fresh ? "connected" : "no handshake", tone: fresh ? .ok : .warn)
                                Text("↓\(Format.bytes(p.value.rxBytes)) ↑\(Format.bytes(p.value.txBytes))")
                                    .font(.caption11).foregroundStyle(Color.textMuted)
                            }
                            .font(.secondary)
                        }
                        if s.peers.isEmpty { Text("None").font(.secondary).foregroundStyle(Color.textMuted) }
                    }
                }
            }
            .padding(24)
        }
        .task(id: server.id) { await load() }
        .confirmAction($pending)
        .sheet(isPresented: $creating, onDismiss: { Task { await load() } }) { MeshCreateSheet(first: server) }
    }

    private func askLeave() {
        pending = PendingAction(title: "Take \(server.name) out of the mesh?",
                                message: "Other members keep it as a peer until the mesh is rebuilt. Reverts automatically unless confirmed.",
                                button: "Leave", destructive: true) {
            guard let api = core.api else { return }
            Task {
                do {
                    let c = try await api.meshLeave(serverId: server.id)
                    revert.confirm(api: api, serverId: server.id, change: c) { Task { await load() } }
                } catch {
                    self.error = error.fleetMessage
                }
            }
        }
    }

    private func retryConfirm() {
        guard let api = core.api, let c = revert.change else { return }
        revert.confirm(api: api, serverId: server.id, change: c) { Task { await load() } }
    }

    private func load() async {
        guard let api = core.api else { return }
        loading = true
        defer { loading = false }
        do {
            status = try await api.meshStatus(serverId: server.id)
            error = nil
        } catch {
            self.error = error.fleetMessage
        }
    }
}

// MARK: - Game servers

struct GameInstallSheet: View {
    @Environment(\.dismiss) private var dismiss
    let install: (String, String) -> Void
    @State private var name = ""
    @State private var template = "minecraft-paper"

    var body: some View {
        Form {
            TextField("Instance name", text: $name)
            Picker("Template", selection: $template) {
                Text("Minecraft (Paper)").tag("minecraft-paper")
                Text("Valheim").tag("valheim")
            }
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }
                Button("Install…") { install(name, template); dismiss() }
                    .buttonStyle(.borderedProminent).tint(.accent).disabled(name.isEmpty)
            }
        }
        .padding(20)
        .frame(width: 380)
    }
}

struct GameConsoleSheet: View {
    @Environment(CoreBridge.self) private var core
    @Environment(\.dismiss) private var dismiss
    let serverId: String
    let game: String
    @State private var command = ""
    @State private var log: [String] = []
    @State private var backups: [GameBackupRow] = []
    @State private var error: String?
    @State private var pending: PendingAction?

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Text(game).font(.system(size: 15, weight: .semibold))
                Spacer()
                Button("Close") { dismiss() }
            }
            Text("RCON console").font(.system(size: 13, weight: .semibold))
            ScrollView {
                Text(log.joined(separator: "\n")).font(.mono(11)).textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
            .frame(minHeight: 160)
            .padding(8)
            .background(Color.track, in: RoundedRectangle(cornerRadius: 8))
            HStack {
                TextField("Command, e.g. list", text: $command).textFieldStyle(.roundedBorder)
                    .onSubmit(send)
                Button("Send", action: send).disabled(command.isEmpty)
            }
            if let error { Text(error).foregroundStyle(Tone.warn.text).font(.secondary) }
            Text("Backups").font(.system(size: 13, weight: .semibold))
            List(backups) { b in
                HStack {
                    Text(fmtDate(b.timeMs))
                    Text(Format.bytes(b.sizeBytes)).foregroundStyle(Color.textSecondary)
                    Spacer()
                    Button("Restore…") { askRestore(b) }.controlSize(.small)
                }
                .font(.secondary)
            }
            .frame(minHeight: 120)
        }
        .padding(20)
        .frame(minWidth: 620, minHeight: 520)
        .task { await loadBackups() }
        .confirmAction($pending)
    }

    private func send() {
        guard let api = core.api, !command.isEmpty else { return }
        let c = command
        command = ""
        log.append("> \(c)")
        Task {
            do {
                log.append(try await api.gameRcon(serverId: serverId, name: game, command: c))
                error = nil
            } catch {
                self.error = error.fleetMessage
            }
        }
    }

    private func askRestore(_ b: GameBackupRow) {
        pending = PendingAction(title: "Restore \(game) from \(fmtDate(b.timeMs))?",
                                message: "The instance's data is replaced with this backup.",
                                button: "Restore", destructive: true) {
            guard let api = core.api else { return }
            Task {
                do {
                    try await api.gameRestore(serverId: serverId, name: game, backupId: b.id)
                    error = nil
                } catch {
                    self.error = error.fleetMessage
                }
            }
        }
    }

    private func loadBackups() async {
        guard let api = core.api else { return }
        do { backups = try await api.gameBackups(serverId: serverId, name: game) } catch { self.error = error.fleetMessage }
    }
}

struct GamesTab: View {
    @Environment(CoreBridge.self) private var core
    let server: ServerRow
    @State private var games: [GameRow] = []
    @State private var installing = false
    @State private var console: GameRow?
    @State private var loading = false
    @State private var error: String?
    @State private var pending: PendingAction?

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            TabHeader(title: "Game servers", loading: loading, error: error, refresh: { Task { await load() } }) {
                Button("Install…", systemImage: "plus") { installing = true }
            }
            Table(games) {
                TableColumn("Name") { g in Text(g.name) }
                TableColumn("Template") { g in Text(g.template) }.width(140)
                TableColumn("State") { g in StatusPill(label: g.running ? "running" : "stopped", tone: g.running ? .ok : .neutral) }
                    .width(100)
                TableColumn("Players") { g in Text(g.players.map(String.init) ?? "–") }.width(70)
                TableColumn("Version") { g in Text(g.version ?? "–").lineLimit(1) }.width(110)
                TableColumn("Last backup") { g in Text(fmtDate(g.lastBackupMs)) }.width(140)
                TableColumn("") { g in
                    Menu {
                        Button("Console & backups…") { console = g }
                        Divider()
                        Button("Start") { ask(g, .start) }
                        Button("Stop") { ask(g, .stop) }
                        Button("Restart") { ask(g, .restart) }
                        Button("Update") { ask(g, .update) }
                        Button("Back up now") { ask(g, .backup) }
                        Divider()
                        Button("Remove…") { askRemove(g) }
                    } label: { Image(systemName: "ellipsis.circle") }
                    .menuStyle(.borderlessButton).frame(width: 30)
                }
                .width(40)
            }
            .tableCard()
        }
        .padding(24)
        .task(id: server.id) { await load() }
        .confirmAction($pending)
        .sheet(item: $console) { g in GameConsoleSheet(serverId: server.id, game: g.name) }
        .sheet(isPresented: $installing) {
            GameInstallSheet { name, template in
                pending = PendingAction(title: "Install \(template) as \(name) on \(server.name)?",
                                        message: "Creates the instance from the built-in template. Allow its ports in the Firewall tab if the table is Managed.",
                                        button: "Install") {
                    run { try await $0.gameInstall(serverId: server.id, name: name, template: template) }
                }
            }
        }
    }

    private func ask(_ g: GameRow, _ a: GameAction) {
        let (verb, msg, destructive): (String, String, Bool) = switch a {
        case .start: ("Start", "", false)
        case .stop: ("Stop", "Players are disconnected.", true)
        case .restart: ("Restart", "Players are disconnected briefly.", false)
        case .update: ("Update", "The server restarts on the new version.", false)
        case .backup: ("Back up", "", false)
        }
        pending = PendingAction(title: "\(verb) \(g.name)?", message: msg, button: verb, destructive: destructive) {
            run { try await $0.gameAction(serverId: server.id, name: g.name, action: a) }
        }
    }

    private func askRemove(_ g: GameRow) {
        pending = PendingAction(title: "Remove \(g.name) from \(server.name)?",
                                message: "The unit is removed; the world data and backups are kept.",
                                button: "Remove", destructive: true) {
            run { try await $0.gameRemove(serverId: server.id, name: g.name, keepData: true) }
        }
    }

    private func run(_ op: @escaping (FleetCore) async throws -> Void) {
        guard let api = core.api else { return }
        Task {
            do {
                try await op(api)
                error = nil
            } catch {
                self.error = error.fleetMessage
            }
            await load()
        }
    }

    private func load() async {
        guard let api = core.api else { return }
        loading = true
        defer { loading = false }
        do {
            games = try await api.gameStatus(serverId: server.id)
            error = nil
        } catch {
            self.error = error.fleetMessage
        }
    }
}
