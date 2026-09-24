import SwiftUI

enum ServerTab: String, CaseIterable, Identifiable {
    case overview = "Overview"
    case terminal = "Terminal"
    case files = "Files"
    case logs = "Logs"
    case security = "Security"
    case services = "Services"
    case firewall = "Firewall"
    case packages = "Packages"
    case docker = "Docker"
    case cron = "Cron"
    case config = "Config history"
    case timeline = "Timeline"
    var id: String { rawValue }
}

struct ServerDetailView: View {
    @Environment(CoreBridge.self) private var core
    let serverId: String
    @State private var tab: ServerTab = .overview

    private var server: ServerRow? { core.servers.first { $0.id == serverId } }

    var body: some View {
        if let server {
            VStack(alignment: .leading, spacing: 0) {
                header(server)
                ScrollView {
                    Group {
                        switch tab {
                        case .overview: OverviewTab(server: server)
                        default: PlaceholderTab(name: tab.rawValue)
                        }
                    }
                    .padding(24)
                }
            }
            .background(Color.window)
            .id(serverId)
        } else {
            ContentUnavailableView("Server removed", systemImage: "server.rack")
        }
    }

    private func header(_ s: ServerRow) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(alignment: .firstTextBaseline, spacing: 12) {
                Text(s.name).font(.serverTitle).foregroundStyle(Color.text)
                StatusPill(label: s.state.label, tone: s.state.tone)
                Spacer()
                Button("Reconnect", systemImage: "arrow.clockwise") { core.reconnect(s.id) }
                Button("Terminal", systemImage: "terminal") {}
                    .disabled(true)
                    .help("Terminal arrives with PTY support")
            }
            Text("\(s.user)@\(s.host):\(s.port)")
                .font(.mono(12)).foregroundStyle(Color.textMuted)
            if let failure = core.failures[s.id] {
                Text(failure).font(.secondary).foregroundStyle(Tone.critical.text)
            }
            ScrollView(.horizontal, showsIndicators: false) {
                HStack(spacing: 4) {
                    ForEach(ServerTab.allCases) { t in
                        Button(t.rawValue) { tab = t }
                            .buttonStyle(.plain)
                            .font(.base)
                            .foregroundStyle(tab == t ? Color.text : Color.textSecondary)
                            .padding(.horizontal, 10)
                            .frame(height: 28)
                            .background(tab == t ? Color.selected : .clear,
                                        in: RoundedRectangle(cornerRadius: 8))
                    }
                }
            }
        }
        .padding(.horizontal, 24)
        .padding(.vertical, 16)
        .background(Color.header)
    }
}

/// `system.info` and `agent.health`, fetched on appear and on refresh.
/// Every string here came from the server (untrusted, display only).
private struct OverviewTab: View {
    @Environment(CoreBridge.self) private var core
    let server: ServerRow
    @State private var info: SystemInfoRow?
    @State private var health: AgentHealthRow?
    @State private var error: String?
    @State private var loading = false

    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            HStack {
                Text("Resources").font(.system(size: 15, weight: .semibold))
                Spacer()
                Button("Refresh", systemImage: "arrow.clockwise") { Task { await load() } }
                    .disabled(loading)
            }
            if let error {
                Text(error).font(.base).foregroundStyle(Tone.warn.text)
            }
            HStack(alignment: .top, spacing: 16) {
                section("System") {
                    if let info {
                        row("Hostname", info.hostname)
                        row("OS", "\(info.osId) \(info.osVersion)")
                        row("Kernel", info.kernel, mono: true)
                        row("Architecture", info.arch)
                        row("CPUs", "\(info.cpuCount)")
                        row("Memory", Format.bytes(info.memTotalBytes))
                        row("Uptime", Format.uptime(info.uptimeS))
                    } else {
                        placeholder
                    }
                }
                section("Agent") {
                    if let health {
                        row("Version", health.agentVersion, mono: true)
                        row("Protocol", "v\(health.protoVersion)")
                        row("Uptime", Format.uptime(health.uptimeS))
                        row("Gate memory", Format.bytes(health.gateRssBytes))
                        row("Exec memory", Format.bytes(health.execRssBytes))
                        row("Audit seq", "\(health.auditSeq)")
                        row("Roster", "epoch \(health.rosterEpoch) · v\(health.rosterVersion)")
                        row("Policy", "v\(health.policyVersion)")
                        if health.recoveryPending {
                            StatusPill(label: "Recovery pending", tone: .critical)
                        }
                    } else {
                        placeholder
                    }
                }
            }
            HStack(alignment: .top, spacing: 16) {
                section("Top processes") { Text("Arrives with telemetry streams.").foregroundStyle(Color.textMuted) }
                section("Timeline") { Text("Arrives with the event history.").foregroundStyle(Color.textMuted) }
            }
        }
        .task(id: server.id) { await load() }
    }

    private var placeholder: some View {
        Text(loading ? "Loading…" : "No data").foregroundStyle(Color.textMuted)
    }

    private func load() async {
        loading = true
        defer { loading = false }
        error = nil
        // agent.health works on monitor sessions; system.info needs unlock.
        do {
            health = try await core.agentHealth(server.id)
        } catch {
            self.error = Self.describe(error)
        }
        do {
            info = try await core.systemInfo(server.id)
        } catch {
            self.error = Self.describe(error)
        }
    }

    static func describe(_ error: Error) -> String {
        guard let e = error as? FleetError else { return "Request failed." }
        switch e {
        case .NotStarted, .NotEnrolled: return "Not connected: this Mac is not enrolled."
        case .NotReady(let state): return "Not connected (\(state.label))."
        case .Locked: return "Unlock to load system details."
        case .Timeout: return "The server did not answer in time."
        case .Agent(let code): return "The agent refused the request (\(code))."
        case .UnknownServer: return "Server not managed yet (agent keys not pinned)."
        default: return "Request failed."
        }
    }

    private func section(_ title: String, @ViewBuilder _ content: () -> some View) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(title).font(.system(size: 13, weight: .semibold)).foregroundStyle(Color.text)
            content()
        }
        .frame(maxWidth: .infinity, alignment: .topLeading)
        .card()
    }

    private func row(_ label: String, _ value: String, mono: Bool = false) -> some View {
        HStack {
            Text(label).foregroundStyle(Color.textSecondary)
            Spacer()
            Text(value)
                .font(mono ? .mono(12) : .base)
                .foregroundStyle(Color.text)
                .lineLimit(1)
                .truncationMode(.middle)
                .textSelection(.enabled)
        }
        .font(.base)
    }
}

struct PlaceholderTab: View {
    let name: String

    var body: some View {
        ContentUnavailableView(name, systemImage: "hammer",
                               description: Text("Not built yet."))
            .frame(maxWidth: .infinity, minHeight: 300)
    }
}
