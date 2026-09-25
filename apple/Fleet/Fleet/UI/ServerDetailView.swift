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
    @State private var installing = false

    private var server: ServerRow? { core.servers.first { $0.id == serverId } }

    var body: some View {
        if let server {
            VStack(alignment: .leading, spacing: 0) {
                header(server)
                content(server)
                    .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
            }
            .background(Color.window)
            .id(serverId)
            .sheet(isPresented: $installing) { AddServerSheet(existing: server) }
        } else {
            ContentUnavailableView("Server removed", systemImage: "server.rack")
        }
    }

    @ViewBuilder private func content(_ s: ServerRow) -> some View {
        // Terminals and SFTP ride the agent session's SSH connection too.
        if !s.agentPinned {
            ContentUnavailableView {
                Label("Agent not installed", systemImage: "shippingbox")
            } description: {
                Text("Install the Fleet agent to see live data and manage this server.")
            } actions: {
                Button("Install agent…") { installing = true }
                    .buttonStyle(.borderedProminent).tint(.accent)
            }
        } else {
            switch tab {
            case .overview: OverviewTab(server: s)
            case .terminal: TerminalTab(server: s)
            case .files: FilesTab(server: s)
            case .logs: LogsTab(server: s)
            case .security: SecurityTab(server: s)
            case .services: ServicesTab(server: s)
            case .firewall: FirewallTab(server: s)
            case .packages: PackagesTab(server: s)
            case .timeline: TimelineTab(server: s)
            case .docker, .cron, .config: PlaceholderTab(name: tab.rawValue)
            }
        }
    }

    private func header(_ s: ServerRow) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(alignment: .firstTextBaseline, spacing: 12) {
                Text(s.name).font(.serverTitle).foregroundStyle(Color.text)
                StatusPill(label: s.state.label, tone: s.state.tone)
                Spacer()
                if !s.agentPinned {
                    Button("Install agent…", systemImage: "shippingbox") { installing = true }
                }
                if s.agentPinned {
                    SudoPasswordButton(serverId: s.id, serverName: s.name)
                }
                Button("Reconnect", systemImage: "arrow.clockwise") { core.reconnect(s.id) }
                Button("Terminal", systemImage: "terminal") { tab = .terminal }
                    .disabled(s.state != .ready)
            }
            HStack(spacing: 6) {
                Text("\(s.user)@\(s.host):\(s.port)")
                if let j = s.proxyJump { Text("via \(j)") }
            }
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

struct PlaceholderTab: View {
    let name: String

    var body: some View {
        ContentUnavailableView(name, systemImage: "hammer",
                               description: Text("Not built yet."))
            .frame(maxWidth: .infinity, minHeight: 300)
    }
}
