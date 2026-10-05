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
    case config = "History"
    case timeline = "Timeline"
    // Not in the mockup's twelve; reached through the "More" menu.
    case users = "Users"
    case mesh = "Mesh"
    case games = "Games"
    var id: String { rawValue }
    /// Stable accessibility name: `serverTab.<identifier>`.
    var identifier: String {
        switch self {
        case .config: "config"
        default: "\(self)"
        }
    }

    /// The twelve tabs of the mockup, in order.
    static let primary: [ServerTab] = [
        .overview, .terminal, .files, .logs, .security, .services,
        .firewall, .packages, .docker, .cron, .config, .timeline,
    ]
    static let more: [ServerTab] = [.users, .mesh, .games]
}

struct ServerDetailView: View {
    @Environment(CoreBridge.self) private var core
    @Environment(IntelStore.self) private var intel
    let serverId: String
    /// Breadcrumb navigation (Fleet, group). Nil: breadcrumb is plain text.
    var navigate: ((NavItem) -> Void)?
    @State private var tab: ServerTab = .overview
    @State private var installing = false
    @State private var running = false
    @State private var ctx = ServerContext()

    init(serverId: String, navigate: ((NavItem) -> Void)? = nil) {
        self.serverId = serverId
        self.navigate = navigate
    }

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
            .onReceive(NotificationCenter.default.publisher(for: .fleetSelectServerTab)) { n in
                if n.userInfo?["serverId"] as? String == serverId,
                   let raw = n.userInfo?["tab"] as? String, let t = ServerTab(rawValue: raw) { tab = t }
            }
            .sheet(isPresented: $installing) { AddServerSheet(existing: server) }
            .sheet(isPresented: $running) { BulkRunSheet(targets: [server.id]) }
            .task(id: "\(serverId)/\(server.agentPinned)/\(server.state == .ready)") {
                guard server.agentPinned, let _ = core.api else { return }
                await ctx.loadFacts(core: core, serverId: serverId)
                await ctx.loadTimeline(core: core, intel: intel, serverId: serverId)
            }
            .onChange(of: core.eventTick) {
                if core.lastEventServer == serverId, server.agentPinned {
                    Task { await ctx.loadTimeline(core: core, intel: intel, serverId: serverId) }
                }
            }
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
                    .accessibilityIdentifier("server.installAgentPrimary")
                    .buttonStyle(.borderedProminent).tint(.accent)
            }
        } else {
            switch tab {
            case .overview: OverviewTab(server: s, ctx: ctx) { tab = $0 }
            case .terminal: TerminalTab(server: s)
            case .files: FilesTab(server: s)
            case .logs: LogsTab(server: s)
            case .security: SecurityTab(server: s)
            case .services: ServicesTab(server: s)
            case .firewall: FirewallTab(server: s)
            case .packages: PackagesTab(server: s)
            case .timeline: TimelineTab(server: s)
            case .users: UsersTab(server: s)
            case .docker: DockerTab(server: s)
            case .cron: CronTab(server: s)
            case .config: ConfigHistoryTab(server: s)
            case .mesh: MeshTab(server: s)
            case .games: GamesTab(server: s)
            }
        }
    }

    // MARK: header

    /// Connection trouble outranks the newest health note.
    private func healthPill(_ s: ServerRow) -> (label: String, tone: Tone, help: String?) {
        if s.state != .ready { return (s.state.label, s.state.tone, nil) }
        if let n = ctx.healthNote {
            return (n.title, n.severity == .critical ? .critical : .warn, n.detail.isEmpty ? nil : n.detail)
        }
        return (s.state.label, s.state.tone, nil)
    }

    private func groupName(_ s: ServerRow) -> String? {
        guard let g = s.groupId else { return nil }
        return core.groups.first { $0.id == g }?.name
    }

    private func crumb(_ label: String, _ target: NavItem, id: String) -> some View {
        Button(label) { navigate?(target) }
            .buttonStyle(.plain)
            .foregroundStyle(Color.textSecondary)
            .disabled(navigate == nil)
            .accessibilityIdentifier(id)
    }

    private func header(_ s: ServerRow) -> some View {
        let pill = healthPill(s)
        return VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 6) {
                crumb("Fleet", .fleet, id: "server.crumb.fleet")
                if let name = groupName(s), let g = s.groupId {
                    Text("/").accessibilityHidden(true)
                    crumb(name, .group(g), id: "server.crumb.group")
                }
                Text("/").accessibilityHidden(true)
                Text(s.name).foregroundStyle(Color.text.opacity(0.85))
                    .accessibilityIdentifier("server.crumb.name")
            }
            .font(.secondary).foregroundStyle(Color.textMuted)
            HStack(alignment: .center, spacing: 16) {
                VStack(alignment: .leading, spacing: 4) {
                    HStack(alignment: .center, spacing: 10) {
                        Text(s.name).font(.serverTitle).foregroundStyle(Color.text)
                            .accessibilityIdentifier("server.name")
                        StatusPill(label: pill.label, tone: pill.tone)
                            .help(pill.help ?? "")
                            .accessibilityIdentifier("server.state")
                    }
                    Text(ServerContext.facts(s, info: ctx.info, health: ctx.health)
                         + (s.proxyJump.map { " · via \($0)" } ?? ""))
                        .font(.mono(12)).foregroundStyle(Color.textSecondary)
                        .lineLimit(2).truncationMode(.tail)
                        .fixedSize(horizontal: false, vertical: true)
                        .help("\(s.user)@\(s.host):\(s.port)")
                        .accessibilityIdentifier("server.facts")
                }
                Spacer()
                if !s.agentPinned {
                    Button("Install agent…", systemImage: "shippingbox") { installing = true }
                        .buttonStyle(.fleetPrimary)
                        .accessibilityIdentifier("server.installAgent")
                }
                if s.agentPinned {
                    SudoPasswordButton(serverId: s.id, serverName: s.name)
                }
                Button("Reconnect", systemImage: "arrow.clockwise") { core.reconnect(s.id) }
                    .buttonStyle(.fleetSecondary)
                    .accessibilityIdentifier("server.reconnect")
                Button("Terminal", systemImage: "terminal") { tab = .terminal }
                    .buttonStyle(.fleetSecondary)
                    .accessibilityIdentifier("server.terminal")
                    .disabled(s.state != .ready)
                Button("Run command") { running = true }
                    .buttonStyle(.fleetPrimary)
                    .accessibilityIdentifier("server.runCommand")
                    .disabled(s.state != .ready || !s.agentPinned)
            }
            if let failure = core.failures[s.id] {
                Text(failure).font(.secondary).foregroundStyle(Tone.critical.text)
            }
            tabBar
        }
        .padding(.horizontal, 28)
        .padding(.top, 16)
        .background(Color.header)
        .overlay(alignment: .bottom) { Rectangle().fill(Color.border).frame(height: 1) }
    }

    private var tabBar: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 22) {
                ForEach(ServerTab.primary) { t in
                    tabButton(t.rawValue, active: tab == t) { tab = t }
                        .accessibilityIdentifier("serverTab.\(t.identifier)")
                }
                Menu {
                    ForEach(ServerTab.more) { t in
                        Button(t.rawValue) { tab = t }
                            .accessibilityIdentifier("serverTab.\(t.identifier)")
                    }
                } label: {
                    tabLabel(ServerTab.more.contains(tab) ? tab.rawValue : "More",
                             active: ServerTab.more.contains(tab), chevron: true)
                }
                // `.button` + plain draws the SwiftUI label as is; the
                // borderless style re-renders it as an accent-tinted AppKit title.
                .menuStyle(.button)
                .buttonStyle(.plain)
                .menuIndicator(.hidden)
                .fixedSize()
                .accessibilityIdentifier("serverTab.more")
            }
        }
    }

    private func tabButton(_ title: String, active: Bool, action: @escaping () -> Void) -> some View {
        Button(action: action) { tabLabel(title, active: active) }
            .buttonStyle(.plain)
    }

    /// 38 px high, 2 px accent underline on the active tab.
    private func tabLabel(_ title: String, active: Bool, chevron: Bool = false) -> some View {
        HStack(spacing: 4) {
            Text(title)
            if chevron { Image(systemName: "chevron.down").font(.system(size: 9, weight: .semibold)) }
        }
            .font(.system(size: 13, weight: .medium))
            .foregroundStyle(active ? Color.text : Color.textSecondary)
            .frame(height: 38)
            .overlay(alignment: .bottom) {
                Rectangle().fill(active ? Color.accent : .clear).frame(height: 2)
            }
            .contentShape(Rectangle())
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
