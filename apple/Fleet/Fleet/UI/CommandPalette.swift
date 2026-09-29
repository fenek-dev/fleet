import SwiftUI

/// One row of the ⌘K palette.
struct PaletteAction: Identifiable {
    let id: String
    let title: String
    let subtitle: String
    let symbol: String
    let run: @MainActor () -> Void
}

extension OpDraft.Kind {
    /// Palette wording for the operation.
    var paletteTitle: String {
        switch self {
        case .agentHealth: "Check agent health"
        case .unit: "Restart, stop or start a service"
        case .pkgRefresh: "Refresh package lists"
        case .pkgUpgrade: "Upgrade packages"
        case .container: "Restart, stop or start a container"
        case .composePull: "Pull a Compose project"
        case .composeRestart: "Restart a Compose project"
        case .configRollback: "Roll back a config file"
        case .profileCheck: "Check the hardening profile"
        case .reboot: "Reboot"
        case .shell: "Run a shell command"
        }
    }

    var paletteSymbol: String {
        switch self {
        case .shell: "terminal"
        case .reboot: "power"
        case .pkgRefresh, .pkgUpgrade: "shippingbox"
        case .container, .composePull, .composeRestart: "cube"
        case .profileCheck: "shield.lefthalf.filled"
        case .configRollback: "clock.arrow.circlepath"
        default: "play"
        }
    }
}

/// ⌘K palette: jump to screens, servers, groups, tags and Settings
/// sections; run operations (opening the bulk run sheet), lock, pause AI.
struct CommandPalette: View {
    @Environment(CoreBridge.self) private var core
    @Environment(AppLock.self) private var lock
    @Environment(AIModel.self) private var ai
    @Binding var isPresented: Bool
    @Binding var selection: NavItem?
    /// Opens the bulk run sheet on `targets` with `draft` filled in.
    var runBulk: ([String], OpDraft) -> Void
    @State private var query = ""
    @State private var highlighted = 0
    @State private var snippets: [SnippetRow] = []
    @State private var runbooks: [RunbookRow] = []
    @FocusState private var focused: Bool

    /// Servers a run action applies to: the open server, else every
    /// connected one.
    private var runTargets: (ids: [String], label: String) {
        if case .server(let id)? = selection, let s = core.servers.first(where: { $0.id == id }) {
            return ([id], s.name)
        }
        let ready = core.servers.filter { $0.state == .ready }.map(\.id)
        return (ready, "\(ready.count) connected server\(ready.count == 1 ? "" : "s")")
    }

    private var actions: [PaletteAction] {
        var all: [PaletteAction] = []
        func go(_ id: String, _ title: String, _ symbol: String, _ item: NavItem) {
            all.append(.init(id: "nav.\(id)", title: title, subtitle: "Go to", symbol: symbol) {
                selection = item
            })
        }
        go("fleet", "Fleet", "server.rack", .fleet)
        go("alerts", "Alerts", "bell", .alerts)
        go("timeline", "Timeline", "clock", .timeline)
        go("search", "Fleet search", "magnifyingglass", .search)
        go("vulnerabilities", "Vulnerabilities", "shield.lefthalf.filled", .vulnerabilities)
        go("runbooks", "Snippets and runbooks", "list.bullet", .runbooks)
        go("provision", "Provision a server", "plus.square", .provision)
        go("settings", "Settings", "slider.horizontal.3", .settings)
        for s in SettingsSection.allCases {
            all.append(.init(id: "settings.\(s.rawValue)", title: "Settings: \(s.title)",
                             subtitle: "Go to", symbol: "slider.horizontal.3") {
                UserDefaults.standard.set(s.rawValue, forKey: SettingsSection.storageKey)
                selection = .settings
            })
        }
        all.append(.init(id: "lock", title: lock.isLocked ? "Unlock Fleet" : "Lock Fleet",
                         subtitle: "App", symbol: lock.isLocked ? "lock.open" : "lock") {
            if lock.isLocked { Task { await lock.unlock() } } else { lock.lock() }
        })
        all.append(.init(id: "ai.pause", title: ai.paused ? "Resume AI agents" : "Pause AI agents",
                         subtitle: "App", symbol: ai.paused ? "play" : "pause") {
            ai.setPaused(!ai.paused)
        })
        if !lock.isLocked {
            let t = runTargets
            for kind in OpDraft.Kind.allCases {
                all.append(.init(id: "run.\(kind.rawValue)", title: kind.paletteTitle,
                                 subtitle: t.ids.isEmpty ? "Run · choose servers" : "Run on \(t.label)",
                                 symbol: kind.paletteSymbol) {
                    var d = OpDraft()
                    d.kind = kind
                    runBulk(t.ids, d)
                })
            }
        }
        for s in snippets {
            all.append(.init(id: "snippet.\(s.id)", title: s.name, subtitle: "Snippet",
                             symbol: "text.alignleft") { selection = .runbooks })
        }
        for r in runbooks {
            all.append(.init(id: "runbook.\(r.id)", title: r.name, subtitle: "Runbook",
                             symbol: "list.bullet.rectangle") { selection = .runbooks })
        }
        for g in core.groups {
            all.append(.init(id: "group.\(g.id)", title: g.name, subtitle: "Group",
                             symbol: "square.stack.3d.up") { selection = .group(g.id) })
        }
        for t in Set(core.servers.flatMap(\.tags)).sorted() {
            all.append(.init(id: "tag.\(t)", title: t, subtitle: "Tag", symbol: "tag") {
                selection = .tag(t)
            })
        }
        for s in core.servers {
            all.append(.init(id: "srv.\(s.id)", title: s.name, subtitle: s.host,
                             symbol: "server.rack") { selection = .server(s.id) })
        }
        let words = query.lowercased().split(whereSeparator: \.isWhitespace)
        guard !words.isEmpty else { return all }
        return all.filter { a in
            let hay = (a.title + " " + a.subtitle).lowercased()
            return words.allSatisfy { hay.contains($0) }
        }
    }

    var body: some View {
        let list = actions
        VStack(spacing: 0) {
            HStack(spacing: 8) {
                Image(systemName: "magnifyingglass").foregroundStyle(Color.textMuted)
                TextField("Search or run…", text: $query)
                    .textFieldStyle(.plain)
                    .font(.system(size: 15))
                    .focused($focused)
                    .accessibilityIdentifier("palette.query")
                    .onSubmit { run(list) }
            }
            .padding(14)
            Divider().overlay(Color.divider)
            ScrollViewReader { proxy in
                ScrollView {
                    LazyVStack(spacing: 2) {
                        ForEach(Array(list.enumerated()), id: \.element.id) { i, a in
                            HStack(spacing: 10) {
                                Image(systemName: a.symbol).frame(width: 18)
                                Text(a.title).foregroundStyle(Color.text)
                                Spacer()
                                Text(a.subtitle).font(.secondary).foregroundStyle(Color.textMuted)
                            }
                            .font(.base)
                            .padding(.horizontal, 12)
                            .frame(height: 34)
                            .background(i == highlighted ? Color.selected : .clear,
                                        in: RoundedRectangle(cornerRadius: 8))
                            .contentShape(Rectangle())
                            .accessibilityElement(children: .combine)
                            .accessibilityAddTraits(.isButton)
                            .accessibilityIdentifier("palette.item.\(a.id)")
                            .onTapGesture { highlighted = i; run(list) }
                            .id(a.id)
                        }
                        if list.isEmpty {
                            Text("Nothing matches “\(query)”")
                                .foregroundStyle(Color.textMuted)
                                .frame(maxWidth: .infinity, minHeight: 60)
                                .accessibilityIdentifier("palette.empty")
                        }
                    }
                    .padding(6)
                }
                .frame(maxHeight: 360)
                .onChange(of: highlighted) {
                    if list.indices.contains(highlighted) {
                        proxy.scrollTo(list[highlighted].id)
                    }
                }
            }
        }
        .frame(width: 560)
        .background(Color.card, in: RoundedRectangle(cornerRadius: 12))
        .overlay(RoundedRectangle(cornerRadius: 12).stroke(Color.border))
        .shadow(radius: 30)
        .onAppear {
            focused = true
            snippets = (try? core.api?.listSnippets()) ?? []
            runbooks = (try? core.api?.listRunbooks()) ?? []
        }
        .onChange(of: query) { highlighted = 0 }
        .onKeyPress(.downArrow) { highlighted = min(highlighted + 1, max(list.count - 1, 0)); return .handled }
        .onKeyPress(.upArrow) { highlighted = max(highlighted - 1, 0); return .handled }
        .onKeyPress(.escape) { isPresented = false; return .handled }
    }

    private func run(_ list: [PaletteAction]) {
        guard list.indices.contains(highlighted) else { return }
        isPresented = false
        list[highlighted].run()
    }
}
