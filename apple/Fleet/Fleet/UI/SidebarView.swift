import SwiftUI

enum NavItem: Hashable {
    case fleet
    case group(String)
    case server(String)
    case tag(String)
    case alerts
    case timeline
    case search
    case vulnerabilities
    case runbooks
    case provision
    case settings
}

/// Sidebar of Main.dc.html: search button, navigation, groups, tags, then
/// Settings and the lock / AI card pinned to the bottom.
struct SidebarView: View {
    @Environment(CoreBridge.self) private var core
    @Environment(AppLock.self) private var lock
    @Environment(AlertAcks.self) private var acks
    @Binding var selection: NavItem?
    var openPalette: () -> Void
    @State private var groupSheet: GroupSheetRequest?
    @State private var deleting: GroupRow?

    var body: some View {
        VStack(spacing: 0) {
            Button(action: openPalette) {
                HStack(spacing: 8) {
                    Image(systemName: "magnifyingglass")
                    Text("Search or run…")
                    Spacer()
                    Text("⌘K").font(.mono(11)).foregroundStyle(Color.textMuted)
                }
                .font(.base)
                .foregroundStyle(Color.textSecondary)
                .padding(.horizontal, 10)
                .frame(height: 34)
                .background(Color.control, in: RoundedRectangle(cornerRadius: 8))
                .overlay(RoundedRectangle(cornerRadius: 8).stroke(Color.borderControl))
            }
            .buttonStyle(.plain)
            .accessibilityIdentifier("sidebar.palette")
            .padding(.horizontal, 12)
            .focusEffectDisabled()
            .padding(.top, 8)
            .padding(.bottom, 20)

            ScrollView {
                VStack(alignment: .leading, spacing: 20) {
                    navSection
                    groupsSection
                    serversSection
                    tagsSection
                }
                .padding(.horizontal, 12)
            }
            .scrollIndicators(.never)

            VStack(spacing: 8) {
                row(.settings, id: "settings", title: "Settings", symbol: "slider.horizontal.3")
                FooterCard()
            }
            .padding(12)
        }
        .background(Color.sidebar)
        .sheet(item: $groupSheet) { GroupNameSheet(group: $0.group) }
        .confirmationDialog(
            "Delete group \(deleting?.name ?? "")?", isPresented: Binding(
                get: { deleting != nil }, set: { if !$0 { deleting = nil } }),
            titleVisibility: .visible
        ) {
            Button("Delete group", role: .destructive) {
                if let g = deleting {
                    try? core.removeGroup(g.id)
                    if selection == .group(g.id) { selection = .fleet }
                }
                deleting = nil
            }
            .accessibilityIdentifier("group.confirmDelete")
        } message: {
            Text("Its servers stay in the fleet, ungrouped.")
        }
    }

    // MARK: sections

    private var navSection: some View {
        VStack(spacing: 2) {
            row(.fleet, id: "fleet", title: "Fleet", symbol: "server.rack",
                trailing: AnyView(Text("\(core.servers.count)").font(.secondary).foregroundStyle(Color.textMuted)))
            row(.alerts, id: "alerts", title: "Alerts", symbol: "bell",
                trailing: AnyView(AlertBadge(count: core.unackedAlertCount(acks))))
            row(.timeline, id: "timeline", title: "Timeline", symbol: "clock")
            row(.search, id: "search", title: "Search", symbol: "magnifyingglass")
            row(.vulnerabilities, id: "vulnerabilities", title: "Vulnerabilities",
                symbol: "shield.lefthalf.filled")
            row(.runbooks, id: "runbooks", title: "Runbooks", symbol: "list.bullet")
            row(.provision, id: "provisioning", title: "Provision", symbol: "plus.square")
        }
    }

    private var groupsSection: some View {
        VStack(alignment: .leading, spacing: 2) {
            HStack {
                header("Groups")
                Spacer()
                Button { groupSheet = GroupSheetRequest(group: nil) } label: {
                    Image(systemName: "plus").font(.system(size: 11, weight: .semibold))
                        .frame(width: 22, height: 22).contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .foregroundStyle(Color.textMuted)
                .help("New group")
                .accessibilityLabel("New group")
                .accessibilityIdentifier("sidebar.newGroup")
            }
            ForEach(core.groups, id: \.id) { g in
                let count = core.servers.filter { $0.groupId == g.id }.count
                SidebarRow(selected: selection == .group(g.id), height: 30, action: { selection = .group(g.id) }) {
                    RoundedRectangle(cornerRadius: 2).fill(Color(hex: 0x7b818b)).frame(width: 8, height: 8)
                    Text(g.name).lineLimit(1)
                    Spacer()
                    Text("\(count)").font(.secondary).foregroundStyle(Color.textMuted)
                }
                .accessibilityIdentifier("sidebar.group.\(g.name)")
                .contextMenu {
                    Button("Rename…") { groupSheet = GroupSheetRequest(group: g) }
                    Button("Delete…", role: .destructive) { deleting = g }
                }
            }
        }
    }

    private var serversSection: some View {
        VStack(alignment: .leading, spacing: 2) {
            header("Servers")
            ForEach(core.servers, id: \.id) { s in
                SidebarRow(selected: selection == .server(s.id), height: 30, action: { selection = .server(s.id) }) {
                    Circle().fill(s.state.tone.dot).frame(width: 6, height: 6)
                    Text(s.name).lineLimit(1)
                    Spacer()
                    // Status is never color alone: unhealthy states say so.
                    if s.state != .ready {
                        Text(s.state.label).font(.caption11).foregroundStyle(s.state.tone.text)
                    }
                }
                .accessibilityLabel("\(s.name), \(s.state.label)")
                .accessibilityIdentifier("sidebar.server.\(s.name)")
            }
        }
    }

    private var tagsSection: some View {
        let tags = Array(Set(core.servers.flatMap(\.tags))).sorted()
        return Group {
            if !tags.isEmpty {
                VStack(alignment: .leading, spacing: 8) {
                    header("Tags")
                    FlowLayout(spacing: 6) {
                        ForEach(tags, id: \.self) { t in
                            Button { selection = .tag(t) } label: {
                                Text(t).font(.secondary)
                                    .foregroundStyle(selection == .tag(t) ? Color.text : Color(hex: 0xc3c6cb))
                                    .padding(.horizontal, 8).frame(height: 22)
                                    .background(selection == .tag(t) ? Color.accent.opacity(0.35) : Color.selected,
                                                in: RoundedRectangle(cornerRadius: 6))
                            }
                            .buttonStyle(.plain)
                            .accessibilityIdentifier("sidebar.tag.\(t)")
                        }
                    }
                    .padding(.horizontal, 8)
                }
            }
        }
    }

    private func header(_ title: String) -> some View {
        Text(title).font(Typeface.ui(11, .semibold)).foregroundStyle(Color.textMuted)
            .padding(.horizontal, 10).padding(.bottom, 4)
    }

    private func row(_ item: NavItem, id: String, title: String, symbol: String,
                     trailing: AnyView? = nil) -> some View {
        let on = selection == item
        return SidebarRow(selected: on, height: 32, action: { selection = item }) {
            Image(systemName: symbol).frame(width: 16)
                .foregroundStyle(on ? Color.accentText : Color(hex: 0xd4d6da))
            Text(title).font(.base.weight(.medium))
            Spacer()
            if let trailing { trailing }
        }
        .accessibilityIdentifier("sidebar.\(id)")
    }
}

private struct GroupSheetRequest: Identifiable {
    let id = UUID()
    let group: GroupRow?
}

private struct SidebarRow<Content: View>: View {
    let selected: Bool
    let height: CGFloat
    let action: () -> Void
    @ViewBuilder var content: () -> Content
    @State private var hovering = false

    var body: some View {
        Button(action: action) {
            HStack(spacing: 10) { content() }
                .font(.base)
                .foregroundStyle(selected ? Color.text : Color(hex: 0xd4d6da))
                .padding(.horizontal, 10)
                .frame(maxWidth: .infinity, alignment: .leading)
                .frame(height: height)
                .background(selected ? Color.selected : hovering ? Color.selected.opacity(0.5) : .clear,
                            in: RoundedRectangle(cornerRadius: 7))
                .contentShape(RoundedRectangle(cornerRadius: 7))
        }
        .buttonStyle(.plain)
        .focusEffectDisabled()
        .onHover { hovering = $0 }
        .accessibilityAddTraits(selected ? .isSelected : [])
    }
}

/// Warn pill with the open, unacknowledged alert count.
private struct AlertBadge: View {
    let count: Int

    var body: some View {
        if count > 0 {
            Text("\(count)")
                .font(Typeface.ui(11, .semibold))
                .foregroundStyle(Tone.warn.text)
                .padding(.horizontal, 6)
                .frame(minWidth: 20, minHeight: 18)
                .background(Tone.warn.bg, in: Capsule())
                .accessibilityLabel("\(count) open alerts")
                .accessibilityIdentifier("sidebar.alerts.badge")
        }
    }
}

/// "MacBook Pro · Unlocked · locks in 14 min" with lock/unlock, and the
/// AI agents row with its pause button.
private struct FooterCard: View {
    @Environment(AppLock.self) private var lock
    @Environment(AIModel.self) private var ai
    private static let macName = Host.current().localizedName ?? "This Mac"

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            TimelineView(.periodic(from: .now, by: 30)) { _ in
                VStack(alignment: .leading, spacing: 4) {
                    HStack(spacing: 10) {
                        Image(systemName: lock.isLocked ? "lock.fill" : "lock.open")
                            .foregroundStyle(lock.isLocked ? Tone.warn.text : Color.textSecondary)
                            .frame(width: 16)
                        Text(Self.macName)
                            .font(.base.weight(.medium)).foregroundStyle(Color.text)
                            .lineLimit(1).truncationMode(.middle)
                        Spacer(minLength: 0)
                        Button(lock.isLocked ? "Unlock" : "Lock") {
                            if lock.isLocked {
                                Task { await lock.unlock() }
                            } else {
                                lock.lock()
                            }
                        }
                        .buttonStyle(.fleetSecondary)
                        .controlSize(.small)
                        .accessibilityIdentifier("sidebar.lock")
                    }
                    // Own line: beside the button it wrapped at the 240 px sidebar width.
                    Text(subtitle).font(.caption11).foregroundStyle(Color.textMuted)
                        .lineLimit(1)
                        .padding(.leading, 26)
                        .accessibilityIdentifier("sidebar.lockState")
                }
            }
            HStack(spacing: 10) {
                Image(systemName: "sparkle")
                    .foregroundStyle(ai.paused ? Color.textMuted : Color.accentText)
                Text(ai.paused ? "AI agents paused" : "AI agents active")
                    .font(.secondary).foregroundStyle(Color(hex: 0xd4d6da))
                    .accessibilityIdentifier("sidebar.aiState")
                Spacer()
                Button { ai.setPaused(!ai.paused) } label: {
                    Image(systemName: ai.paused ? "play" : "pause")
                        .frame(width: 28, height: 28)
                        .background(Color.control, in: RoundedRectangle(cornerRadius: 7))
                        .overlay(RoundedRectangle(cornerRadius: 7).stroke(Color.borderControl))
                }
                .buttonStyle(.plain)
                .accessibilityLabel(ai.paused ? "Resume AI agents" : "Pause AI agents")
                .accessibilityIdentifier("sidebar.aiPause")
            }
        }
        .padding(.horizontal, 12).padding(.vertical, 10)
        .background(Color(hex: 0x1d1e22), in: RoundedRectangle(cornerRadius: 10))
        .overlay(RoundedRectangle(cornerRadius: 10).stroke(Color.border))
    }

    private var subtitle: String {
        if lock.isLocked { return "Locked · monitor only" }
        let mins = Int(lock.remaining.components.seconds / 60)
        return "Unlocked · locks in \(mins) min"
    }
}
