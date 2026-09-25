import SwiftUI

enum NavItem: Hashable {
    case fleet
    case group(String)
    case server(String)
    case alerts
    case timeline
    case search
    case vulnerabilities
    case runbooks
    case provision
}

struct SidebarView: View {
    @Environment(CoreBridge.self) private var core
    @Environment(AppLock.self) private var lock
    @Binding var selection: NavItem?
    var openPalette: () -> Void

    var body: some View {
        VStack(spacing: 0) {
            Button(action: openPalette) {
                HStack(spacing: 8) {
                    Image(systemName: "magnifyingglass")
                    Text("Search or run…")
                    Spacer()
                    Text("⌘K").font(.caption11).foregroundStyle(Color.textMuted)
                }
                .font(.base)
                .foregroundStyle(Color.textSecondary)
                .padding(.horizontal, 10)
                .frame(height: 30)
                .background(Color.control, in: RoundedRectangle(cornerRadius: 8))
                .overlay(RoundedRectangle(cornerRadius: 8).stroke(Color.borderControl))
            }
            .buttonStyle(.plain)
            .padding(.horizontal, 12)
            .padding(.top, 8)

            List(selection: $selection) {
                Section {
                    Label("Fleet", systemImage: "server.rack").tag(NavItem.fleet)
                    Label {
                        HStack {
                            Text("Alerts")
                            Spacer()
                            if !core.alerts.isEmpty {
                                Text("\(core.alerts.count)")
                                    .font(.caption11)
                                    .foregroundStyle(Tone.critical.text)
                            }
                        }
                    } icon: {
                        Image(systemName: "bell")
                    }
                    .tag(NavItem.alerts)
                    Label("Timeline", systemImage: "clock").tag(NavItem.timeline)
                    Label("Search", systemImage: "magnifyingglass").tag(NavItem.search)
                    Label("Vulnerabilities", systemImage: "shield.lefthalf.filled")
                        .tag(NavItem.vulnerabilities)
                    Label("Runbooks", systemImage: "list.bullet").tag(NavItem.runbooks)
                    Label("Provision", systemImage: "plus.square").tag(NavItem.provision)
                }
                Section("Groups") {
                    ForEach(core.groups, id: \.id) { g in
                        HStack {
                            Text(g.name)
                            Spacer()
                            Text("\(core.servers.filter { $0.groupId == g.id }.count)")
                                .font(.caption11).foregroundStyle(Color.textMuted)
                        }
                        .tag(NavItem.group(g.id))
                    }
                }
                Section("Servers") {
                    ForEach(core.servers, id: \.id) { s in
                        HStack(spacing: 8) {
                            Circle().fill(s.state.tone.dot).frame(width: 6, height: 6)
                            Text(s.name).lineLimit(1)
                        }
                        .accessibilityLabel("\(s.name), \(s.state.label)")
                        .tag(NavItem.server(s.id))
                    }
                }
            }
            .listStyle(.sidebar)
            .scrollContentBackground(.hidden)

            Divider().overlay(Color.divider)
            LockFooter()
                .padding(12)
        }
        .background(Color.sidebar)
    }
}

/// "MacBook Pro · Unlocked · locks in 14 min" plus lock/unlock.
private struct LockFooter: View {
    @Environment(AppLock.self) private var lock
    private static let macName = Host.current().localizedName ?? "This Mac"

    var body: some View {
        TimelineView(.periodic(from: .now, by: 30)) { _ in
            HStack(spacing: 10) {
                Image(systemName: lock.isLocked ? "lock.fill" : "lock.open")
                    .foregroundStyle(lock.isLocked ? Tone.warn.text : Color.textSecondary)
                VStack(alignment: .leading, spacing: 2) {
                    Text(Self.macName)
                        .font(.secondary).foregroundStyle(Color.text).lineLimit(1)
                    Text(subtitle).font(.caption11).foregroundStyle(Color.textMuted)
                }
                Spacer()
                Button(lock.isLocked ? "Unlock" : "Lock") {
                    if lock.isLocked {
                        Task { await lock.unlock() }
                    } else {
                        lock.lock()
                    }
                }
                .controlSize(.small)
            }
        }
    }

    private var subtitle: String {
        if lock.isLocked { return "Locked · monitor only" }
        let mins = Int(lock.remaining.components.seconds / 60)
        return "Unlocked · locks in \(mins) min"
    }
}
