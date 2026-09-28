import SwiftUI

/// Bulk run requested from outside a bulk screen (the palette).
private struct BulkRequest: Identifiable {
    let id = UUID()
    let targets: [String]
    let draft: OpDraft
}

extension Notification.Name {
    /// ⌘,: show the Settings screen.
    static let openSettings = Notification.Name("dev.fleet.openSettings")
}

struct ContentView: View {
    @Environment(CoreBridge.self) private var core
    @Environment(AIModel.self) private var ai
    @Environment(AppLock.self) private var lock
    @Binding var paletteShown: Bool
    @State private var selection: NavItem? = .fleet
    @State private var acks = AlertAcks()
    @State private var bulk: BulkRequest?
    /// Redraws the tree when the accent changes (colors read a static).
    @AppStorage(Appearance.accentKey) private var accent = Int(Appearance.defaultAccent)

    var body: some View {
        @Bindable var core = core
        Group {
            if core.status == .notEnrolled {
                OnboardingView()
                    .frame(minWidth: 900, minHeight: 640)
            } else {
                main
            }
        }
        .environment(acks)
        .environment(\.fleetLocked, lock.isLocked)
        .tint(Color.accent)
        .id(accent)
        .alert("Security problem", isPresented: Binding(
            get: { core.securityAlert != nil && !core.securityAlertSeen },
            set: { if !$0 { core.securityAlertSeen = true } }
        )) {
            Button("OK", role: .cancel) {}
                .accessibilityIdentifier("security.alertOK")
        } message: {
            Text(core.securityAlert ?? "")
        }
        // AI pairing / approval prompts; answered only by their buttons.
        .sheet(item: Binding(get: { ai.current }, set: { _ in })) { prompt in
            AIPromptSheet(prompt: prompt)
                .interactiveDismissDisabled()
        }
        .sheet(item: $bulk) { req in
            BulkRunSheet(targets: req.targets, draft: req.draft)
        }
    }

    private var main: some View {
        NavigationSplitView {
            SidebarView(selection: $selection) { paletteShown = true }
                .navigationSplitViewColumnWidth(Layout.sidebarWidth)
        } detail: {
            VStack(spacing: 0) {
                if lock.isLocked { LockedBanner() }
                detail
            }
        }
        .overlay(alignment: .top) {
            if paletteShown {
                ZStack(alignment: .top) {
                    Color.black.opacity(0.35)
                        .ignoresSafeArea()
                        .onTapGesture { paletteShown = false }
                    CommandPalette(isPresented: $paletteShown, selection: $selection) { targets, draft in
                        bulk = BulkRequest(targets: targets, draft: draft)
                    }
                    .padding(.top, 80)
                }
            }
        }
        .frame(minWidth: 1100, minHeight: 700)
        .background(Color.window)
        .onReceive(NotificationCenter.default.publisher(for: .fleetSearch)) { _ in
            selection = .search
        }
        .onReceive(NotificationCenter.default.publisher(for: .openSettings)) { _ in
            selection = .settings
        }
    }

    @ViewBuilder private var detail: some View {
        switch selection {
        case .fleet, .none:
            FleetTableView(groupId: nil, selection: $selection)
        case .group(let id):
            FleetTableView(groupId: id, selection: $selection).id(id)
        case .server(let id):
            ServerDetailView(serverId: id)
        case .tag(let t):
            TagView(tag: t, selection: $selection).id(t)
        case .alerts:
            AlertsView(selection: $selection)
        case .timeline:
            FleetTimelineView(selection: $selection)
        case .search:
            VStack(spacing: 0) {
                ScreenHeader("Search")
                FleetSearchView(selection: $selection)
            }
        case .vulnerabilities:
            FleetVulnerabilitiesView(selection: $selection)
        case .runbooks:
            RunbooksView()
                .disabled(lock.isLocked)
        case .provision:
            ProvisionView(selection: $selection)
                .disabled(lock.isLocked)
        case .settings:
            SettingsView(selection: $selection)
        }
    }
}

/// Shown on every screen while only the monitor key is usable.
private struct LockedBanner: View {
    @Environment(AppLock.self) private var lock

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: "lock.fill")
            Text("Locked: telemetry and events only. Changes need Touch ID.")
                .font(.secondary)
            Spacer()
            Button("Unlock") { Task { await lock.unlock() } }
                .buttonStyle(.fleetPrimary)
                .accessibilityIdentifier("locked.unlock")
        }
        .foregroundStyle(Tone.warn.text)
        .padding(.horizontal, 24)
        .frame(height: 44)
        .background(Tone.warn.bg)
        .overlay(alignment: .bottom) { Rectangle().fill(Color.border).frame(height: 1) }
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier("locked.banner")
    }
}
