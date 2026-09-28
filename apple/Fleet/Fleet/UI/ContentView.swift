import SwiftUI

struct ContentView: View {
    @Environment(CoreBridge.self) private var core
    @Environment(AIModel.self) private var ai
    @Binding var paletteShown: Bool
    @State private var selection: NavItem? = .fleet

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
    }

    private var main: some View {
        NavigationSplitView {
            SidebarView(selection: $selection) { paletteShown = true }
                .navigationSplitViewColumnWidth(240)
        } detail: {
            detail
        }
        .overlay(alignment: .top) {
            if paletteShown {
                ZStack(alignment: .top) {
                    Color.black.opacity(0.35)
                        .ignoresSafeArea()
                        .onTapGesture { paletteShown = false }
                    CommandPalette(isPresented: $paletteShown, selection: $selection)
                        .padding(.top, 80)
                }
            }
        }
        .frame(minWidth: 1100, minHeight: 700)
        .background(Color.window)
        .onReceive(NotificationCenter.default.publisher(for: .fleetSearch)) { _ in
            selection = .search
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
        case .alerts:
            AlertsView()
        case .timeline:
            FleetTimelineView(selection: $selection)
        case .search:
            FleetSearchView(selection: $selection)
        case .vulnerabilities:
            FleetVulnerabilitiesView(selection: $selection)
        case .runbooks:
            RunbooksView()
        case .provision:
            ProvisionView(selection: $selection)
        }
    }
}

/// Alerts inbox: open alerts from agent events (app-only, design §2.2).
struct AlertsView: View {
    @Environment(CoreBridge.self) private var core

    var body: some View {
        let alerts = core.alerts.values.sorted { $0.seq > $1.seq }
        VStack(spacing: 0) {
            // Roster, recovery and sync alerts (design §5.10) first.
            if !core.fleetAlerts.isEmpty {
                Form { FleetAlertsSection() }
                    .formStyle(.grouped)
                    .scrollContentBackground(.hidden)
                    .frame(maxHeight: 320)
            }
            if alerts.isEmpty {
                ContentUnavailableView("No open alerts", systemImage: "checkmark.seal")
                    .accessibilityIdentifier("alerts.empty")
            } else {
                List(alerts, id: \.self) { e in
                    HStack(spacing: 12) {
                        let tone = tone(e.alert?.severity)
                        StatusPill(label: label(e.alert?.severity), tone: tone)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(e.alert?.ruleId ?? e.name).foregroundStyle(Color.text)
                                .accessibilityIdentifier("alerts.rule")
                            Text("\(serverName(e.serverId)) · \(e.alert?.subject ?? "")")
                                .font(.secondary).foregroundStyle(Color.textMuted)
                        }
                    }
                }
                .scrollContentBackground(.hidden)
                .accessibilityIdentifier("alerts.list")
            }
        }
        .background(Color.window)
        .navigationTitle("Alerts")
    }

    private func serverName(_ id: String) -> String {
        core.servers.first { $0.id == id }?.name ?? id
    }

    private func tone(_ s: AlertSeverity?) -> Tone {
        switch s {
        case .critical: .critical
        case .warning: .warn
        case .info, .none: .info
        }
    }

    private func label(_ s: AlertSeverity?) -> String {
        switch s {
        case .critical: "Critical"
        case .warning: "Warning"
        case .info, .none: "Info"
        }
    }
}
