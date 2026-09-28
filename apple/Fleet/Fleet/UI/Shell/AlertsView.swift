import SwiftUI

/// Alerts the operator acknowledged. Acknowledging only hides an alert
/// from the sidebar count and the default list on this Mac; the agent
/// keeps firing until the condition clears (then the entry is dropped).
@MainActor @Observable
final class AlertAcks {
    private static let key = "alerts.acked"
    private(set) var acked: Set<String>

    init() {
        acked = Set(UserDefaults.standard.stringArray(forKey: Self.key) ?? [])
    }

    func isAcked(_ key: String) -> Bool { acked.contains(key) }

    func set(_ key: String, acked value: Bool) {
        if value { acked.insert(key) } else { acked.remove(key) }
        save()
    }

    /// Forgets acknowledgements of alerts that are no longer open.
    func prune(open: Set<String>) {
        let next = acked.intersection(open)
        if next != acked {
            acked = next
            save()
        }
    }

    private func save() {
        UserDefaults.standard.set(Array(acked).sorted(), forKey: Self.key)
    }
}

extension CoreBridge {
    /// The key `alerts` uses for one open alert.
    static func alertKey(_ e: AgentEventRow) -> String {
        "\(e.serverId)|\(e.alert?.ruleId ?? e.name)|\(e.alert?.subject ?? "")"
    }

    /// Open alerts not acknowledged on this Mac.
    func unackedAlertCount(_ acks: AlertAcks) -> Int {
        alerts.keys.filter { !acks.isAcked($0) }.count
    }
}

/// Alerts inbox: open alerts from agent events (app-only, design §2.2).
struct AlertsView: View {
    @Environment(CoreBridge.self) private var core
    @Environment(AlertAcks.self) private var acks
    @Binding var selection: NavItem?
    @State private var showAcked = false
    /// Each alerting server's rules, to word alerts in plain language.
    @State private var rules: [String: [String: AlertRuleRow]] = [:]

    var body: some View {
        let all = core.alerts.sorted { $0.value.seq > $1.value.seq }
        let shown = all.filter { showAcked || !acks.isAcked($0.key) }
        VStack(spacing: 0) {
            ScreenHeader("Alerts", subtitle: subtitle(open: all.count, acked: all.count - all.filter { !acks.isAcked($0.key) }.count)) {
                if all.contains(where: { acks.isAcked($0.key) }) {
                    Toggle("Show acknowledged", isOn: $showAcked)
                        .toggleStyle(.checkbox)
                        .font(.secondary)
                        .accessibilityIdentifier("alerts.showAcked")
                }
            }
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    if !core.fleetAlerts.isEmpty {
                        Form { FleetAlertsSection() }
                            .formStyle(.grouped)
                            .scrollContentBackground(.hidden)
                            .frame(maxHeight: 320)
                    }
                    if shown.isEmpty {
                        ContentUnavailableView(
                            all.isEmpty ? "No open alerts" : "Nothing new",
                            systemImage: "checkmark.seal",
                            description: all.isEmpty ? nil : Text("Every open alert is acknowledged."))
                            .frame(maxWidth: .infinity, minHeight: 240)
                            .accessibilityIdentifier("alerts.empty")
                    } else {
                        VStack(spacing: 0) {
                            ForEach(Array(shown.enumerated()), id: \.element.key) { i, item in
                                if i > 0 { Divider().overlay(Color.divider) }
                                row(item.key, item.value)
                            }
                        }
                        .background(Color.card, in: RoundedRectangle(cornerRadius: 12))
                        .overlay(RoundedRectangle(cornerRadius: 12).stroke(Color.border))
                        .accessibilityIdentifier("alerts.list")
                    }
                }
                .padding(24)
            }
        }
        .background(Color.window)
        .navigationTitle("Alerts")
        .task(id: core.alerts.keys.sorted()) {
            acks.prune(open: Set(core.alerts.keys))
            await loadRules()
        }
    }

    private func subtitle(open: Int, acked: Int) -> String {
        acked > 0 ? "\(open) open · \(acked) acknowledged" : "\(open) open"
    }

    private func row(_ key: String, _ e: AgentEventRow) -> some View {
        let sev = e.alert?.severity
        let isAcked = acks.isAcked(key)
        return HStack(spacing: 12) {
            StatusPill(label: label(sev), tone: tone(sev))
            VStack(alignment: .leading, spacing: 2) {
                Text(title(e)).foregroundStyle(isAcked ? Color.textMuted : Color.text)
                    .accessibilityIdentifier("alerts.rule")
                Text("\(serverName(e.serverId))\(subject(e))")
                    .font(.secondary).foregroundStyle(Color.textMuted)
            }
            Spacer()
            Button("Open server") { selection = .server(e.serverId) }
                .controlSize(.small)
                .accessibilityIdentifier("alerts.openServer")
            Button(isAcked ? "Unacknowledge" : "Acknowledge") { acks.set(key, acked: !isAcked) }
                .controlSize(.small)
                .accessibilityIdentifier("alerts.ack")
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 12)
        .accessibilityElement(children: .contain)
    }

    private func subject(_ e: AgentEventRow) -> String {
        let s = e.alert?.subject ?? ""
        return s.isEmpty ? "" : " · \(s)"
    }

    private func title(_ e: AgentEventRow) -> String {
        guard let a = e.alert else { return e.name }
        if let rule = rules[e.serverId]?[a.ruleId] { return rule.humanTitle }
        return AlertRuleRow.humanize(a.ruleId)
    }

    private func loadRules() async {
        guard let api = core.api else { return }
        let ids = Set(core.alerts.values.map(\.serverId)).filter { rules[$0] == nil }
        for id in ids {
            if let set = try? await api.alertRulesGet(serverId: id) {
                rules[id] = Dictionary(set.rules.map { ($0.id, $0) }, uniquingKeysWith: { a, _ in a })
            }
        }
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
