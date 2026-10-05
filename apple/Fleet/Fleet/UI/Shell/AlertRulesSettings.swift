import SwiftUI

/// How a rule's integer threshold reads to a person.
enum ThresholdUnit {
    /// Permille in the wire type, shown as percent.
    case percent
    /// Load average per core times 100, shown as a decimal.
    case load
    case days
    case count
    /// The kind takes no threshold.
    case none

    var suffix: String {
        switch self {
        case .percent: "%"
        case .load: "per core"
        case .days: "days"
        case .count: ""
        case .none: ""
        }
    }
}

extension AlertKindRow: CaseIterable, Identifiable {
    public static var allCases: [AlertKindRow] {
        [.diskUsage, .inodeUsage, .memoryUsage, .swapUsage, .cpuUsage, .cpuSteal, .load,
         .serviceDown, .containerDown, .healthCheckFailed, .bruteForce, .certExpiry,
         .securityUpdates, .rebootRequired, .newListeningPort, .userChange,
         .authorizedKeysChange, .loginNewSource, .integrityViolation]
    }

    public var id: String { slug }

    var label: String {
        switch self {
        case .diskUsage: "Disk usage"
        case .inodeUsage: "Inode usage"
        case .memoryUsage: "Memory usage"
        case .swapUsage: "Swap usage"
        case .cpuUsage: "CPU usage"
        case .cpuSteal: "CPU steal"
        case .load: "Load average"
        case .serviceDown: "Service down"
        case .bruteForce: "Failed SSH logins"
        case .certExpiry: "Certificate expiry"
        case .newListeningPort: "New listening port"
        case .userChange: "User or group change"
        case .authorizedKeysChange: "authorized_keys change"
        case .loginNewSource: "Login from a new source"
        case .integrityViolation: "Integrity violation"
        case .containerDown: "Container down"
        case .healthCheckFailed: "Health check failing"
        case .securityUpdates: "Pending security updates"
        case .rebootRequired: "Reboot required"
        }
    }

    var slug: String {
        switch self {
        case .diskUsage: "disk"
        case .inodeUsage: "inodes"
        case .memoryUsage: "memory"
        case .swapUsage: "swap"
        case .cpuUsage: "cpu"
        case .cpuSteal: "cpu-steal"
        case .load: "load"
        case .serviceDown: "service"
        case .bruteForce: "ssh-failures"
        case .certExpiry: "cert-expiry"
        case .newListeningPort: "new-port"
        case .userChange: "user-change"
        case .authorizedKeysChange: "authorized-keys"
        case .loginNewSource: "new-login-source"
        case .integrityViolation: "integrity"
        case .containerDown: "container"
        case .healthCheckFailed: "health-check"
        case .securityUpdates: "security-updates"
        case .rebootRequired: "reboot-required"
        }
    }

    var unit: ThresholdUnit {
        switch self {
        case .diskUsage, .inodeUsage, .memoryUsage, .swapUsage, .cpuUsage, .cpuSteal: .percent
        case .load: .load
        case .certExpiry: .days
        case .bruteForce, .securityUpdates: .count
        default: .none
        }
    }

    /// Label of the kind's parameter; `nil` when it takes none.
    var paramLabel: String? {
        switch self {
        case .diskUsage, .inodeUsage: "Mount (empty: every filesystem)"
        case .serviceDown: "Unit, e.g. nginx.service"
        case .containerDown: "Container name"
        case .healthCheckFailed: "Check id"
        default: nil
        }
    }

    var paramRequired: Bool {
        switch self {
        case .serviceDown, .containerDown, .healthCheckFailed: true
        default: false
        }
    }

    var defaultThreshold: UInt32 {
        switch self {
        case .diskUsage, .memoryUsage, .cpuUsage: 900
        case .inodeUsage: 900
        case .swapUsage: 500
        case .cpuSteal: 100
        case .load: 200
        case .certExpiry: 14
        case .bruteForce: 30
        case .securityUpdates: 1
        default: 0
        }
    }

    var defaultForSeconds: UInt32 {
        switch self {
        case .diskUsage, .inodeUsage, .memoryUsage, .swapUsage, .cpuUsage, .cpuSteal, .load: 300
        case .bruteForce: 300
        case .healthCheckFailed: 60
        default: 0
        }
    }
}

extension AlertRuleRow {
    /// Plain-language name of what the rule watches.
    var humanTitle: String {
        let p = param.trimmingCharacters(in: .whitespaces)
        switch kind {
        case .diskUsage, .inodeUsage:
            let base = kind == .diskUsage ? "Disk usage" : "Inode usage"
            return "\(base)\(p.isEmpty ? "" : " on \(p)") above \(Self.number(Double(threshold) / 10))%"
        case .memoryUsage, .swapUsage, .cpuUsage, .cpuSteal:
            return "\(kind.label) above \(Self.number(Double(threshold) / 10))%"
        case .load:
            return "Load above \(Self.number(Double(threshold) / 100)) per core"
        case .serviceDown: return "\(p) is down"
        case .containerDown: return "Container \(p) is down"
        case .healthCheckFailed: return "Health check \(p) is failing"
        case .bruteForce: return "\(threshold) or more failed SSH logins"
        case .certExpiry: return "Certificate expires within \(threshold) days"
        case .securityUpdates: return "\(threshold) or more security updates pending"
        default: return kind.label
        }
    }

    /// A rule id as words, for alerts whose rule can't be read.
    static func humanize(_ id: String) -> String {
        let words = id.replacingOccurrences(of: "[-_.]+", with: " ", options: .regularExpression)
            .trimmingCharacters(in: .whitespaces)
        return words.isEmpty ? id : words.prefix(1).uppercased() + words.dropFirst()
    }

    private static func number(_ v: Double) -> String {
        v == v.rounded() ? String(Int(v)) : String(format: "%.1f", v)
    }

    /// A new rule of `kind` with a free id among `taken`.
    static func make(_ kind: AlertKindRow, taken: Set<String>) -> AlertRuleRow {
        var id = kind.slug
        var n = 2
        while taken.contains(id) {
            id = "\(kind.slug)-\(n)"
            n += 1
        }
        let sev: AlertSeverity = switch kind {
        case .integrityViolation, .authorizedKeysChange, .serviceDown: .critical
        case .newListeningPort, .userChange, .loginNewSource, .rebootRequired: .info
        default: .warning
        }
        return AlertRuleRow(id: id, kind: kind, param: "", threshold: kind.defaultThreshold,
                            forS: kind.defaultForSeconds, severity: sev, enabled: true)
    }
}

/// Settings → Alert rules (design §4.5): each server's rules, edited here
/// and pushed as one Elevated command (Touch ID).
struct AlertRulesSettings: View {
    @Environment(CoreBridge.self) private var core
    @Environment(\.fleetLocked) private var locked
    @State private var serverId: String?
    @State private var loaded: AlertRuleSetRow?
    @State private var rules: [AlertRuleRow] = []
    @State private var busy = false
    @State private var error: String?
    @State private var saved = false

    private var dirty: Bool { loaded.map { $0.rules != rules } ?? false }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack(spacing: 12) {
                Picker("Server", selection: $serverId) {
                    Text("Choose a server").tag(String?.none)
                    ForEach(core.servers.filter { $0.agentPinned }, id: \.id) { s in
                        Text(s.name).tag(String?.some(s.id))
                    }
                }
                .frame(maxWidth: 320, alignment: .leading)
                .accessibilityIdentifier("alertRules.server")
                Spacer()
                Menu {
                    ForEach(AlertKindRow.allCases) { k in
                        Button(k.label) { rules.append(.make(k, taken: Set(rules.map(\.id)))) }
                    }
                } label: {
                    Label("Add rule", systemImage: "plus")
                }
                .menuStyle(.button)
                .fixedSize()
                .disabled(loaded == nil || busy)
                .accessibilityIdentifier("alertRules.add")
                Button("Save with Touch ID") { save() }
                    .buttonStyle(.fleetPrimary)
                    .disabled(!dirty || busy || locked)
                    .accessibilityIdentifier("alertRules.save")
            }
            if let error {
                Text(error).foregroundStyle(Tone.critical.text)
                    .accessibilityIdentifier("alertRules.error")
            }
            if saved && !dirty {
                Text("Saved. The agent evaluates the new rules now.")
                    .font(.secondary).foregroundStyle(Tone.ok.text)
                    .accessibilityIdentifier("alertRules.saved")
            }
            if serverId == nil {
                empty("Rules are evaluated on each agent, so they are set per server.")
            } else if loaded == nil {
                if busy { ProgressView().controlSize(.small) } else { empty("Couldn't load the rules.") }
            } else if rules.isEmpty {
                empty("No rules on this server. Add one to be alerted.")
            } else {
                VStack(spacing: 10) {
                    ForEach($rules, id: \.id) { $r in
                        RuleCard(rule: $r) { rules.removeAll { $0.id == r.id } }
                    }
                }
            }
            Text("Alerts stay in this app. Saving needs the root key: one Touch ID for the whole rule set.")
                .font(.caption11).foregroundStyle(Color.textMuted)
        }
        .task(id: serverId) { await load() }
    }

    private func empty(_ text: String) -> some View {
        Text(text).foregroundStyle(Color.textMuted)
            .frame(maxWidth: .infinity, minHeight: 120)
            .background(Color.card, in: RoundedRectangle(cornerRadius: 12))
            .overlay(RoundedRectangle(cornerRadius: 12).stroke(Color.border))
    }

    private func load() async {
        loaded = nil
        rules = []
        error = nil
        saved = false
        guard let serverId, let api = core.api else { return }
        busy = true
        defer { busy = false }
        do {
            let set = try await api.alertRulesGet(serverId: serverId)
            loaded = set
            rules = set.rules
        } catch {
            self.error = error.fleetMessage
        }
    }

    private func save() {
        guard let serverId, let api = core.api, let base = loaded else { return }
        busy = true
        error = nil
        Task {
            defer { busy = false }
            do {
                try await api.alertRulesSet(serverId: serverId, rules: rules, expectedVersion: base.version)
                loaded = try await api.alertRulesGet(serverId: serverId)
                rules = loaded?.rules ?? rules
                saved = true
            } catch SignerError.Cancelled {
                error = nil
            } catch {
                self.error = error.fleetMessage
            }
        }
    }
}

private struct RuleCard: View {
    @Binding var rule: AlertRuleRow
    let remove: () -> Void

    var body: some View {
        HStack(alignment: .top, spacing: 14) {
            Toggle("", isOn: $rule.enabled)
                .labelsHidden()
                .toggleStyle(.switch)
                .controlSize(.small)
                .accessibilityIdentifier("alertRules.enabled.\(rule.id)")
            VStack(alignment: .leading, spacing: 8) {
                HStack {
                    Text(rule.kind.label).font(.base.weight(.medium)).foregroundStyle(Color.text)
                    Text(rule.id).font(.mono(11)).foregroundStyle(Color.textMuted)
                }
                Text(rule.humanTitle).font(.secondary).foregroundStyle(Color.textSecondary)
                HStack(spacing: 12) {
                    if let label = rule.kind.paramLabel {
                        TextField(label, text: $rule.param)
                            .textFieldStyle(.roundedBorder)
                            .frame(maxWidth: 240)
                            .accessibilityIdentifier("alertRules.param.\(rule.id)")
                    }
                    if rule.kind.unit != .none {
                        thresholdField
                    }
                    if rule.kind.defaultForSeconds > 0 || rule.forS > 0 {
                        HStack(spacing: 4) {
                            Text("for").font(.secondary).foregroundStyle(Color.textMuted)
                            TextField("", value: minutes, format: .number)
                                .textFieldStyle(.roundedBorder).frame(width: 56)
                                .accessibilityIdentifier("alertRules.for.\(rule.id)")
                            Text("min").font(.secondary).foregroundStyle(Color.textMuted)
                        }
                    }
                    Picker("", selection: $rule.severity) {
                        Text("Info").tag(AlertSeverity.info)
                        Text("Warning").tag(AlertSeverity.warning)
                        Text("Critical").tag(AlertSeverity.critical)
                    }
                    .labelsHidden()
                    .frame(width: 100)
                    .accessibilityIdentifier("alertRules.severity.\(rule.id)")
                }
            }
            Spacer()
            Button(role: .destructive, action: remove) { Image(systemName: "trash") }
                .buttonStyle(.borderless)
                .help("Remove rule")
                .accessibilityLabel("Remove rule \(rule.id)")
                .accessibilityIdentifier("alertRules.remove.\(rule.id)")
        }
        .padding(14)
        .background(Color.card, in: RoundedRectangle(cornerRadius: 12))
        .overlay(RoundedRectangle(cornerRadius: 12).stroke(Color.border))
        .opacity(rule.enabled ? 1 : 0.6)
    }

    private var thresholdField: some View {
        HStack(spacing: 4) {
            Text(rule.kind.unit == .days ? "within" : "at or above")
                .font(.secondary).foregroundStyle(Color.textMuted)
            TextField("", value: threshold, format: .number)
                .textFieldStyle(.roundedBorder).frame(width: 64)
                .accessibilityIdentifier("alertRules.threshold.\(rule.id)")
            Text(rule.kind.unit.suffix).font(.secondary).foregroundStyle(Color.textMuted)
        }
    }

    /// Threshold in the unit people read.
    private var threshold: Binding<Double> {
        let div: Double = switch rule.kind.unit {
        case .percent: 10
        case .load: 100
        default: 1
        }
        return Binding(
            get: { Double(rule.threshold) / div },
            set: { rule.threshold = UInt32(max(0, min(($0 * div).rounded(), 4_000_000_000))) })
    }

    private var minutes: Binding<Int> {
        Binding(get: { Int(rule.forS / 60) },
                set: { rule.forS = UInt32(max(0, min($0, 1440)) * 60) })
    }
}
