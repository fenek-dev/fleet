import SwiftUI

/// One row of the login history table: failures from one source and user
/// are folded into a single "Failed ×N" row.
struct LoginLine: Identifiable, Equatable {
    let id: Int
    let timeMs: UInt64
    let user: String
    let source: String
    /// Enrolled Mac's name, or `Unknown`.
    let who: String
    let method: String
    let result: String
    let ok: Bool

    /// Builds the table from raw records: newest first, failures grouped by
    /// (user, source, method), `banned` marks sources with an active ban.
    static func build(_ logins: [LoginRow], deviceNames: [String: String],
                      bannedSources: Set<String>, limit: Int = 30) -> [LoginLine] {
        struct Key: Hashable { let user: String; let source: String; let method: String }
        var lines: [LoginLine] = []
        var failed: [Key: (count: Int, latest: UInt64)] = [:]
        for l in logins {
            if l.success {
                let who = l.deviceIdHex.flatMap { deviceNames[$0] } ?? "Unknown"
                lines.append(LoginLine(id: 0, timeMs: l.timeMs, user: l.user, source: l.source ?? "local",
                                       who: who, method: methodName(l), result: "Accepted", ok: true))
            } else {
                let k = Key(user: l.user, source: l.source ?? "local", method: methodName(l))
                let cur = failed[k]
                failed[k] = ((cur?.count ?? 0) + 1, max(cur?.latest ?? 0, l.timeMs))
            }
        }
        for (k, v) in failed {
            let banned = bannedSources.contains(k.source) ? " · banned" : ""
            lines.append(LoginLine(id: 0, timeMs: v.latest, user: k.user, source: k.source, who: "Unknown",
                                   method: k.method,
                                   result: v.count > 1 ? "Failed ×\(v.count)\(banned)" : "Failed\(banned)",
                                   ok: false))
        }
        return lines.sorted { $0.timeMs > $1.timeMs }.prefix(limit).enumerated().map {
            LoginLine(id: $0.offset, timeMs: $0.element.timeMs, user: $0.element.user,
                      source: $0.element.source, who: $0.element.who, method: $0.element.method,
                      result: $0.element.result, ok: $0.element.ok)
        }
    }

    static func methodName(_ l: LoginRow) -> String {
        switch l.method {
        case "publickey": l.deviceIdHex != nil ? "Secure Enclave key" : "Public key"
        case "password": "Password"
        case "keyboard-interactive": "Keyboard-interactive"
        default: "Other"
        }
    }
}

/// A change worth a look, from the verified event timeline.
struct ChangeAlert: Identifiable, Equatable {
    let id: String
    let timeMs: UInt64
    let title: String
    let detail: String
    let action: String
    let tab: ServerTab

    /// Config edits, new listening ports, `authorized_keys` and integrity
    /// events of the last `days`, newest first.
    static func from(_ items: [TimelineItemRow], days: Int = 7, limit: Int = 6,
                     now: Date = Date()) -> [ChangeAlert] {
        let since = UInt64((now.timeIntervalSince1970 - Double(days) * 86400) * 1000)
        var out: [ChangeAlert] = []
        for i in items where i.timeMs >= since {
            switch i.category {
            case .config:
                out.append(ChangeAlert(id: i.id, timeMs: i.timeMs, title: i.title,
                                       detail: configDetail(i.detail), action: "View diff", tab: .config))
            case .network:
                out.append(ChangeAlert(id: i.id, timeMs: i.timeMs, title: i.title, detail: i.detail,
                                       action: "Firewall", tab: .firewall))
            case .security where i.title.hasPrefix("authorized_keys"):
                out.append(ChangeAlert(id: i.id, timeMs: i.timeMs, title: i.title, detail: keysDetail(i.detail),
                                       action: "Details", tab: .users))
            case .security where i.title.hasPrefix("Integrity"):
                out.append(ChangeAlert(id: i.id, timeMs: i.timeMs, title: i.title, detail: i.detail,
                                       action: "Details", tab: .config))
            default: break
            }
        }
        return Array(out.sorted { $0.timeMs > $1.timeMs }.prefix(limit))
    }

    /// The core words a config event `version N, <source>`.
    private static func configDetail(_ d: String) -> String {
        if d.contains("fleet {") { return "Changed by Fleet" }
        if d.contains("external") { return "Edited outside Fleet" }
        return "Found by a scan; the writer is unknown"
    }

    private static func keysDetail(_ d: String) -> String {
        if d.contains("fleet {") { return "Updated by Fleet (roster sync)" }
        if d.contains("external") { return "Changed outside Fleet" }
        return "Found by a scan; the writer is unknown"
    }
}

/// Security tab (Security.dc.html): hardening, intrusion blocking,
/// vulnerabilities, login history, what needs attention and change alerts.
struct SecurityTab: View {
    @Environment(CoreBridge.self) private var core
    @Environment(IntelStore.self) private var intel
    let server: ServerRow
    @State private var hardening = HardeningModel()
    @State private var security = SecurityModeModel()
    @State private var logins: LoginsRow?
    @State private var failed24h = 0
    @State private var failedOnly = false
    @State private var bans: BansRow?
    @State private var ports: [PortRow] = []
    @State private var certs: [CertRow] = []
    @State private var deviceNames: [String: String] = [:]
    @State private var alerts: [ChangeAlert] = []
    @State private var securityUpdates: [UpgradableRow] = []
    @State private var upgrading = false
    @State private var loading = false
    @State private var error: String?

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                TabHeader(title: "Security", loading: loading, error: error, refresh: { Task { await load() } })
                SecurityModeNotice(model: security)
                HardeningAuditSection(server: server, model: hardening, security: security)
                intrusionCard
                VulnerabilitiesSection(server: server)
                loginCard
                attentionCard
                alertsCard
                HStack(alignment: .top, spacing: 16) {
                    section("Certificates") {
                        ForEach(Indexed.wrap(certs)) { c in certRow(c.value) }
                        if certs.isEmpty { empty }
                    }
                    portsCard
                }
            }
            .padding(24)
        }
        .task(id: server.id) { await load() }
        .sheet(isPresented: $upgrading, onDismiss: { Task { await loadUpdates() } }) {
            BulkRunSheet(targets: [server.id], draft: OpDraft())
        }
    }

    // MARK: intrusion blocking

    private var activeBans: [BanRow] {
        let now = UInt64(Date().timeIntervalSince1970 * 1000)
        return (bans?.bans ?? []).filter { $0.untilMs > now }
    }

    private var intrusionCard: some View {
        AdminSection(title: "Intrusion blocking") {
            Button("All bans") { openServerTab(.firewall, serverId: server.id) }
                .buttonStyle(.link)
                .accessibilityIdentifier("security.allBans")
        } content: {
            HStack(alignment: .firstTextBaseline, spacing: 8) {
                Text("\(activeBans.count)").font(.system(size: 24, weight: .semibold)).monospacedDigit()
                    .accessibilityIdentifier("security.banCount")
                Text("active bans · \(failed24h) failed login\(failed24h == 1 ? "" : "s") in 24 h")
                    .font(.base).foregroundStyle(Color.textSecondary)
            }
            ForEach(Indexed.wrap(Array(activeBans.prefix(5)))) { b in
                HStack {
                    Text(b.value.prefix == 32 || b.value.prefix == 128 ? b.value.addr : "\(b.value.addr)/\(b.value.prefix)")
                        .font(.mono(11))
                    Text(b.value.reason).foregroundStyle(Color.textSecondary)
                    Spacer()
                    Text(SecFormat.left(until: b.value.untilMs)).foregroundStyle(Color.textMuted)
                }
                .font(.secondary)
            }
            if activeBans.count > 5 {
                Text("\(activeBans.count - 5) more").font(.caption11).foregroundStyle(Color.textMuted)
            }
        }
    }

    // MARK: login history

    private var bannedSources: Set<String> { Set(activeBans.map(\.addr)) }

    private var loginCard: some View {
        let lines = LoginLine.build(logins?.logins ?? [], deviceNames: deviceNames, bannedSources: bannedSources)
        return AdminSection(title: "Login history") {
            Text("journald · sshd").font(.caption11).foregroundStyle(Color.textMuted)
            Toggle("Failed only", isOn: $failedOnly).toggleStyle(.checkbox)
                .onChange(of: failedOnly) { _, _ in Task { await loadLogins() } }
                .accessibilityIdentifier("security.failedOnly")
        } content: {
            Grid(alignment: .leading, horizontalSpacing: 16, verticalSpacing: 8) {
                GridRow {
                    Text("Time"); Text("User"); Text("Source"); Text("Method"); Text("Result")
                }
                .font(.caption11).foregroundStyle(Color.textMuted)
                Divider().gridCellUnsizedAxes(.horizontal)
                ForEach(lines) { l in
                    GridRow {
                        Text(SecFormat.clockOrDay(l.timeMs)).foregroundStyle(Color.textMuted).monospacedDigit()
                        Text(l.user)
                        VStack(alignment: .leading, spacing: 1) {
                            Text(l.source).font(.mono(11))
                            Text(l.who).font(.caption11).foregroundStyle(Color.textMuted)
                        }
                        Text(l.method).foregroundStyle(Color.textSecondary)
                        StatusPill(label: l.result, tone: l.ok ? .ok : .critical)
                    }
                    .font(.secondary)
                    .accessibilityIdentifier("security.login.\(l.id)")
                }
            }
            if lines.isEmpty { empty }
            if logins?.truncated == true {
                Text("More logins than shown.").font(.caption11).foregroundStyle(Color.textMuted)
            }
        }
    }

    // MARK: needs attention

    private var attentionCard: some View {
        AdminSection(title: "Needs attention") {
            if let r = hardening.report {
                ForEach(Indexed.wrap(hardening.toFix(r))) { f in
                    attention(title: f.value.title, detail: "\(f.value.module) · \(f.value.severity)",
                              action: f.value.fixable && f.value.status == "drifted" ? "Fix" : nil,
                              enabled: security.allowsChanges && hardening.fixing == nil,
                              id: "fix.\(f.value.module)") {
                        if let api = core.api {
                            hardening.plan(api: api, serverId: server.id, module: f.value.module)
                        }
                    }
                }
            }
            if !securityUpdates.isEmpty {
                attention(title: "\(securityUpdates.count) security update\(securityUpdates.count == 1 ? "" : "s") pending",
                          detail: securityUpdates.prefix(4).map(\.name).joined(separator: ", ")
                              + (securityUpdates.count > 4 ? " +\(securityUpdates.count - 4)" : ""),
                          action: "Upgrade", enabled: server.state == .ready, id: "upgrade") { upgrading = true }
            }
            if hardening.report == nil {
                Text("Run the hardening audit to see what needs fixing.")
                    .font(.secondary).foregroundStyle(Color.textMuted)
            } else if let r = hardening.report, hardening.toFix(r).isEmpty, securityUpdates.isEmpty {
                Text("Nothing needs attention.").font(.secondary).foregroundStyle(Tone.ok.text)
                    .accessibilityIdentifier("security.attentionNone")
            }
            if let r = hardening.report, !hardening.exceptions(r).isEmpty {
                Text("Accepted exceptions: " + hardening.exceptions(r).map(\.title).joined(separator: "; ") + ".")
                    .font(.caption11).foregroundStyle(Color.textMuted)
                    .accessibilityIdentifier("security.acceptedNote")
            }
        }
    }

    private func attention(title: String, detail: String, action: String?, enabled: Bool, id: String,
                           run: @escaping () -> Void) -> some View {
        HStack(spacing: 12) {
            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(.base)
                Text(detail).font(.secondary).foregroundStyle(Color.textSecondary)
            }
            Spacer()
            if let action {
                Button(action, action: run)
                    .disabled(!enabled)
                    .help(!security.allowsChanges && action == "Fix" ? (security.blockedReason ?? "") : "")
                    .accessibilityIdentifier("security.attention.\(id)")
            }
        }
        .padding(10)
        .background(Color.track, in: RoundedRectangle(cornerRadius: 8))
    }

    // MARK: change alerts

    private var alertsCard: some View {
        AdminSection(title: "Change alerts") {
            ForEach(alerts) { a in
                HStack(spacing: 12) {
                    Text(SecFormat.clockOrDay(a.timeMs)).font(.secondary).foregroundStyle(Color.textMuted)
                        .frame(width: 56, alignment: .leading)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(a.title).font(.base).lineLimit(1)
                        Text(a.detail).font(.secondary).foregroundStyle(Color.textSecondary).lineLimit(2)
                    }
                    Spacer()
                    Button(a.action) { openServerTab(a.tab, serverId: server.id) }
                        .buttonStyle(.link)
                        .accessibilityIdentifier("security.alert.\(a.tab.identifier)")
                }
            }
            if alerts.isEmpty {
                Text("No config, port or key changes in the last 7 days.")
                    .font(.secondary).foregroundStyle(Color.textMuted)
            }
        }
    }

    // MARK: ports, certificates

    private var portsCard: some View {
        section("Listening ports") {
            ForEach(Indexed.wrap(ports)) { p in
                HStack {
                    Text("\(p.value.proto) \(p.value.addr):\(p.value.port)").font(.mono(11))
                        .frame(width: 200, alignment: .leading)
                    Text(p.value.process ?? "–").frame(width: 110, alignment: .leading)
                    Spacer()
                    switch p.value.reachable {
                    case true?: StatusPill(label: "reachable", tone: .warn)
                    case false?: StatusPill(label: "filtered", tone: .ok)
                    case nil: EmptyView()
                    }
                }
                .font(.secondary)
            }
            if ports.isEmpty { empty }
        }
    }

    private var empty: some View {
        Text("None").font(.secondary).foregroundStyle(Color.textMuted)
    }

    private func certRow(_ c: CertRow) -> some View {
        let days = (Double(c.notAfterMs) / 1000 - Date().timeIntervalSince1970) / 86400
        return HStack {
            VStack(alignment: .leading, spacing: 1) {
                Text(c.subjects.first ?? c.source).lineLimit(1)
                Text(c.source).font(.caption11).foregroundStyle(Color.textMuted).lineLimit(1)
            }
            Spacer()
            StatusPill(label: days < 0 ? "expired" : "\(Int(days)) d",
                       tone: days < 7 ? .critical : days < 21 ? .warn : .ok)
        }
        .font(.secondary)
    }

    private func section(_ title: String, @ViewBuilder _ content: () -> some View) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(title).font(.system(size: 13, weight: .semibold))
            content()
        }
        .frame(maxWidth: .infinity, alignment: .topLeading)
        .card()
    }

    // MARK: loading

    private func load() async {
        guard let api = core.api else { return }
        loading = true
        defer { loading = false }
        error = nil
        async let mode: Void = security.load(api: api, serverId: server.id)
        deviceNames = Dictionary(uniqueKeysWithValues:
            ((try? api.rosterStatus().devices) ?? []).map { ($0.id, $0.name) })
        await loadLogins()
        do { bans = try await api.bansList(serverId: server.id) } catch { self.error = error.fleetMessage }
        do { ports = try await api.portsList(serverId: server.id) } catch { self.error = error.fleetMessage }
        do { certs = try await api.certsList(serverId: server.id) } catch { self.error = error.fleetMessage }
        await loadUpdates()
        if let tl = try? await api.timelineServer(timeline: intel.timeline, serverId: server.id, limit: 400) {
            alerts = ChangeAlert.from(tl.items)
        }
        if hardening.report == nil { await hardening.run(api: api, serverId: server.id) }
        await mode
    }

    private func loadUpdates() async {
        guard let api = core.api else { return }
        if let u = try? await api.pkgUpgradable(serverId: server.id) {
            securityUpdates = u.packages.filter(\.security)
        }
    }

    private func loadLogins() async {
        guard let api = core.api else { return }
        let now = Date().timeIntervalSince1970
        do {
            logins = try await api.loginsQuery(serverId: server.id, sinceMs: UInt64((now - 7 * 86400) * 1000),
                                               failedOnly: failedOnly, limit: 500)
            let day = UInt64((now - 86400) * 1000)
            failed24h = (logins?.logins ?? []).filter { !$0.success && $0.timeMs >= day }.count
        } catch {
            self.error = error.fleetMessage
        }
    }
}
