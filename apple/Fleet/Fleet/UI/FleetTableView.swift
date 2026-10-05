import SwiftUI

/// Sortable projection of a `ServerRow`: missing metrics sort as -1.
struct FleetRow: Identifiable, Equatable {
    let id: String
    let name: String
    let host: String
    let group: String
    let tags: [String]
    let state: ConnState
    /// Worst first: offline / retrying, then critical and warning notes,
    /// then healthy.
    let health: Int
    /// Status pill: the health note when connected, else the connection state.
    let statusLabel: String
    let statusTone: Tone
    let needsAttention: Bool
    let cpu: Double
    let mem: Double
    let disk: Double
    let uptime: Int64
    /// Pending package updates; -1 when not read.
    let updates: Int
    let securityUpdates: Int
    let rebootRequired: Bool
    let cpuSpark: [Float]
    let row: ServerRow

    init(_ r: ServerRow, groupName: String?, facts: FleetFactsRow?, alert: AlertInfo?) {
        id = r.id
        name = r.name
        host = r.host
        group = groupName ?? ""
        tags = r.tags
        state = r.state
        row = r
        cpu = r.cpuPercent.map(Double.init) ?? -1
        mem = r.memPercent.map(Double.init) ?? -1
        disk = r.diskPercent.map(Double.init) ?? -1
        let up = facts?.uptimeS ?? r.uptimeS
        uptime = up.map { Int64(clamping: $0) } ?? -1
        updates = (facts?.updates ?? r.pendingUpdates).map(Int.init) ?? -1
        securityUpdates = facts?.securityUpdates.map(Int.init) ?? 0
        rebootRequired = facts?.rebootRequired ?? false
        cpuSpark = facts?.cpuSpark ?? []

        if r.state == .ready {
            let n = fleetHealthNote(input: HealthNoteInput(
                online: true, diskPercent: r.diskPercent, memPercent: r.memPercent,
                alertRule: alert?.ruleId, alertSubject: alert?.subject,
                alertSeverity: alert?.severity))
            statusLabel = n.text
            switch n.tone {
            case .ok: statusTone = .ok; health = 9; needsAttention = false
            case .warn: statusTone = .warn; health = 6; needsAttention = true
            case .critical: statusTone = .critical; health = 5; needsAttention = true
            }
        } else {
            statusLabel = r.state == .offline
                ? "Offline" + FleetRow.offlineSuffix(r.lastSeenMs) : r.state.label
            statusTone = r.state == .offline ? .neutral : r.state.tone
            health = r.state.rank
            needsAttention = true
        }
    }

    /// " · 2 h" since the server was last heard from.
    static func offlineSuffix(_ lastSeenMs: UInt64?) -> String {
        guard let ms = lastSeenMs else { return "" }
        let s = max(0, Date().timeIntervalSince1970 - Double(ms) / 1000)
        if s < 90 { return "" }
        if s < 3600 { return " · \(Int(s / 60)) min" }
        if s < 86_400 { return " · \(Int(s / 3600)) h" }
        return " · \(Int(s / 86_400)) d"
    }
}

enum FleetFilter: String, CaseIterable, Identifiable {
    case all = "All"
    case attention = "Needs attention"
    case updates = "Updates"
    var id: String { rawValue }
}

struct FleetTableView: View {
    @Environment(CoreBridge.self) private var core
    @Environment(IntelStore.self) private var intel
    /// Restrict to one group.
    var groupId: String?
    @Binding var selection: NavItem?

    @State private var sortOrder = [KeyPathComparator(\FleetRow.health)]
    @State private var selected = Set<String>()
    @State private var filter: FleetFilter = .all
    @State private var showAdd = false
    @State private var showBulk = false
    @State private var editing: ServerRow?
    @State private var showNewGroup = false
    /// Servers awaiting the remove confirmation.
    @State private var removing: [String]?
    @State private var actionError: String?
    @State private var store = FleetFactsStore.shared

    /// Worst open alert per server.
    private var worstAlerts: [String: AlertInfo] {
        var out: [String: AlertInfo] = [:]
        for e in core.alerts.values {
            guard let a = e.alert, !a.cleared else { continue }
            let rank = { (s: AlertSeverity?) in s == .critical ? 2 : (s == .warning ? 1 : 0) }
            if rank(a.severity) >= rank(out[e.serverId]?.severity) { out[e.serverId] = a }
        }
        return out
    }

    private var allRows: [FleetRow] {
        let names = Dictionary(uniqueKeysWithValues: core.groups.map { ($0.id, $0.name) })
        let alerts = worstAlerts
        return core.servers
            .filter { groupId == nil || $0.groupId == groupId }
            .map { FleetRow($0, groupName: $0.groupId.flatMap { names[$0] },
                            facts: store.facts($0.id), alert: alerts[$0.id]) }
    }

    private func rows(of all: [FleetRow]) -> [FleetRow] {
        all.filter { r in
            switch filter {
            case .all: true
            case .attention: r.needsAttention
            case .updates: r.updates > 0
            }
        }
        .sorted(using: sortOrder)
    }

    private var title: String {
        guard let groupId else { return "Fleet" }
        return core.groups.first { $0.id == groupId }?.name ?? "Group"
    }

    private func subtitle(_ shown: Int) -> String {
        var s = "\(shown) \(shown == 1 ? "server" : "servers")"
        if groupId == nil { s += " · \(core.groups.count) \(core.groups.count == 1 ? "group" : "groups")" }
        let versions = Set(store.facts.values.compactMap(\.agentVersion))
        if versions.count == 1, let v = versions.first { s += " · agents on \(v)" }
        else if versions.count > 1 { s += " · \(versions.count) agent versions" }
        return s
    }

    var body: some View {
        let all = allRows
        VStack(alignment: .leading, spacing: 0) {
            header(all)
            if core.servers.isEmpty {
                ScrollView {
                    VStack(alignment: .leading, spacing: 20) {
                        StatusBanners()
                        emptyState
                    }
                    .padding(24)
                }
            } else {
                ScrollView {
                    VStack(alignment: .leading, spacing: 20) {
                        StatusBanners()
                        summary(all)
                        digestCard
                        table(rows(of: all))
                    }
                    .padding(24)
                }
            }
        }
        .background(Color.window)
        .sheet(isPresented: $showAdd) { AddServerSheet() }
        .sheet(isPresented: $showBulk) {
            BulkRunSheet(targets: bulkTargets)
        }
        .sheet(item: $editing) { EditServerSheet(server: $0) }
        .sheet(isPresented: $showNewGroup) { GroupNameSheet(group: nil) }
        .confirmationDialog(removeTitle, isPresented: Binding(
            get: { removing != nil }, set: { if !$0 { removing = nil } }
        ), titleVisibility: .visible) {
            Button("Remove", role: .destructive) { removeConfirmed() }
                .accessibilityIdentifier("fleet.confirmRemove")
        } message: {
            Text("Fleet forgets the server: its pinned keys and cached history are deleted "
                 + "on this Mac. The agent stays on the server; uninstall it first to remove it.")
        }
        .alert("Couldn't complete the action", isPresented: Binding(
            get: { actionError != nil }, set: { if !$0 { actionError = nil } }
        )) {
            Button("OK", role: .cancel) {}
        } message: {
            Text(actionError ?? "")
        }
        .task(id: core.servers.filter { $0.state == .ready }.map(\.id)) {
            store.startActivityStamp()
            while !Task.isCancelled {
                await store.refresh(core)
                await store.refreshDigest(core, intel: intel)
                try? await Task.sleep(for: .seconds(60))
            }
        }
    }

    private var removeTitle: String {
        let ids = removing ?? []
        if ids.count == 1, let s = core.servers.first(where: { $0.id == ids[0] }) {
            return "Remove \(s.name)?"
        }
        return "Remove \(ids.count) servers?"
    }

    private func removeConfirmed() {
        var failures: [String] = []
        for id in removing ?? [] {
            do { try core.removeServer(id) } catch { failures.append(error.fleetMessage) }
        }
        selected.subtract(removing ?? [])
        removing = nil
        if !failures.isEmpty { actionError = failures.joined(separator: "\n") }
    }

    private func move(_ ids: Set<String>, to group: String?) {
        for id in ids {
            guard let s = core.servers.first(where: { $0.id == id }) else { continue }
            do { try core.setPlacement(id, groupId: group, tags: s.tags) } catch {
                actionError = error.fleetMessage
            }
        }
    }

    /// Selected servers, else every connected one.
    private var bulkTargets: [String] {
        if !selected.isEmpty { return core.servers.filter { selected.contains($0.id) }.map(\.id) }
        return core.servers.filter { $0.state == .ready }.map(\.id)
    }

    private func header(_ all: [FleetRow]) -> some View {
        HStack(spacing: 16) {
            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(.toolbarTitle).foregroundStyle(Color.text)
                Text(subtitle(all.count))
                    .font(.secondary).foregroundStyle(Color.textMuted)
                    .lineLimit(1)
                    .accessibilityIdentifier("fleet.subtitle")
            }
            Spacer(minLength: 0)
            // Trailing, so the subtitle length can't shift it.
            Picker("Filter", selection: $filter) {
                ForEach(FleetFilter.allCases) { f in
                    Text(filterLabel(f, all)).tag(f)
                }
            }
            .fleetSegmented()
            .labelsHidden()
            .focusEffectDisabled()
            .frame(width: 380)
            .accessibilityIdentifier("fleet.filter")
            Button("Run command", systemImage: "terminal") { showBulk = true }
                .buttonStyle(.fleetSecondary)
                .disabled(core.servers.isEmpty)
                .help(selected.isEmpty ? "Run on every connected server"
                                       : "Run on the \(selected.count) selected servers")
                .accessibilityIdentifier("fleet.runCommand")
            Button("Add server", systemImage: "plus") { showAdd = true }
                .buttonStyle(.fleetSecondary)
                .accessibilityIdentifier("fleet.addServer")
            Button("Provision server", systemImage: "plus") { selection = .provision }
                .accessibilityIdentifier("fleet.provision")
                .buttonStyle(.fleetPrimary)
        }
        .padding(.horizontal, 24)
        .frame(height: 60)
        .background(Color.header)
        .overlay(alignment: .bottom) { Rectangle().fill(Color.border).frame(height: 1) }
    }

    private func filterLabel(_ f: FleetFilter, _ all: [FleetRow]) -> String {
        switch f {
        case .all: f.rawValue
        case .attention: "\(f.rawValue) · \(all.filter(\.needsAttention).count)"
        case .updates: "\(f.rawValue) · \(all.filter { $0.updates > 0 }.count)"
        }
    }

    private var emptyState: some View {
        VStack(spacing: 12) {
            Image(systemName: "server.rack").font(.system(size: 34)).foregroundStyle(Color.textMuted)
            Text("No servers yet").font(.toolbarTitle).foregroundStyle(Color.text)
            Text("Provision a new server, or add one that already exists.")
                .font(.base).foregroundStyle(Color.textSecondary)
            HStack {
                Button("Add server", systemImage: "plus") { showAdd = true }
                    .buttonStyle(.fleetSecondary)
                    .accessibilityIdentifier("fleet.empty.add")
                Button("Provision server") { selection = .provision }
                    .buttonStyle(.fleetPrimary)
                    .accessibilityIdentifier("fleet.empty.provision")
            }
        }
        .frame(maxWidth: .infinity, minHeight: 280)
        .card()
        .accessibilityIdentifier("fleet.empty")
    }

    // MARK: summary

    private func summary(_ all: [FleetRow]) -> some View {
        let online = all.filter { $0.state == .ready }.count
        let notOnline = all.filter { $0.state != .ready }
        let warnings = core.alerts.values.filter { ($0.alert?.severity) == .warning }.count
        let critical = core.criticalCount
        let secKnown = store.facts.values.contains { $0.updates != nil }
        return HStack(spacing: 16) {
            SummaryCard(title: "Online", value: "\(online)", suffix: "/ \(all.count)",
                        note: onlineNote(notOnline, total: all.count), id: "online")
            SummaryCard(title: "Open alerts", value: "\(core.alerts.count)", suffix: nil,
                        note: warnings > 0 ? "\(critical) critical · \(warnings) warnings"
                                           : "\(critical) critical",
                        valueTone: critical > 0 ? Tone.critical.text
                            : (core.alerts.isEmpty ? nil : Tone.warn.text),
                        id: "alerts")
            SummaryCard(title: "Security updates",
                        value: secKnown ? "\(store.securityUpdateTotal)" : "–", suffix: nil,
                        note: secKnown
                            ? (store.securityUpdateServers == 0 ? "Nothing pending"
                                : "Across \(store.securityUpdateServers) \(store.securityUpdateServers == 1 ? "server" : "servers")")
                            : "Reading package lists",
                        actionTitle: store.securityUpdateTotal > 0 ? "Roll out" : nil,
                        action: { rollOutSecurity() }, id: "security")
            SummaryCard(title: "Reboot required",
                        value: secKnown ? "\(store.rebootRequiredCount)" : "–", suffix: nil,
                        note: secKnown
                            ? (store.rebootRequiredCount == 0 ? "Nothing pending" : "Kernel updates installed")
                            : "Reading package lists",
                        id: "reboot")
        }
    }

    private func onlineNote(_ notOnline: [FleetRow], total: Int) -> String {
        guard let first = notOnline.first else { return total == 0 ? "No servers" : "All servers connected" }
        let dur = FleetRow.offlineSuffix(first.row.lastSeenMs).replacingOccurrences(of: " · ", with: "")
        let base = first.state == .offline
            ? "\(first.name) unreachable" + (dur.isEmpty ? "" : " for \(dur)")
            : "\(first.name) \(first.state.label.lowercased())"
        return notOnline.count > 1 ? base + " · +\(notOnline.count - 1) more" : base
    }

    /// Security upgrade on every connected server that has one pending.
    private func rollOutSecurity() {
        let ids = store.facts.values.filter { ($0.securityUpdates ?? 0) > 0 }.map(\.serverId)
        selected = Set(ids)
        showBulk = true
    }

    // MARK: digest

    @ViewBuilder
    private var digestCard: some View {
        if let d = store.digest {
            HStack(alignment: .center, spacing: 24) {
                VStack(alignment: .leading, spacing: 2) {
                    Text("While you were away").fontWeight(.semibold).foregroundStyle(Color.text)
                    Text("Since " + Self.since(d.sinceMs))
                        .font(.secondary).foregroundStyle(Color.textMuted)
                }
                .frame(width: 160, alignment: .leading)
                if d.lines.isEmpty {
                    Text("Nothing notable happened.")
                        .font(.base).foregroundStyle(Color.textSecondary)
                        .frame(maxWidth: .infinity, alignment: .leading)
                } else {
                    HStack(alignment: .top, spacing: 24) {
                        ForEach(Array(d.lines.enumerated()), id: \.offset) { i, l in
                            VStack(alignment: .leading, spacing: 2) {
                                Text(l.title).fontWeight(.medium)
                                    .foregroundStyle(digestColor(l.tone))
                                    .lineLimit(2)
                                if !l.detail.isEmpty {
                                    Text(l.detail).font(.secondary).foregroundStyle(Color.textMuted)
                                        .lineLimit(2)
                                }
                            }
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .accessibilityElement(children: .combine)
                            .accessibilityIdentifier("fleet.digest.line.\(i)")
                        }
                    }
                }
                Button("Open timeline") { selection = .timeline }
                    .accessibilityIdentifier("fleet.digest.timeline")
            }
            .padding(.horizontal, 18).padding(.vertical, 14)
            .background(Color.card, in: RoundedRectangle(cornerRadius: 12))
            .overlay(RoundedRectangle(cornerRadius: 12).stroke(Color.border))
            .accessibilityIdentifier("fleet.digest")
        }
    }

    private func digestColor(_ t: NoteTone) -> Color {
        switch t {
        case .ok: Color.text
        case .warn: Tone.warn.text
        case .critical: Tone.critical.text
        }
    }

    private static func since(_ ms: UInt64) -> String {
        let d = Date(timeIntervalSince1970: TimeInterval(ms) / 1000)
        let cal = Calendar.current
        let time = d.formatted(date: .omitted, time: .shortened)
        if cal.isDateInToday(d) { return "today \(time)" }
        if cal.isDateInYesterday(d) { return "yesterday \(time)" }
        return d.formatted(date: .abbreviated, time: .shortened)
    }

    // MARK: table

    private func table(_ rows: [FleetRow]) -> some View {
        Table(rows, selection: $selected, sortOrder: $sortOrder) {
            TableColumn("Server", value: \.name) { r in
                VStack(alignment: .leading, spacing: 1) {
                    Text(r.name).fontWeight(.medium).foregroundStyle(Color.text)
                    Text(r.host).font(.mono(11)).foregroundStyle(Color.textMuted)
                }
            }
            .width(min: 130)
            TableColumn("Group", value: \.group) { r in
                VStack(alignment: .leading, spacing: 1) {
                    Text(r.group.isEmpty ? "–" : r.group).foregroundStyle(Color.text)
                    if !r.tags.isEmpty {
                        Text(r.tags.joined(separator: " · "))
                            .font(.caption11).foregroundStyle(Color.textMuted).lineLimit(1)
                    }
                }
            }
            .width(min: 80)
            TableColumn("Status", value: \.health) { r in
                StatusPill(label: r.statusLabel, tone: r.statusTone)
            }
            .width(min: 110)
            TableColumn("CPU · 1 h", value: \.cpu) { r in cpuCell(r) }
                .width(min: 120)
            TableColumn("Memory", value: \.mem) { r in
                barCell(r.row.memPercent, hot: false)
            }
            .width(min: 100)
            TableColumn("Disk", value: \.disk) { r in
                barCell(r.row.diskPercent, hot: (r.row.diskPercent ?? 0) >= 85)
            }
            .width(min: 100)
            TableColumn("Updates", value: \.updates) { r in updatesCell(r) }
                .width(min: 80)
            TableColumn("Uptime", value: \.uptime) { r in
                Text(r.state == .ready ? Format.uptime(r.uptime < 0 ? nil : UInt64(r.uptime)) : "—")
                    .monospacedDigit().foregroundStyle(Color.text)
            }
            .width(min: 60)
        }
        .accessibilityIdentifier("fleet.table")
        .contextMenu(forSelectionType: String.self) { ids in
            Button("Open") { if let id = ids.first { selection = .server(id) } }
            Button("Run command on \(ids.count) server\(ids.count == 1 ? "" : "s")…") {
                selected = ids
                showBulk = true
            }
            .accessibilityIdentifier("fleet.menu.run")
            Button("Reconnect") { ids.forEach(core.reconnect) }
            Divider()
            if ids.count == 1, let id = ids.first, let s = core.servers.first(where: { $0.id == id }) {
                Button("Edit group and tags…") { editing = s }
                    .accessibilityIdentifier("fleet.menu.edit")
            }
            Menu("Move to group") {
                Button("None") { move(ids, to: nil) }
                ForEach(core.groups, id: \.id) { g in
                    Button(g.name) { move(ids, to: g.id) }
                }
                Divider()
                Button("New group…") { showNewGroup = true }
            }
            .accessibilityIdentifier("fleet.menu.moveToGroup")
            Divider()
            Button("Remove…", role: .destructive) { removing = Array(ids) }
                .accessibilityIdentifier("fleet.menu.remove")
        } primaryAction: { ids in
            if let id = ids.first { selection = .server(id) }
        }
        .font(.base)
        .alternatingRowBackgrounds(.disabled)
        // Header + one two-line row each (measured ~28 + 39 px), so no
        // filler rows show; the page scrolls vertically, not the table.
        .frame(height: 30 + 40 * CGFloat(max(rows.count, 1)))
        .scrollIndicators(.never, axes: .vertical)
        .scrollContentBackground(.hidden)
        .background(Color.card, in: RoundedRectangle(cornerRadius: 12))
        .overlay(RoundedRectangle(cornerRadius: 12).stroke(Color.border))
    }

    @ViewBuilder
    private func cpuCell(_ r: FleetRow) -> some View {
        if r.state == .ready, let cpu = r.row.cpuPercent {
            HStack(spacing: 8) {
                Sparkline(values: r.cpuSpark,
                          color: r.statusTone == .warn ? Tone.warn.dot : Color.accent)
                    .frame(width: 64, height: 22)
                Text(Format.percent(cpu)).monospacedDigit().foregroundStyle(Color.text)
            }
        } else {
            Text("—").foregroundStyle(Color.textMuted)
        }
    }

    @ViewBuilder
    private func barCell(_ v: Float?, hot: Bool) -> some View {
        if let v {
            HStack(spacing: 8) {
                ZStack(alignment: .leading) {
                    Capsule().fill(hot ? Tone.critical.bg : Color.border)
                    GeometryReader { g in
                        Capsule().fill(hot ? Tone.critical.dot : Color(hex: 0x7b818b))
                            .frame(width: g.size.width * CGFloat(min(max(v, 0), 100)) / 100)
                    }
                }
                .frame(width: 56, height: 6)
                Text(Format.percent(v)).monospacedDigit()
                    .foregroundStyle(hot ? Tone.critical.text : Color.text)
            }
        } else {
            Text("—").foregroundStyle(Color.textMuted)
        }
    }

    @ViewBuilder
    private func updatesCell(_ r: FleetRow) -> some View {
        if r.updates < 0 || r.state != .ready {
            Text("—").foregroundStyle(Color.textMuted)
        } else if r.updates == 0 {
            Text("Up to date").font(.secondary).foregroundStyle(Color.textMuted)
        } else {
            Text("\(r.updates) pending").font(.secondary).fontWeight(.medium)
                .foregroundStyle(Tone.info.text)
                .padding(.horizontal, 8).frame(height: 22)
                .background(Tone.info.bg, in: RoundedRectangle(cornerRadius: 6))
        }
    }
}

/// Line chart without axes (CPU history in the fleet table).
struct Sparkline: View {
    let values: [Float]
    let color: Color

    var body: some View {
        Canvas { ctx, size in
            guard values.count > 1 else {
                var p = Path()
                p.move(to: CGPoint(x: 0, y: size.height - 1))
                p.addLine(to: CGPoint(x: size.width, y: size.height - 1))
                ctx.stroke(p, with: .color(Color.border), lineWidth: 1)
                return
            }
            // Scale to at least 0–50 % so quiet servers stay flat.
            let top = max(50, CGFloat(values.max() ?? 50))
            var p = Path()
            for (i, v) in values.enumerated() {
                let x = size.width * CGFloat(i) / CGFloat(values.count - 1)
                let y = size.height - 1 - (size.height - 2) * CGFloat(v) / top
                if i == 0 { p.move(to: CGPoint(x: x, y: y)) } else { p.addLine(to: CGPoint(x: x, y: y)) }
            }
            ctx.stroke(p, with: .color(color), style: StrokeStyle(lineWidth: 1.5, lineJoin: .round))
        }
        .accessibilityHidden(true)
    }
}

private struct SummaryCard: View {
    let title: String
    let value: String
    let suffix: String?
    let note: String
    var valueTone: Color?
    var actionTitle: String?
    var action: (() -> Void)?
    let id: String

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(title).font(.secondary).foregroundStyle(Color.textSecondary)
            HStack(alignment: .firstTextBaseline, spacing: 4) {
                Text(value).font(Typeface.ui(28, .semibold)).monospacedDigit()
                    .foregroundStyle(valueTone ?? Color.text)
                if let suffix {
                    Text(suffix).font(.base).foregroundStyle(Color.textMuted)
                }
            }
            HStack(spacing: 4) {
                Text(note).font(.caption11).foregroundStyle(Color.textMuted)
                if let actionTitle, let action {
                    Text("·").font(.caption11).foregroundStyle(Color.textMuted)
                    Button(actionTitle, action: action)
                        .buttonStyle(.plain).font(.caption11).fontWeight(.medium)
                        .foregroundStyle(Color.accentText)
                        .accessibilityIdentifier("fleet.card.\(id).action")
                }
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .card()
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier("fleet.card.\(id)")
    }
}

/// Enrollment, key backend and host key prompts.
struct StatusBanners: View {
    @Environment(CoreBridge.self) private var core

    var body: some View {
        VStack(spacing: 8) {
            switch core.status {
            case .notEnrolled:
                banner("This Mac is not enrolled in a fleet yet. Servers are listed but not connected.",
                       tone: .info)
            case .failed(let msg):
                banner("Core failed to start: \(msg)", tone: .critical)
            case .starting, .running:
                EmptyView()
            }
            if let alert = core.securityAlert {
                banner(alert, tone: .critical)
            }
            if core.usesSoftwareKeys {
                banner("Software keys in use (no Secure Enclave). Development only.", tone: .warn)
            }
            ForEach(core.hostKeyPrompts, id: \.self) { p in
                HStack {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("New host key for \(serverName(p.serverId))")
                            .foregroundStyle(Tone.warn.text)
                        if p.targetUnpinned {
                            Text("\(p.algorithm) \(p.fingerprint)").font(.mono(11))
                                .foregroundStyle(Color.textSecondary)
                                .textSelection(.enabled)
                        }
                        ForEach(p.jumps, id: \.self) { j in
                            Text(verbatim: "via \(j.host):\(j.port) \(j.algorithm) \(j.fingerprint)").font(.mono(11))
                                .foregroundStyle(Color.textSecondary)
                                .textSelection(.enabled)
                        }
                    }
                    Spacer()
                    Button("Reject") { core.resolveHostKey(p, accept: false) }
                        .accessibilityIdentifier("fleet.hostKey.reject")
                    Button("Trust") { core.resolveHostKey(p, accept: true) }
                        .accessibilityIdentifier("fleet.hostKey.trust")
                        .buttonStyle(.borderedProminent)
                }
                .padding(12)
                .background(Tone.warn.bg, in: RoundedRectangle(cornerRadius: 8))
            }
        }
    }

    private func serverName(_ id: String) -> String {
        core.servers.first { $0.id == id }?.name ?? id
    }

    private func banner(_ text: String, tone: Tone) -> some View {
        Text(text)
            .font(.base)
            .foregroundStyle(tone.text)
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(12)
            .background(tone.bg, in: RoundedRectangle(cornerRadius: 8))
    }
}
