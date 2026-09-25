import SwiftUI

/// Sortable projection of a `ServerRow`: missing metrics sort as -1.
struct FleetRow: Identifiable, Equatable {
    let id: String
    let name: String
    let host: String
    let group: String
    let state: ConnState
    let health: Int
    let cpu: Double
    let mem: Double
    let disk: Double
    let uptime: Int64
    let kernel: String
    let updates: Int
    let agent: String
    let lastSeen: Int64
    /// Packages with an available security fix; -1 when not scanned.
    let vulnerable: Int
    let row: ServerRow

    init(_ r: ServerRow, groupName: String?, vulnerable: Int = -1) {
        self.vulnerable = vulnerable
        id = r.id
        name = r.name
        host = r.host
        group = groupName ?? ""
        state = r.state
        health = r.state.rank
        cpu = r.cpuPercent.map(Double.init) ?? -1
        mem = r.memPercent.map(Double.init) ?? -1
        disk = r.diskPercent.map(Double.init) ?? -1
        uptime = r.uptimeS.map { Int64(clamping: $0) } ?? -1
        kernel = r.kernel ?? ""
        updates = r.pendingUpdates.map(Int.init) ?? -1
        agent = r.agentVersion ?? ""
        lastSeen = r.lastSeenMs.map { Int64(clamping: $0) } ?? -1
        row = r
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

    private var rows: [FleetRow] {
        let names = Dictionary(uniqueKeysWithValues: core.groups.map { ($0.id, $0.name) })
        return core.servers
            .filter { groupId == nil || $0.groupId == groupId }
            .map { FleetRow($0, groupName: $0.groupId.flatMap { names[$0] },
                            vulnerable: intel.vulnerableCount($0.id)) }
            .filter { r in
                switch filter {
                case .all: true
                case .attention: r.state != .ready
                case .updates: r.updates > 0
                }
            }
            .sorted(using: sortOrder)
    }

    private var title: String {
        guard let groupId else { return "Fleet" }
        return core.groups.first { $0.id == groupId }?.name ?? "Group"
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header
            ScrollView {
                VStack(alignment: .leading, spacing: 20) {
                    StatusBanners()
                    summary
                    table
                }
                .padding(24)
            }
        }
        .background(Color.window)
        .sheet(isPresented: $showAdd) { AddServerSheet() }
    }

    private var header: some View {
        HStack(spacing: 16) {
            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(.toolbarTitle).foregroundStyle(Color.text)
                Text("\(core.servers.count) servers · \(core.groups.count) groups")
                    .font(.secondary).foregroundStyle(Color.textMuted)
            }
            Picker("Filter", selection: $filter) {
                ForEach(FleetFilter.allCases) { Text($0.rawValue).tag($0) }
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .frame(width: 320)
            Spacer()
            Button("Run command", systemImage: "terminal") {}
                .disabled(true)
                .help("Bulk actions arrive with the bulk engine")
            Button("Add server", systemImage: "plus") { showAdd = true }
                .buttonStyle(.borderedProminent)
                .tint(.accent)
        }
        .padding(.horizontal, 24)
        .frame(height: 60)
        .background(Color.header)
    }

    private var summary: some View {
        HStack(spacing: 16) {
            SummaryCard(title: "Online", value: "\(core.onlineCount)",
                        suffix: "/ \(core.servers.count)", note: "Ready sessions")
            SummaryCard(title: "Open alerts", value: "\(core.alerts.count)",
                        suffix: nil, note: "\(core.criticalCount) critical")
            SummaryCard(title: "Security updates", value: "–", suffix: nil, note: "Needs package data")
            SummaryCard(title: "Reboot required", value: "–", suffix: nil, note: "Needs package data")
        }
    }

    private var table: some View {
        // TableColumnBuilder takes at most 10 columns; typed halves also
        // keep the type checker fast.
        Table(rows, selection: $selected, sortOrder: $sortOrder) {
            leadingColumns
            trailingColumns
        }
        .contextMenu(forSelectionType: String.self) { ids in
            Button("Open") { if let id = ids.first { selection = .server(id) } }
            Button("Reconnect") { ids.forEach(core.reconnect) }
            Divider()
            Button("Remove", role: .destructive) { ids.forEach { try? core.removeServer($0) } }
        } primaryAction: { ids in
            if let id = ids.first { selection = .server(id) }
        }
        .font(.base)
        .frame(minHeight: 420)
        .scrollContentBackground(.hidden)
        .background(Color.card, in: RoundedRectangle(cornerRadius: 12))
        .overlay(RoundedRectangle(cornerRadius: 12).stroke(Color.border))
    }

    @TableColumnBuilder<FleetRow, KeyPathComparator<FleetRow>>
    private var trailingColumns: some TableColumnContent<FleetRow, KeyPathComparator<FleetRow>> {
        TableColumn("Updates", value: \.updates) { r in count(r.updates) }
            .width(64)
        TableColumn("Vulnerable", value: \.vulnerable) { r in vulnerable(r.vulnerable) }
            .width(72)
        TableColumn("Agent", value: \.agent) { r in
            Text(r.agent.isEmpty ? "–" : r.agent).font(.mono(11))
        }
        .width(64)
        TableColumn("Last seen", value: \.lastSeen) { r in
            Text(Format.lastSeen(r.row.lastSeenMs))
        }
    }

    @TableColumnBuilder<FleetRow, KeyPathComparator<FleetRow>>
    private var leadingColumns: some TableColumnContent<FleetRow, KeyPathComparator<FleetRow>> {
        TableColumn("Server", value: \.name) { r in
            VStack(alignment: .leading, spacing: 1) {
                Text(r.name).foregroundStyle(Color.text)
                Text(r.host).font(.mono(11)).foregroundStyle(Color.textMuted)
            }
        }
        .width(min: 140, ideal: 180)
        TableColumn("Status", value: \.health) { r in
            StatusPill(label: r.state.label, tone: r.state.tone)
        }
        .width(min: 110, ideal: 130)
        TableColumn("CPU", value: \.cpu) { r in metric(r.row.cpuPercent) }.width(56)
        TableColumn("Memory", value: \.mem) { r in metric(r.row.memPercent) }.width(64)
        TableColumn("Disk", value: \.disk) { r in metric(r.row.diskPercent) }.width(56)
        TableColumn("Uptime", value: \.uptime) { r in
            Text(Format.uptime(r.row.uptimeS)).monospacedDigit()
        }
        .width(64)
        TableColumn("Kernel", value: \.kernel) { r in
            Text(r.kernel.isEmpty ? "–" : r.kernel).font(.mono(11))
        }
    }

    private func count(_ n: Int) -> Text {
        Text(n < 0 ? "–" : String(n)).monospacedDigit()
    }

    private func vulnerable(_ n: Int) -> some View {
        count(n)
            .foregroundStyle(n > 0 ? Tone.warn.text : Color.text)
            .help("Packages with an available security fix")
    }

    private func metric(_ v: Float?) -> some View {
        Text(Format.percent(v)).monospacedDigit()
    }
}

private struct SummaryCard: View {
    let title: String
    let value: String
    let suffix: String?
    let note: String

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(title).font(.secondary).foregroundStyle(Color.textSecondary)
            HStack(alignment: .firstTextBaseline, spacing: 4) {
                Text(value).font(.system(size: 26, weight: .semibold)).monospacedDigit()
                    .foregroundStyle(Color.text)
                if let suffix {
                    Text(suffix).font(.base).foregroundStyle(Color.textMuted)
                }
            }
            Text(note).font(.caption11).foregroundStyle(Color.textMuted)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .card()
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
                            Text("via \(j.host):\(j.port) \(j.algorithm) \(j.fingerprint)").font(.mono(11))
                                .foregroundStyle(Color.textSecondary)
                                .textSelection(.enabled)
                        }
                    }
                    Spacer()
                    Button("Reject") { core.resolveHostKey(p, accept: false) }
                    Button("Trust") { core.resolveHostKey(p, accept: true) }
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

