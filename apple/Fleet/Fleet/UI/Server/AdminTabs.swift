import SwiftUI

extension RemoteFileRow: Identifiable { public var id: String { path } }
extension UnitRow: Identifiable { public var id: String { name } }
extension UpgradableRow: Identifiable { public var id: String { name } }

/// Wraps rows without a natural key for `Table`/`ForEach`.
struct Indexed<T>: Identifiable {
    let id: Int
    let value: T
    static func wrap(_ xs: [T]) -> [Indexed<T>] {
        xs.enumerated().map { Indexed(id: $0.offset, value: $0.element) }
    }
}

/// Shared chrome for the read-mostly tabs: title row with refresh and an
/// error line.
struct TabHeader<Trailing: View>: View {
    let title: String
    let loading: Bool
    let error: String?
    let refresh: () -> Void
    @ViewBuilder var trailing: () -> Trailing

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text(title).font(.system(size: 15, weight: .semibold))
                if loading { ProgressView().controlSize(.small) }
                Spacer()
                trailing()
                Button { refresh() } label: { Image(systemName: "arrow.clockwise") }
                    .help("Refresh")
            }
            if let error {
                Text(error).font(.base).foregroundStyle(Tone.warn.text)
            }
        }
    }
}

extension TabHeader where Trailing == EmptyView {
    init(title: String, loading: Bool, error: String?, refresh: @escaping () -> Void) {
        self.init(title: title, loading: loading, error: error, refresh: refresh) { EmptyView() }
    }
}

extension View {
    func tableCard() -> some View {
        self.font(.base)
            .scrollContentBackground(.hidden)
            .background(Color.card, in: RoundedRectangle(cornerRadius: 12))
            .overlay(RoundedRectangle(cornerRadius: 12).stroke(Color.border))
    }
}

private func date(_ ms: UInt64?) -> String {
    guard let ms else { return "–" }
    return Date(timeIntervalSince1970: TimeInterval(ms) / 1000)
        .formatted(date: .abbreviated, time: .shortened)
}

// MARK: - Services

struct ServicesTab: View {
    @Environment(CoreBridge.self) private var core
    let server: ServerRow
    @State private var units: [UnitRow] = []
    @State private var filter = ""
    @State private var selection: String?
    @State private var status: UnitStatusRow?
    @State private var pending: (UnitRow, UnitAction)?
    @State private var loading = false
    @State private var error: String?

    private var shown: [UnitRow] {
        filter.isEmpty ? units : units.filter { $0.name.localizedCaseInsensitiveContains(filter) }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            TabHeader(title: "Services", loading: loading, error: error, refresh: { Task { await load() } }) {
                TextField("Filter", text: $filter).frame(width: 200)
            }
            HSplitView {
                Table(shown, selection: $selection) {
                    TableColumn("Unit") { u in Text(u.name).lineLimit(1) }
                    TableColumn("State") { u in StatusPill(label: u.active.label, tone: u.active.tone) }
                        .width(110)
                    TableColumn("Sub") { u in Text(u.sub) }.width(80)
                    TableColumn("Enabled") { u in Text(u.fileState) }.width(80)
                    TableColumn("Description") { u in Text(u.description).lineLimit(1) }
                }
                .contextMenu(forSelectionType: String.self) { names in
                    if let u = units.first(where: { names.first == $0.name }) { actionMenu(u) }
                }
                .tableCard()
                .frame(minWidth: 480)
                detail.frame(minWidth: 260, maxWidth: 340)
            }
        }
        .padding(24)
        .task(id: server.id) { await load() }
        .onChange(of: selection) { _, name in Task { await loadStatus(name) } }
        .confirmationDialog(confirmTitle, isPresented: Binding(get: { pending != nil }, set: { if !$0 { pending = nil } })) {
            Button(pending.map { $0.1.label } ?? "Run", role: pending?.1.destructive == true ? .destructive : nil) {
                if let p = pending { run(p.0, p.1) }
            }
        }
    }

    private var confirmTitle: String {
        guard let p = pending else { return "" }
        return "\(p.1.label) \(p.0.name) on \(server.name)?"
    }

    @ViewBuilder private func actionMenu(_ u: UnitRow) -> some View {
        ForEach([UnitAction.start, .stop, .restart, .reload, .enable, .disable], id: \.self) { a in
            Button(a.label) { pending = (u, a) }
        }
    }

    @ViewBuilder private var detail: some View {
        VStack(alignment: .leading, spacing: 8) {
            if let s = status {
                Text(s.unit.name).font(.system(size: 13, weight: .semibold)).lineLimit(1)
                StatusPill(label: s.unit.active.label, tone: s.unit.active.tone)
                LabeledContent("Main PID", value: s.mainPid.map(String.init) ?? "–")
                LabeledContent("Since", value: date(s.sinceMs))
                LabeledContent("Memory", value: s.memoryBytes.map(Format.bytes) ?? "–")
                LabeledContent("Tasks", value: s.tasks.map(String.init) ?? "–")
                LabeledContent("Restarts", value: "\(s.restarts)")
                Divider()
                HStack {
                    ForEach([UnitAction.start, .stop, .restart], id: \.self) { a in
                        Button(a.label) { pending = (s.unit, a) }.controlSize(.small)
                    }
                }
            } else {
                Text("Select a unit").foregroundStyle(Color.textMuted)
            }
            Spacer()
        }
        .font(.base)
        .frame(maxWidth: .infinity, alignment: .topLeading)
        .card()
    }

    private func load() async {
        guard let api = core.api else { return }
        loading = true
        defer { loading = false }
        do {
            units = try await api.unitList(serverId: server.id).sorted { $0.name < $1.name }
            error = nil
        } catch {
            self.error = error.fleetMessage
        }
    }

    private func loadStatus(_ name: String?) async {
        guard let api = core.api, let name else { status = nil; return }
        status = try? await api.unitStatus(serverId: server.id, unitName: name)
    }

    private func run(_ u: UnitRow, _ a: UnitAction) {
        guard let api = core.api else { return }
        Task {
            do {
                try await api.unitAction(serverId: server.id, unitName: u.name, action: a)
                error = nil
            } catch {
                self.error = error.fleetMessage
            }
            await load()
            await loadStatus(u.name)
        }
    }
}

extension UnitActive {
    var label: String {
        switch self {
        case .active: "active"
        case .reloading: "reloading"
        case .inactive: "inactive"
        case .failed: "failed"
        case .activating: "activating"
        case .deactivating: "deactivating"
        case .other: "other"
        }
    }

    var tone: Tone {
        switch self {
        case .active: .ok
        case .failed: .critical
        case .activating, .deactivating, .reloading: .info
        case .inactive, .other: .neutral
        }
    }
}

extension UnitAction {
    var label: String {
        switch self {
        case .start: "Start"
        case .stop: "Stop"
        case .restart: "Restart"
        case .reload: "Reload"
        case .enable: "Enable"
        case .disable: "Disable"
        }
    }

    var destructive: Bool { self == .stop || self == .disable }
}

// MARK: - Packages

struct PackagesTab: View {
    @Environment(CoreBridge.self) private var core
    let server: ServerRow
    @State private var list: UpgradableListRow?
    @State private var result: PackageChangesRow?
    @State private var confirm: Bool?
    @State private var busy = false
    @State private var error: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            TabHeader(title: "Packages", loading: busy, error: error, refresh: { Task { await load() } }) {
                Button("apt update") { Task { await refresh() } }.disabled(busy)
                Button("Upgrade security") { confirm = true }.disabled(busy || securityCount == 0)
                Button("Upgrade all") { confirm = false }
                    .buttonStyle(.borderedProminent).tint(.accent)
                    .disabled(busy || (list?.packages.isEmpty ?? true))
            }
            if let l = list {
                HStack(spacing: 16) {
                    StatusPill(label: "\(l.packages.count) upgradable", tone: l.packages.isEmpty ? .ok : .info)
                    StatusPill(label: "\(securityCount) security", tone: securityCount > 0 ? .warn : .ok)
                    if l.rebootRequired { StatusPill(label: "Reboot required", tone: .warn) }
                    Spacer()
                    Text("Lists updated \(date(l.listsUpdatedMs))").font(.secondary).foregroundStyle(Color.textMuted)
                }
            }
            Table(list?.packages ?? []) {
                TableColumn("Package") { p in Text(p.name) }
                TableColumn("Installed") { p in Text(p.current).font(.mono(11)) }
                TableColumn("Candidate") { p in Text(p.candidate).font(.mono(11)) }
                TableColumn("Security") { p in
                    if p.security { StatusPill(label: "security", tone: .warn) }
                }
                .width(90)
                TableColumn("Origin") { p in Text(p.origin).lineLimit(1) }
            }
            .tableCard()
            if let r = result {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Last run: \(r.changes.count) change\(r.changes.count == 1 ? "" : "s")\(r.rebootRequired ? " · reboot required" : "")")
                        .font(.system(size: 13, weight: .semibold))
                    ForEach(Indexed.wrap(r.changes)) { c in
                        Text("\(c.value.action) \(c.value.name) \(c.value.from ?? "") → \(c.value.to ?? "")")
                            .font(.mono(11)).foregroundStyle(Color.textSecondary)
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .card(padding: 12)
            }
        }
        .padding(24)
        .task(id: server.id) { await load() }
        .confirmationDialog(confirm == true ? "Install security updates on \(server.name)?" : "Upgrade all packages on \(server.name)?",
                            isPresented: Binding(get: { confirm != nil }, set: { if !$0 { confirm = nil } })) {
            Button("Upgrade") { if let s = confirm { upgrade(securityOnly: s) } }
        }
    }

    private var securityCount: Int { list?.packages.filter(\.security).count ?? 0 }

    private func load() async {
        guard let api = core.api else { return }
        busy = true
        defer { busy = false }
        do {
            list = try await api.pkgUpgradable(serverId: server.id)
            error = nil
        } catch {
            self.error = error.fleetMessage
        }
    }

    private func refresh() async {
        guard let api = core.api else { return }
        busy = true
        do {
            try await api.pkgRefresh(serverId: server.id)
        } catch {
            self.error = error.fleetMessage
        }
        busy = false
        await load()
    }

    private func upgrade(securityOnly: Bool) {
        guard let api = core.api else { return }
        busy = true
        Task {
            do {
                result = try await api.pkgUpgrade(serverId: server.id, securityOnly: securityOnly)
                error = nil
            } catch {
                self.error = error.fleetMessage
            }
            busy = false
            await load()
        }
    }
}

// Security: SecurityTab.swift. Firewall: FirewallTab.swift (editing with auto-revert).
