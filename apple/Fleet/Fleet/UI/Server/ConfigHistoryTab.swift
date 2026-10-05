import SwiftUI

extension ConfigVersionRow: Identifiable {
    public var id: String { "\(path)#\(version)" }
}

/// Config history (design §4.9): every tracked file's versions, colored
/// diffs, rollback with confirmation (protected paths need Touch ID).
struct ConfigHistoryTab: View {
    @Environment(CoreBridge.self) private var core
    let server: ServerRow
    @State private var history: ConfigHistoryRow?
    @State private var paths: ConfigPathsRow?
    @State private var filter = ""
    @State private var selection: String?
    @State private var diff: ConfigDiffRow?
    @State private var againstLive = false
    @State private var loading = false
    @State private var error: String?
    @State private var pending: PendingAction?

    private var versions: [ConfigVersionRow] {
        let all = history?.versions ?? []
        return filter.isEmpty ? all : all.filter { $0.path.localizedCaseInsensitiveContains(filter) }
    }

    private var selected: ConfigVersionRow? { versions.first { $0.id == selection } }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            TabHeader(title: "Config history", loading: loading, error: error, refresh: { Task { await load() } }) {
                TextField("Filter paths", text: $filter).frame(width: 220)
            }
            if let p = paths {
                DisclosureGroup("Tracked paths") {
                    VStack(alignment: .leading, spacing: 2) {
                        ForEach(p.builtinTracked + p.tracked, id: \.self) { Text($0).font(.mono(11)) }
                        Text("Secret (hash only): " + (p.builtinSecret + p.secret).joined(separator: ", "))
                            .font(.caption11).foregroundStyle(Color.textMuted)
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
                .font(.secondary)
            }
            HSplitView {
                Table(versions, selection: $selection) {
                    TableColumn("Path") { v in Text(v.path).font(.mono(11)).lineLimit(1).truncationMode(.head) }
                    TableColumn("Ver") { v in Text(verbatim: String(v.version)) }.width(36)
                    TableColumn("When") { v in Text(fmtDate(v.timeMs)) }.width(160)
                    TableColumn("By") { v in Text(v.source).lineLimit(1) }.width(90)
                    TableColumn("") { v in
                        if v.deleted { StatusPill(label: "deleted", tone: .warn) }
                        else if v.secret { StatusPill(label: "secret", tone: .neutral) }
                    }
                    .width(70)
                }
                .tableCard()
                .frame(minWidth: 520)
                // Capped so the list (long paths) keeps the larger share;
                // the split view ignores ideal widths.
                detail.frame(minWidth: 380, maxWidth: 460)
            }
            if history?.truncated == true {
                Text("Older versions exist.").font(.caption11).foregroundStyle(Color.textMuted)
            }
        }
        .padding(24)
        .task(id: server.id) { await load() }
        .onChange(of: selection) { _, _ in Task { await loadDiff() } }
        .onChange(of: againstLive) { _, _ in Task { await loadDiff() } }
        .confirmAction($pending)
    }

    @ViewBuilder private var detail: some View {
        VStack(alignment: .leading, spacing: 8) {
            if let v = selected {
                HStack {
                    Text(v.path).font(.mono(12)).lineLimit(1).truncationMode(.head)
                    Spacer()
                    Toggle("Compare with live file", isOn: $againstLive).controlSize(.small)
                    Button("Roll back…") { askRollback(v) }
                        .disabled(v.secret || v.deleted)
                }
                Text("Version \(v.version) · \(Format.bytes(v.size)) · \(v.source)")
                    .font(.caption11).foregroundStyle(Color.textMuted)
                if let d = diff {
                    if d.binary {
                        Text("Binary, secret or not kept: no content diff.").foregroundStyle(Color.textMuted)
                    } else if d.unified.isEmpty {
                        Text("No differences.").foregroundStyle(Color.textMuted)
                    } else {
                        UnifiedDiffView(text: d.unified)
                    }
                } else {
                    Text("First version of this file: comparing with the live file.")
                        .font(.caption11).foregroundStyle(Color.textMuted)
                }
            } else {
                Text("Select a version").foregroundStyle(Color.textMuted)
            }
            Spacer(minLength: 0)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .card()
    }

    /// The version just before `v` of the same file, if listed.
    private func previous(_ v: ConfigVersionRow) -> ConfigVersionRow? {
        (history?.versions ?? []).filter { $0.path == v.path && $0.version < v.version }
            .max { $0.version < $1.version }
    }

    private func askRollback(_ v: ConfigVersionRow) {
        let elevated = configRollbackNeedsApproval(path: v.path)
        pending = PendingAction(
            title: "Roll back \(v.path) to version \(v.version)?",
            message: "The file on \(server.name) is replaced with this version. The rollback is recorded as a new version, so it can be undone the same way.",
            button: "Roll back", destructive: true, elevated: elevated) {
                guard let api = core.api else { return }
                Task {
                    do {
                        try await api.configRollback(serverId: server.id, path: v.path, version: v.version)
                        error = nil
                    } catch {
                        self.error = error.fleetMessage
                    }
                    await load()
                }
            }
    }

    private func loadDiff() async {
        guard let api = core.api, let v = selected else { diff = nil; return }
        let (from, to): (UInt64, UInt64?) =
            if againstLive { (v.version, nil) }
            else if let p = previous(v) { (p.version, v.version) }
            else { (v.version, nil) }
        do {
            diff = try await api.configDiff(serverId: server.id, path: v.path, from: from, to: to)
        } catch {
            diff = nil
            self.error = error.fleetMessage
        }
    }

    private func load() async {
        guard let api = core.api else { return }
        loading = true
        defer { loading = false }
        do {
            history = try await api.configHistory(serverId: server.id, path: nil, sinceMs: nil, limit: 500)
            error = nil
        } catch {
            self.error = error.fleetMessage
        }
        paths = try? await api.configPathsGet(serverId: server.id)
    }
}
