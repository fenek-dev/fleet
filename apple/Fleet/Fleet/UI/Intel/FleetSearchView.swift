import SwiftUI

extension Notification.Name {
    /// ⌘F: open fleet search (posted by the app menu).
    static let fleetSearch = Notification.Name("dev.fleet.fleetSearch")
}

extension SearchKindRow {
    static let ordered: [SearchKindRow] = [.package, .port, .process, .user, .file, .journal]

    var label: String {
        switch self {
        case .package: "Packages"
        case .port: "Ports"
        case .process: "Processes"
        case .user: "Users"
        case .file: "Files"
        case .journal: "Logs"
        }
    }

    var symbol: String {
        switch self {
        case .package: "shippingbox"
        case .port: "network"
        case .process: "cpu"
        case .user: "person"
        case .file: "doc"
        case .journal: "text.alignleft"
        }
    }
}

/// Fleet search (design §2.7): one query across every connected server.
struct FleetSearchView: View {
    @Environment(CoreBridge.self) private var core
    @Binding var selection: NavItem?
    @State private var term = ""
    @State private var kinds = Set(SearchKindRow.ordered)
    @State private var caseSensitive = false
    @State private var result: FleetSearchRow?
    @State private var loading = false
    @State private var error: String?
    @FocusState private var focused: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    if let error {
                        Text(error).font(.base).foregroundStyle(Tone.warn.text)
                    }
                    if let result {
                        results(result)
                    } else if !loading && error == nil {
                        ContentUnavailableView("Search the fleet", systemImage: "magnifyingglass",
                                               description: Text("Find packages, ports, processes, users, files and logs across every connected server."))
                            .frame(maxWidth: .infinity, minHeight: 280)
                    }
                }
                .padding(24)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
        .background(Color.window)
        .onAppear { focused = true }
        .onReceive(NotificationCenter.default.publisher(for: .fleetSearch)) { _ in focused = true }
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 10) {
                Image(systemName: "magnifyingglass").foregroundStyle(Color.textMuted)
                TextField("Search packages, ports, processes, users, files and logs across the fleet",
                          text: $term)
                    .textFieldStyle(.plain)
                    .font(.system(size: 15))
                    .focused($focused)
                    .onSubmit { Task { await search() } }
                if loading { ProgressView().controlSize(.small) }
                Button("Search") { Task { await search() } }
                    .buttonStyle(.fleetPrimary)
                    .disabled(loading || term.trimmingCharacters(in: .whitespaces).isEmpty || kinds.isEmpty)
            }
            HStack(spacing: 6) {
                ForEach(SearchKindRow.ordered, id: \.self) { k in
                    Toggle(isOn: Binding(
                        get: { kinds.contains(k) },
                        set: { on in if on { kinds.insert(k) } else { kinds.remove(k) } }
                    )) {
                        Label(k.label, systemImage: k.symbol)
                    }
                    .toggleStyle(.button)
                    .controlSize(.small)
                }
                Spacer()
                Toggle("Match case", isOn: $caseSensitive).toggleStyle(.checkbox)
            }
            .font(.secondary)
        }
        .padding(.horizontal, 24)
        .padding(.vertical, 14)
        .background(Color.header)
    }

    @ViewBuilder private func results(_ r: FleetSearchRow) -> some View {
        Text(summary(r)).font(.secondary).foregroundStyle(Color.textMuted)
        ForEach(SearchKindRow.ordered, id: \.self) { k in
            let hits = r.hits.filter { $0.kind == k }
            if !hits.isEmpty {
                group(k, hits: hits, truncated: r.truncated.filter { $0.kind == k })
            }
        }
        if r.hits.isEmpty {
            ContentUnavailableView.search(text: term)
        }
        if !r.failures.isEmpty {
            VStack(alignment: .leading, spacing: 4) {
                Text("Not searched").font(.system(size: 13, weight: .semibold))
                ForEach(Indexed.wrap(r.failures)) { f in
                    Text("\(f.value.serverName) · \(f.value.kind.label): \(f.value.message)")
                        .font(.secondary).foregroundStyle(Tone.warn.text)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .card()
        }
    }

    private func group(_ k: SearchKindRow, hits: [FleetSearchHitRow],
                       truncated: [FleetSearchIssueRow]) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Label("\(k.label) · \(hits.count)", systemImage: k.symbol)
                    .font(.system(size: 13, weight: .semibold))
                Spacer()
                if !truncated.isEmpty {
                    Text("more on \(truncated.map(\.serverName).joined(separator: ", "))")
                        .font(.caption11).foregroundStyle(Color.textMuted).lineLimit(1)
                }
            }
            ForEach(Indexed.wrap(Array(hits.prefix(500)))) { h in
                Button { selection = .server(h.value.serverId) } label: {
                    HStack(spacing: 12) {
                        Text(h.value.primary).font(.mono(12)).lineLimit(1)
                            .frame(maxWidth: 420, alignment: .leading)
                        Text(h.value.detail).foregroundStyle(Color.textSecondary).lineLimit(1)
                        Spacer()
                        Text(h.value.serverName).foregroundStyle(Color.accentText)
                    }
                    .font(.secondary)
                    .padding(.vertical, 2)
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .help("Open \(h.value.serverName)")
            }
            if hits.count > 500 {
                Text("\(hits.count - 500) more not shown.").font(.caption11).foregroundStyle(Color.textMuted)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .card()
    }

    private func summary(_ r: FleetSearchRow) -> String {
        var s = "\(r.hits.count) results on \(r.serversSearched) server\(r.serversSearched == 1 ? "" : "s")"
        if r.serversSkipped > 0 { s += " · \(r.serversSkipped) not connected" }
        if r.dropped > 0 { s += " · \(r.dropped) over the limit" }
        return s
    }

    private func search() async {
        guard let api = core.api else { return }
        let t = term.trimmingCharacters(in: .whitespaces)
        guard !t.isEmpty else { return }
        loading = true
        defer { loading = false }
        error = nil
        do {
            result = try await api.fleetSearch(args: FleetSearchArgs(
                term: t, caseSensitive: caseSensitive,
                kinds: SearchKindRow.ordered.filter { kinds.contains($0) },
                limit: 200, sinceMs: nil))
        } catch {
            self.error = error.fleetMessage
        }
    }
}
