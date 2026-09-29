import SwiftUI

extension LogPriority: CaseIterable {
    public static var allCases: [LogPriority] {
        [.emerg, .alert, .crit, .err, .warning, .notice, .info, .debug]
    }

    var label: String {
        switch self {
        case .emerg: "emerg"
        case .alert: "alert"
        case .crit: "crit"
        case .err: "error"
        case .warning: "warning"
        case .notice: "notice"
        case .info: "info"
        case .debug: "debug"
        }
    }
}

/// Journal entries (query + live tail). Messages are untrusted server text.
@Observable
@MainActor
final class JournalModel {
    struct Entry: Identifiable {
        let id: Int
        let row: JournalEntryRow
    }

    private(set) var entries: [Entry] = []
    private(set) var status: StreamStatus?
    private(set) var error: String?
    private(set) var loading = false
    @ObservationIgnored private var next = 0
    @ObservationIgnored private var handle: StreamHandle?
    static let cap = 5000

    func query(api: FleetCore, serverId: String, args: JournalQueryArgs) async {
        stopFollow()
        loading = true
        defer { loading = false }
        do {
            let page = try await api.journalQuery(serverId: serverId, query: args)
            entries = []
            append(page.entries)
            error = nil
        } catch {
            self.error = error.fleetMessage
        }
    }

    func follow(api: FleetCore, serverId: String, args: JournalQueryArgs) {
        stopFollow()
        do {
            handle = try api.followJournal(serverId: serverId, query: args, sink: JournalRelay(model: self))
            error = nil
        } catch {
            self.error = error.fleetMessage
        }
    }

    func stopFollow() {
        handle?.cancel()
        handle = nil
        status = nil
    }

    var following: Bool { handle != nil }

    fileprivate func append(_ rows: [JournalEntryRow]) {
        for r in rows {
            entries.append(Entry(id: next, row: r))
            next += 1
        }
        if entries.count > Self.cap { entries.removeFirst(entries.count - Self.cap) }
    }

    fileprivate func setStatus(_ s: StreamStatus) {
        status = s
        if case .ended = s { handle = nil }
    }
}

private final class JournalRelay: JournalSink {
    private let model: JournalModel
    init(model: JournalModel) { self.model = model }
    func onEntries(page: JournalPageRow) {
        Task { @MainActor [model] in model.append(page.entries) }
    }
    func onStatus(status: StreamStatus) {
        Task { @MainActor [model] in model.setStatus(status) }
    }
}

/// Logs: journald, allow-listed log files and web access logs.
struct LogsTab: View {
    enum Source: String, CaseIterable, Identifiable {
        case journal = "Journal"
        case files = "Log files"
        case web = "Web access"
        var id: String { rawValue }
    }

    let server: ServerRow
    @State private var source: Source = .journal

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Picker("Source", selection: $source) {
                ForEach(Source.allCases) { Text($0.rawValue).tag($0) }
            }
            .pickerStyle(.segmented).labelsHidden()
            .frame(width: 320)
            .padding(.horizontal, 24).padding(.top, 16)
            .accessibilityIdentifier("logs.source")
            switch source {
            case .journal: JournalLogsView(server: server)
            case .files: LogFilesView(server: server)
            case .web: WebLogsView(server: server)
            }
        }
    }
}

private struct JournalLogsView: View {
    @Environment(CoreBridge.self) private var core
    let server: ServerRow
    @State private var model = JournalModel()
    @State private var units = ""
    @State private var grep = ""
    @State private var priority: LogPriority?
    @State private var hours = 1.0

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 8) {
                TextField("Units (nginx.service, …)", text: $units).frame(width: 220)
                TextField("Contains", text: $grep).frame(width: 180)
                Picker("Priority", selection: $priority) {
                    Text("Any priority").tag(LogPriority?.none)
                    ForEach(LogPriority.allCases, id: \.self) { Text($0.label).tag(Optional($0)) }
                }
                .labelsHidden().frame(width: 130)
                Picker("Since", selection: $hours) {
                    Text("15 min").tag(0.25)
                    Text("1 h").tag(1.0)
                    Text("24 h").tag(24.0)
                    Text("7 d").tag(168.0)
                }
                .labelsHidden().frame(width: 90)
                Button("Search") { Task { await search() } }.keyboardShortcut(.defaultAction)
                Spacer()
                statusPill
                Toggle("Live", isOn: Binding(get: { model.following }, set: { live($0) }))
                    .toggleStyle(.switch)
            }
            if let e = model.error {
                Text(e).font(.base).foregroundStyle(Tone.warn.text)
            }
            logList
        }
        .padding(24)
        .task(id: server.id) { await search() }
        .onDisappear { model.stopFollow() }
    }

    @ViewBuilder private var statusPill: some View {
        switch model.status {
        case .live: StatusPill(label: "Following", tone: .ok)
        case .reconnecting: StatusPill(label: "Reconnecting", tone: .warn)
        case .ended(let e?): StatusPill(label: "Ended", tone: .critical).help(e)
        default: EmptyView()
        }
    }

    private var logList: some View {
        ScrollViewReader { proxy in
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 1) {
                    ForEach(model.entries) { e in
                        HStack(alignment: .firstTextBaseline, spacing: 10) {
                            Text(time(e.row.timeUs)).foregroundStyle(Color.textMuted)
                            Text(e.row.unit ?? e.row.identifier ?? "–")
                                .foregroundStyle(Color.accentText).lineLimit(1)
                                .frame(width: 150, alignment: .leading)
                            Text(e.row.message).foregroundStyle(color(e.row.priority))
                                .textSelection(.enabled)
                        }
                        .font(.mono(11))
                        .id(e.id)
                    }
                }
                .padding(12)
            }
            .background(Color.track, in: RoundedRectangle(cornerRadius: 12))
            .overlay(RoundedRectangle(cornerRadius: 12).stroke(Color.border))
            .overlay {
                if model.entries.isEmpty && !model.loading {
                    Text("No entries").foregroundStyle(Color.textMuted)
                }
            }
            .onChange(of: model.entries.last?.id) { _, last in
                if model.following, let last { proxy.scrollTo(last, anchor: .bottom) }
            }
        }
    }

    private func time(_ us: UInt64) -> String {
        Date(timeIntervalSince1970: TimeInterval(us) / 1_000_000)
            .formatted(.dateTime.month(.abbreviated).day().hour().minute().second())
    }

    private func color(_ p: UInt8) -> Color {
        switch p {
        case 0...3: Tone.critical.text
        case 4: Tone.warn.text
        default: Color.text
        }
    }

    private func args(limit: UInt32, since: Bool) -> JournalQueryArgs {
        let unitList = units.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
        let sinceMs = since ? UInt64((Date().timeIntervalSince1970 - hours * 3600) * 1000) : nil
        return JournalQueryArgs(units: unitList, priority: priority, sinceMs: sinceMs, untilMs: nil,
                                grep: grep.isEmpty ? nil : grep, afterCursor: nil, limit: limit)
    }

    private func search() async {
        guard let api = core.api else { return }
        await model.query(api: api, serverId: server.id, args: args(limit: 1000, since: true))
    }

    private func live(_ on: Bool) {
        guard let api = core.api else { return }
        if on {
            model.follow(api: api, serverId: server.id, args: args(limit: 500, since: false))
        } else {
            model.stopFollow()
        }
    }
}
