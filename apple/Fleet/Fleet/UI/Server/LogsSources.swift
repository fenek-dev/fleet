import SwiftUI

// Logs tab sources besides journald (design §2.4): allow-listed log files
// (`logfiles.list`, `logfile.tail`) and Caddy/nginx access logs
// (`weblog.query`). Every string is server data: untrusted, display only.

/// `logfile.tail`: the last lines of one file, then live.
@Observable
@MainActor
final class LogTailModel {
    private(set) var lines: [String] = []
    private(set) var status: StreamStatus?
    private(set) var error: String?
    @ObservationIgnored private var handle: StreamHandle?
    static let cap = 5000

    var following: Bool { handle != nil }

    /// Bumped whenever a stream opens or stops; callbacks of an older
    /// stream (already queued on the main actor) are ignored.
    @ObservationIgnored private var generation = 0

    /// `path` is the raw path from `LogFileRow.path`, never a display label.
    func open(api: FleetCore, serverId: String, path: String, lines n: UInt16, follow: Bool) {
        stop()
        lines = []
        let gen = generation
        do {
            handle = try api.tailLogfile(serverId: serverId, path: path, lines: n, follow: follow,
                                         sink: LogTailRelay(model: self, generation: gen))
            error = nil
        } catch { self.error = error.fleetMessage }
    }

    func stop() {
        generation += 1
        handle?.cancel()
        handle = nil
        status = nil
    }

    fileprivate func append(_ new: [String], rotated: Bool, generation gen: Int) {
        guard gen == generation else { return }
        if rotated { lines.append("— file rotated or truncated —") }
        lines.append(contentsOf: new)
        if lines.count > Self.cap { lines.removeFirst(lines.count - Self.cap) }
    }

    fileprivate func setStatus(_ s: StreamStatus, generation gen: Int) {
        guard gen == generation else { return }
        status = s
        if case .ended(let e) = s {
            handle = nil
            if let e { error = e }
        }
    }
}

private final class LogTailRelay: LogLinesSink {
    private let model: LogTailModel
    private let generation: Int
    init(model: LogTailModel, generation: Int) {
        self.model = model
        self.generation = generation
    }
    func onLines(lines: [String], rotated: Bool) {
        Task { @MainActor [model, generation] in
            model.append(lines, rotated: rotated, generation: generation)
        }
    }
    func onStatus(status: StreamStatus) {
        Task { @MainActor [model, generation] in
            model.setStatus(status, generation: generation)
        }
    }
}

extension LogFileRow: Identifiable {
    public var id: String { path }
}

struct LogFilesView: View {
    @Environment(CoreBridge.self) private var core
    let server: ServerRow
    @State private var files: [LogFileRow] = []
    @State private var loaded = false
    @State private var error: String?
    @State private var path: String?
    @State private var live = false
    @State private var model = LogTailModel()

    var body: some View {
        HStack(alignment: .top, spacing: 16) {
            fileList.frame(width: 300)
            VStack(alignment: .leading, spacing: 10) {
                HStack {
                    Text(files.first { $0.path == path }?.label ?? "Choose a file")
                        .font(.mono(12)).foregroundStyle(Color.textSecondary).lineLimit(1)
                        .truncationMode(.middle)
                    Spacer()
                    switch model.status {
                    case .live: StatusPill(label: "Following", tone: .ok)
                    case .reconnecting: StatusPill(label: "Reconnecting", tone: .warn)
                    case .ended(let e?): StatusPill(label: "Ended", tone: .critical).help(e)
                    default: EmptyView()
                    }
                    Toggle("Live", isOn: $live).toggleStyle(.switch)
                        .disabled(path == nil)
                        .accessibilityIdentifier("logs.files.live")
                }
                if let e = model.error {
                    Text(e).font(.base).foregroundStyle(Tone.warn.text)
                }
                tail
            }
        }
        .padding(24)
        .task(id: server.id) { await reload() }
        .onChange(of: path) { open() }
        .onChange(of: live) { open() }
        .onDisappear { model.stop() }
    }

    private var fileList: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("Log files").font(.system(size: 13, weight: .semibold))
                Spacer()
                Button("Refresh") { Task { await reload() } }
                    .controlSize(.small)
                    .accessibilityIdentifier("logs.files.refresh")
            }
            if let error {
                Text(error).font(.secondary).foregroundStyle(Tone.warn.text)
            }
            List(files, selection: $path) { f in
                VStack(alignment: .leading, spacing: 1) {
                    Text(f.label).font(.mono(11)).lineLimit(1).truncationMode(.middle)
                    Text(ByteCountFormatter.string(fromByteCount: Int64(clamping: f.sizeBytes),
                                                   countStyle: .file)
                         + " · " + Date(timeIntervalSince1970: TimeInterval(f.mtimeMs) / 1000)
                            .formatted(.relative(presentation: .named)))
                        .font(.caption11).foregroundStyle(Color.textMuted)
                }
                .tag(Optional(f.path))
                .accessibilityIdentifier("logs.file.\(f.label)")
            }
            .listStyle(.plain)
            .overlay {
                if loaded && files.isEmpty && error == nil {
                    Text("No readable log files").foregroundStyle(Color.textMuted)
                }
            }
            .background(Color.track, in: RoundedRectangle(cornerRadius: 12))
            .overlay(RoundedRectangle(cornerRadius: 12).stroke(Color.border))
        }
    }

    private var tail: some View {
        ScrollViewReader { proxy in
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 1) {
                    ForEach(Array(model.lines.enumerated()), id: \.offset) { i, l in
                        Text(l).font(.mono(11)).foregroundStyle(Color.text)
                            .textSelection(.enabled).id(i)
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(12)
            }
            .background(Color.track, in: RoundedRectangle(cornerRadius: 12))
            .overlay(RoundedRectangle(cornerRadius: 12).stroke(Color.border))
            .accessibilityIdentifier("logs.files.tail")
            .onChange(of: model.lines.count) { _, n in
                if n > 0 { proxy.scrollTo(n - 1, anchor: .bottom) }
            }
        }
    }

    private func reload() async {
        guard let api = core.api else { return }
        do {
            files = try await api.logfilesList(serverId: server.id)
            error = nil
        } catch { self.error = error.fleetMessage }
        loaded = true
    }

    private func open() {
        guard let api = core.api, let path else { model.stop(); return }
        model.open(api: api, serverId: server.id, path: path, lines: 500, follow: live)
    }
}

struct WebLogsView: View {
    @Environment(CoreBridge.self) private var core
    let server: ServerRow
    @State private var hours = 24.0
    /// 0 = any, else the hundreds digit (2 → 200…299).
    @State private var statusClass = 0
    @State private var pathPrefix = ""
    @State private var client = ""
    @State private var result: WebLogRow?
    @State private var loading = false
    @State private var error: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 8) {
                Picker("Since", selection: $hours) {
                    Text("1 h").tag(1.0)
                    Text("24 h").tag(24.0)
                    Text("7 d").tag(168.0)
                }
                .labelsHidden().frame(width: 80)
                Picker("Status", selection: $statusClass) {
                    Text("Any status").tag(0)
                    Text("2xx").tag(2)
                    Text("3xx").tag(3)
                    Text("4xx").tag(4)
                    Text("5xx").tag(5)
                }
                .labelsHidden().frame(width: 120)
                .accessibilityIdentifier("logs.web.status")
                TextField("Path prefix (/api/)", text: $pathPrefix).frame(width: 170)
                TextField("Client IP", text: $client).frame(width: 150)
                Button("Search") { Task { await search() } }
                    .keyboardShortcut(.defaultAction)
                    .accessibilityIdentifier("logs.web.search")
                Spacer()
                if loading { ProgressView().controlSize(.small) }
            }
            if let error {
                Text(error).font(.base).foregroundStyle(Tone.warn.text)
                    .accessibilityIdentifier("logs.web.error")
            }
            if let r = result {
                summary(r)
                entries(r)
            } else if !loading && error == nil {
                Text("Search the Caddy or nginx JSON access logs.")
                    .foregroundStyle(Color.textMuted)
            }
        }
        .padding(24)
        .task(id: server.id) { await search() }
    }

    private func summary(_ r: WebLogRow) -> some View {
        HStack(alignment: .top, spacing: 16) {
            stat("Requests", "\(r.requests)" + (r.truncated ? "+" : ""))
            stat("Scanner hits", "\(r.scannerHits)")
            counts("Status", r.byStatus)
            counts("Top clients", r.topClients)
            counts("Top paths", r.topPaths)
        }
        .accessibilityIdentifier("logs.web.summary")
    }

    private func stat(_ title: String, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(title).font(.caption11).foregroundStyle(Color.textMuted)
            Text(value).font(.system(size: 20, weight: .semibold)).monospacedDigit()
        }
        .frame(minWidth: 90, alignment: .leading)
        .card(padding: 12)
    }

    private func counts(_ title: String, _ rows: [WebLogCount]) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(title).font(.caption11).foregroundStyle(Color.textMuted)
            ForEach(Array(rows.prefix(5).enumerated()), id: \.offset) { _, c in
                HStack(spacing: 8) {
                    Text(c.label).font(.mono(11)).lineLimit(1).truncationMode(.middle)
                    Spacer(minLength: 4)
                    Text("\(c.count)").font(.mono(11)).foregroundStyle(Color.textSecondary)
                }
            }
            if rows.isEmpty { Text("–").foregroundStyle(Color.textMuted) }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .card(padding: 12)
    }

    private func entries(_ r: WebLogRow) -> some View {
        ScrollView {
            LazyVStack(alignment: .leading, spacing: 1) {
                ForEach(Array(r.entries.enumerated()), id: \.offset) { _, e in
                    HStack(alignment: .firstTextBaseline, spacing: 10) {
                        Text(Date(timeIntervalSince1970: TimeInterval(e.timeMs) / 1000)
                            .formatted(.dateTime.month(.abbreviated).day().hour().minute().second()))
                            .foregroundStyle(Color.textMuted)
                        Text(verbatim: String(e.status))
                            .foregroundStyle(tone(e.status).text).frame(width: 34, alignment: .leading)
                        Text(e.method).frame(width: 52, alignment: .leading)
                        Text(e.client).foregroundStyle(Color.accentText)
                            .frame(width: 130, alignment: .leading)
                        Text(e.path).textSelection(.enabled).lineLimit(1).truncationMode(.middle)
                            .help(e.userAgent ?? "")
                        Spacer(minLength: 0)
                    }
                    .font(.mono(11))
                }
                if r.entries.isEmpty {
                    Text("No requests match").foregroundStyle(Color.textMuted)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(12)
        }
        .background(Color.track, in: RoundedRectangle(cornerRadius: 12))
        .overlay(RoundedRectangle(cornerRadius: 12).stroke(Color.border))
        .accessibilityIdentifier("logs.web.entries")
    }

    private func tone(_ status: UInt16) -> Tone {
        switch status {
        case 500...: .critical
        case 400...: .warn
        default: .ok
        }
    }

    private func search() async {
        guard let api = core.api else { return }
        loading = true
        defer { loading = false }
        let since = UInt64(max(0, (Date().timeIntervalSince1970 - hours * 3600) * 1000))
        let min = statusClass == 0 ? nil : UInt16(statusClass * 100)
        let max = statusClass == 0 ? nil : UInt16(statusClass * 100 + 99)
        do {
            result = try await api.weblogQuery(
                serverId: server.id, sinceMs: since, limit: 300, statusMin: min, statusMax: max,
                pathPrefix: pathPrefix.isEmpty ? nil : pathPrefix,
                client: client.isEmpty ? nil : client)
            error = nil
        } catch {
            result = nil
            self.error = error.fleetMessage
        }
    }
}
