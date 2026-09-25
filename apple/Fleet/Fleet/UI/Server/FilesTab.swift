import AppKit
import CoreServices
import SwiftUI
import UniformTypeIdentifiers

/// Transfer progress (core thread → main actor).
@Observable
@MainActor
final class TransferModel {
    struct Item: Identifiable {
        let id = UUID()
        let name: String
        var done: UInt64 = 0
        var total: UInt64 = 0
        var finished = false
        var error: String?
    }

    private(set) var items: [Item] = []

    func begin(_ name: String) -> UUID {
        let item = Item(name: name)
        items.insert(item, at: 0)
        if items.count > 8 { items.removeLast() }
        return item.id
    }

    func update(_ id: UUID, done: UInt64, total: UInt64) {
        guard let i = items.firstIndex(where: { $0.id == id }) else { return }
        items[i].done = done
        items[i].total = total
    }

    func finish(_ id: UUID, error: String?) {
        guard let i = items.firstIndex(where: { $0.id == id }) else { return }
        items[i].finished = true
        items[i].error = error
    }

    nonisolated func listener(_ id: UUID) -> TransferListener {
        TransferRelay { [weak self] d, t in
            Task { @MainActor in self?.update(id, done: d, total: t) }
        }
    }
}

private final class TransferRelay: TransferListener {
    private let handler: @Sendable (UInt64, UInt64) -> Void
    init(_ handler: @escaping @Sendable (UInt64, UInt64) -> Void) { self.handler = handler }
    func onProgress(doneBytes: UInt64, totalBytes: UInt64) { handler(doneBytes, totalBytes) }
}

/// A file opened in the editor, with what's needed to detect a
/// concurrent change on save.
struct EditSession: Identifiable {
    let id = UUID()
    let path: String
    let original: String
    let size: UInt64
    let mtime: UInt32?
}

/// SFTP browser over the server's SSH connection (design §2.3).
struct FilesTab: View {
    @Environment(CoreBridge.self) private var core
    let server: ServerRow
    @State private var dir = "/"
    @State private var entries: [RemoteFileRow] = []
    @State private var selection = Set<String>()
    @State private var loading = false
    @State private var error: String?
    @State private var transfers = TransferModel()
    @State private var editing: EditSession?
    @State private var renaming: RemoteFileRow?
    @State private var newName = ""
    @State private var chmodTarget: RemoteFileRow?
    @State private var modeText = ""
    @State private var newFolder = false
    @State private var confirmDelete: RemoteFileRow?
    @State private var dropTargeted = false

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            toolbar
            if let error {
                Text(error).font(.base).foregroundStyle(Tone.warn.text)
            }
            table
            if !transfers.items.isEmpty { transferList }
        }
        .padding(24)
        .task(id: server.id) { await start() }
        .sheet(item: $editing) { e in
            FileEditor(session: e) { text in try await save(e, text: text) }
        }
        .alert("Rename", isPresented: Binding(get: { renaming != nil }, set: { if !$0 { renaming = nil } })) {
            TextField("Name", text: $newName)
            Button("Rename") { if let r = renaming { rename(r, to: newName) } }
            Button("Cancel", role: .cancel) {}
        }
        .alert("Permissions (octal)", isPresented: Binding(get: { chmodTarget != nil }, set: { if !$0 { chmodTarget = nil } })) {
            TextField("644", text: $modeText)
            Button("Apply") { if let r = chmodTarget { chmod(r, modeText) } }
            Button("Cancel", role: .cancel) {}
        }
        .alert("New folder", isPresented: $newFolder) {
            TextField("Name", text: $newName)
            Button("Create") { mkdir(newName) }
            Button("Cancel", role: .cancel) {}
        }
        .confirmationDialog("Delete \(confirmDelete?.name ?? "")?",
                            isPresented: Binding(get: { confirmDelete != nil }, set: { if !$0 { confirmDelete = nil } })) {
            Button("Delete", role: .destructive) { if let r = confirmDelete { remove(r) } }
        } message: {
            Text("This cannot be undone. Directories must be empty.")
        }
    }

    private var toolbar: some View {
        HStack(spacing: 8) {
            Button { go(parent(of: dir)) } label: { Image(systemName: "chevron.up") }
                .disabled(dir == "/")
                .help("Parent directory")
            breadcrumbs
            Spacer()
            if loading { ProgressView().controlSize(.small) }
            Button { Task { await list() } } label: { Image(systemName: "arrow.clockwise") }
                .help("Refresh")
            Button { newName = ""; newFolder = true } label: { Image(systemName: "folder.badge.plus") }
                .help("New folder")
            Button("Upload…", systemImage: "arrow.up.doc") { pickUpload() }
        }
    }

    private var breadcrumbs: some View {
        let parts = dir.split(separator: "/").map(String.init)
        return HStack(spacing: 2) {
            Button("/") { go("/") }.buttonStyle(.plain)
            ForEach(Array(parts.enumerated()), id: \.offset) { i, p in
                Text("/").foregroundStyle(Color.textMuted)
                Button(p) { go("/" + parts[0...i].joined(separator: "/")) }.buttonStyle(.plain)
            }
        }
        .font(.mono(12)).foregroundStyle(Color.textSecondary)
        .lineLimit(1)
    }

    private var table: some View {
        Table(entries, selection: $selection) {
            TableColumn("Name") { e in
                HStack(spacing: 6) {
                    Image(systemName: icon(e.kind)).foregroundStyle(e.kind == .directory ? Color.accentText : Color.textMuted)
                    Text(e.name).lineLimit(1)
                }
                .onDrag { dragProvider(e) }
            }
            TableColumn("Size") { e in
                Text(e.kind == .directory ? "–" : Format.bytes(e.size)).monospacedDigit()
            }
            .width(80)
            TableColumn("Mode") { e in Text(String(format: "%04o", e.mode)).font(.mono(11)) }.width(56)
            TableColumn("Owner") { e in Text("\(e.owner ?? e.uid.map(String.init) ?? "–"):\(e.group ?? e.gid.map(String.init) ?? "–")").lineLimit(1) }
                .width(110)
            TableColumn("Modified") { e in
                Text(e.mtimeS.map { Date(timeIntervalSince1970: TimeInterval($0)).formatted(date: .abbreviated, time: .shortened) } ?? "–")
            }
            .width(140)
        }
        .contextMenu(forSelectionType: String.self) { paths in
            if let e = entries.first(where: { paths.first == $0.path }) {
                if e.kind == .directory { Button("Open") { go(e.path) } }
                if e.kind == .file {
                    Button("Edit") { edit(e) }
                    Button("Download…") { download(e) }
                }
                Divider()
                Button("Rename…") { newName = e.name; renaming = e }
                Button("Permissions…") { modeText = String(format: "%o", e.mode); chmodTarget = e }
                Divider()
                Button("Delete…", role: .destructive) { confirmDelete = e }
            }
        } primaryAction: { paths in
            guard let e = entries.first(where: { paths.first == $0.path }) else { return }
            switch e.kind {
            case .directory, .symlink: go(e.path)
            case .file: edit(e)
            case .other: break
            }
        }
        .font(.base)
        .scrollContentBackground(.hidden)
        .background(Color.card, in: RoundedRectangle(cornerRadius: 12))
        .overlay(RoundedRectangle(cornerRadius: 12)
            .stroke(dropTargeted ? Color.accent : Color.border, lineWidth: dropTargeted ? 2 : 1))
        .dropDestination(for: URL.self) { urls, _ in
            upload(urls.filter(\.isFileURL))
            return true
        } isTargeted: { dropTargeted = $0 }
    }

    private var transferList: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("Transfers").font(.system(size: 13, weight: .semibold))
            ForEach(transfers.items) { t in
                HStack {
                    Text(t.name).lineLimit(1)
                    Spacer()
                    if let e = t.error {
                        Text(e).foregroundStyle(Tone.critical.text).lineLimit(1)
                    } else if t.finished {
                        Text("Done").foregroundStyle(Tone.ok.text)
                    } else if t.total > 0 {
                        ProgressView(value: Double(t.done), total: Double(t.total)).frame(width: 120)
                        Text("\(Int(Double(t.done) / Double(t.total) * 100))%").monospacedDigit()
                    } else {
                        ProgressView().controlSize(.small)
                    }
                }
                .font(.secondary)
            }
        }
        .card(padding: 12)
    }

    private func icon(_ k: FileKind) -> String {
        switch k {
        case .directory: "folder.fill"
        case .symlink: "arrow.turn.up.right"
        case .file: "doc"
        case .other: "questionmark.square"
        }
    }

    // MARK: actions

    private func parent(of p: String) -> String {
        let parts = p.split(separator: "/").dropLast()
        return parts.isEmpty ? "/" : "/" + parts.joined(separator: "/")
    }

    private func join(_ name: String) -> String { dir == "/" ? "/\(name)" : "\(dir)/\(name)" }

    private func start() async {
        guard let api = core.api else { return }
        if let home = try? await api.fileHome(serverId: server.id) { dir = home }
        await list()
    }

    private func go(_ path: String) {
        dir = path
        selection = []
        Task { await list() }
    }

    private func list() async {
        guard let api = core.api else { return }
        loading = true
        defer { loading = false }
        do {
            entries = try await api.fileList(serverId: server.id, dir: dir)
            error = nil
        } catch {
            self.error = error.fleetMessage
        }
    }

    private func run(_ op: @escaping @MainActor () async throws -> Void) {
        Task {
            do {
                try await op()
                error = nil
            } catch {
                self.error = error.fleetMessage
            }
            await list()
        }
    }

    private func rename(_ e: RemoteFileRow, to name: String) {
        guard let api = core.api, !name.isEmpty, !name.contains("/") else { return }
        let to = join(name)
        run { try await api.fileRename(serverId: server.id, from: e.path, to: to) }
    }

    private func chmod(_ e: RemoteFileRow, _ text: String) {
        guard let api = core.api, let mode = UInt32(text, radix: 8), mode <= 0o7777 else {
            error = "Mode must be octal, e.g. 644."
            return
        }
        run { try await api.fileChmod(serverId: server.id, path: e.path, mode: mode) }
    }

    private func mkdir(_ name: String) {
        guard let api = core.api, !name.isEmpty else { return }
        let d = dir
        run { try await api.fileMkdir(serverId: server.id, parent: d, name: name) }
    }

    private func remove(_ e: RemoteFileRow) {
        guard let api = core.api else { return }
        run { try await api.fileRemove(serverId: server.id, path: e.path) }
    }

    private func edit(_ e: RemoteFileRow) {
        guard let api = core.api else { return }
        Task {
            do {
                let c = try await api.fileRead(serverId: server.id, path: e.path)
                guard let text = String(data: c.data, encoding: .utf8) else {
                    error = "Not a UTF-8 text file."
                    return
                }
                editing = EditSession(path: e.path, original: text, size: c.size, mtime: c.mtimeS)
            } catch {
                self.error = error.fleetMessage
            }
        }
    }

    private func save(_ e: EditSession, text: String) async throws {
        guard let api = core.api else { return }
        try await api.fileWrite(serverId: server.id, path: e.path, data: Data(text.utf8),
                                expectedSize: e.size, expectedMtimeS: e.mtime)
        await list()
    }

    /// Downloads above this size need an explicit confirmation.
    static let largeDownload: UInt64 = 1 << 30

    /// Marks a file that came from a server as downloaded (Gatekeeper
    /// checks it before it can be opened or run).
    nonisolated static func quarantine(_ url: URL, from serverName: String) {
        var u = url
        var values = URLResourceValues()
        values.quarantineProperties = [
            kLSQuarantineAgentNameKey as String: "Fleet",
            kLSQuarantineTypeKey as String: kLSQuarantineTypeOtherDownload as String,
            kLSQuarantineOriginURLKey as String: "sftp://\(displaySafe(serverName, max: 200))",
        ]
        try? u.setResourceValues(values)
    }

    private func download(_ e: RemoteFileRow) {
        guard let api = core.api else { return }
        if e.size > Self.largeDownload {
            let alert = NSAlert()
            alert.messageText = "Download \(Format.bytes(e.size))?"
            alert.informativeText = "\(e.name) is larger than 1 GiB."
            alert.addButton(withTitle: "Download")
            alert.addButton(withTitle: "Cancel")
            guard alert.runModal() == .alertFirstButtonReturn else { return }
        }
        let panel = NSSavePanel()
        panel.nameFieldStringValue = e.name
        guard panel.runModal() == .OK, let url = panel.url else { return }
        let id = transfers.begin(e.name)
        let listener = transfers.listener(id)
        let serverName = server.name
        Task {
            do {
                _ = try await api.fileDownload(serverId: server.id, remote: e.path,
                                               localPath: url.path, listener: listener)
                Self.quarantine(url, from: serverName)
                transfers.finish(id, error: nil)
            } catch {
                transfers.finish(id, error: error.fleetMessage)
            }
        }
    }

    private func pickUpload() {
        let panel = NSOpenPanel()
        panel.allowsMultipleSelection = true
        panel.canChooseDirectories = false
        if panel.runModal() == .OK { upload(panel.urls) }
    }

    private func upload(_ urls: [URL]) {
        guard let api = core.api else { return }
        let d = dir
        for url in urls {
            let id = transfers.begin(url.lastPathComponent)
            let listener = transfers.listener(id)
            Task {
                do {
                    _ = try await api.fileUpload(serverId: server.id, localPath: url.path,
                                                 remoteDir: d, name: url.lastPathComponent,
                                                 listener: listener)
                    transfers.finish(id, error: nil)
                } catch {
                    transfers.finish(id, error: error.fleetMessage)
                }
                await list()
            }
        }
    }

    /// Drag a remote file out: downloaded to a temporary file on drop and
    /// quarantined. Files over 1 GiB can't be dragged (use Download…,
    /// which asks first).
    private func dragProvider(_ e: RemoteFileRow) -> NSItemProvider {
        let provider = NSItemProvider()
        guard e.kind == .file, e.size <= Self.largeDownload, let api = core.api else {
            return provider
        }
        provider.suggestedName = e.name
        let (serverId, path, name, serverName) = (server.id, e.path, e.name, server.name)
        provider.registerFileRepresentation(forTypeIdentifier: UTType.data.identifier,
                                            fileOptions: [], visibility: .all) { done in
            let dirURL = FileManager.default.temporaryDirectory
                .appendingPathComponent(UUID().uuidString, isDirectory: true)
            let url = dirURL.appendingPathComponent(name)
            Task {
                do {
                    try FileManager.default.createDirectory(at: dirURL, withIntermediateDirectories: true)
                    _ = try await api.fileDownload(serverId: serverId, remote: path,
                                                   localPath: url.path, listener: nil)
                    Self.quarantine(url, from: serverName)
                    done(url, false, nil)
                } catch {
                    done(nil, false, error)
                }
            }
            return nil
        }
        return provider
    }
}

/// Plain-text editor; Save shows a line diff to confirm before writing.
private struct FileEditor: View {
    @Environment(\.dismiss) private var dismiss
    let session: EditSession
    let onSave: (String) async throws -> Void
    @State private var text: String
    @State private var reviewing = false
    @State private var saving = false
    @State private var error: String?

    init(session: EditSession, onSave: @escaping (String) async throws -> Void) {
        self.session = session
        self.onSave = onSave
        _text = State(initialValue: session.original)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text(displaySafe(session.path, max: 4096)).font(.mono(12))
                    .foregroundStyle(Color.textSecondary).lineLimit(1)
                Spacer()
                if reviewing {
                    Button("Back to editing") { reviewing = false }
                }
            }
            if reviewing {
                DiffView(old: session.original, new: text)
            } else {
                TextEditor(text: $text)
                    .font(.mono(12))
                    .scrollContentBackground(.hidden)
                    .background(Color.track, in: RoundedRectangle(cornerRadius: 8))
            }
            if let error {
                Text(error).foregroundStyle(Tone.critical.text)
            }
            HStack {
                Button("Cancel") { dismiss() }
                Spacer()
                if reviewing {
                    Button("Save to server") { save() }
                        .buttonStyle(.borderedProminent).tint(.accent)
                        .disabled(saving)
                } else {
                    Button("Review changes…") { reviewing = true }
                        .buttonStyle(.borderedProminent).tint(.accent)
                        .disabled(text == session.original)
                }
            }
        }
        .padding(20)
        .frame(minWidth: 760, minHeight: 540)
    }

    private func save() {
        saving = true
        Task {
            do {
                try await onSave(text)
                dismiss()
            } catch {
                self.error = error.fleetMessage
                saving = false
            }
        }
    }
}

/// Line diff (removed lines red, added green) from `CollectionDifference`.
struct DiffView: View {
    let old: String
    let new: String

    private struct Line: Identifiable {
        let id: Int
        let sign: Character
        let text: String
    }

    private var lines: [Line] {
        let a = old.components(separatedBy: "\n")
        let b = new.components(separatedBy: "\n")
        let diff = b.difference(from: a)
        var removed = Set<Int>()
        var inserted = Set<Int>()
        for c in diff {
            switch c {
            case .remove(let o, _, _): removed.insert(o)
            case .insert(let o, _, _): inserted.insert(o)
            }
        }
        var out: [Line] = []
        var i = 0, j = 0
        while i < a.count || j < b.count {
            if i < a.count, removed.contains(i) {
                out.append(Line(id: out.count, sign: "-", text: a[i])); i += 1
            } else if j < b.count, inserted.contains(j) {
                out.append(Line(id: out.count, sign: "+", text: b[j])); j += 1
            } else {
                if j < b.count { out.append(Line(id: out.count, sign: " ", text: b[j])) }
                i += 1; j += 1
            }
        }
        return out
    }

    var body: some View {
        let ls = lines
        let changed = ls.filter { $0.sign != " " }.count
        VStack(alignment: .leading, spacing: 6) {
            Text("\(changed) changed line\(changed == 1 ? "" : "s")")
                .font(.secondary).foregroundStyle(Color.textMuted)
            ScrollView([.vertical, .horizontal]) {
                LazyVStack(alignment: .leading, spacing: 0) {
                    ForEach(ls) { l in
                        Text("\(String(l.sign)) \(l.text)")
                            .font(.mono(12))
                            .foregroundStyle(l.sign == "-" ? Tone.critical.text : l.sign == "+" ? Tone.ok.text : Color.textSecondary)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .background(l.sign == "-" ? Tone.critical.bg : l.sign == "+" ? Tone.ok.bg : .clear)
                    }
                }
                .textSelection(.enabled)
            }
            .background(Color.track, in: RoundedRectangle(cornerRadius: 8))
        }
    }
}
