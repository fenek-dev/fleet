import AppKit
import SwiftTerm
import SwiftUI

/// SwiftTerm view that never answers the server with what it knows about
/// the Mac. Everything the *emulator* sends back (as opposed to typed
/// keys, which go through `send(data:)`) passes `send(source: Terminal…)`;
/// answer-backs that can leak state or be abused to inject input are
/// dropped there:
///
/// - window/icon title reports (CSI 20t / 21t → `OSC L` / `OSC l`),
/// - DECRQSS / XTGETTCAP replies (`DCS 0|1 $ r`, `DCS 0|1 + r`),
/// - OSC 52 clipboard replies (the delegate never reads the clipboard
///   either).
///
/// Device-status and cursor-position reports stay: shells and editors
/// need them, and they carry nothing the server doesn't know.
final class FleetTerminalView: TerminalView {
    static func isBlockedReply(_ d: ArraySlice<UInt8>) -> Bool {
        let b = Array(d.prefix(5))
        guard b.count >= 3, b[0] == 0x1b else { return false }
        switch b[1] {
        case UInt8(ascii: "]"):
            // OSC l / OSC L (title reports), OSC 52 (clipboard).
            if b[2] == UInt8(ascii: "l") || b[2] == UInt8(ascii: "L") { return true }
            return b.count >= 4 && b[2] == UInt8(ascii: "5") && b[3] == UInt8(ascii: "2")
        case UInt8(ascii: "P"):
            // DCS replies: DECRQSS (`0$r`/`1$r`), XTGETTCAP (`0+r`/`1+r`).
            guard b.count >= 5 else { return false }
            return (b[2] == UInt8(ascii: "0") || b[2] == UInt8(ascii: "1"))
                && (b[3] == UInt8(ascii: "$") || b[3] == UInt8(ascii: "+"))
                && b[4] == UInt8(ascii: "r")
        default:
            return false
        }
    }

    override func send(source: Terminal, data: ArraySlice<UInt8>) {
        if Self.isBlockedReply(data) { return }
        super.send(source: source, data: data)
    }
}

/// Server text shown in the tab bar: controls and bidi overrides removed.
func displaySafe(_ s: String, max: Int) -> String {
    let bidi: ClosedRange<UInt32> = 0x202A...0x202E
    let isolates: ClosedRange<UInt32> = 0x2066...0x2069
    let kept = s.unicodeScalars.filter {
        !(CharacterSet.controlCharacters.contains($0) || bidi.contains($0.value)
          || isolates.contains($0.value))
    }
    return String(String.UnicodeScalarView(kept).prefix(max))
}

/// Local session recording (asciicast v2). Output only: typed input is
/// never recorded (passwords). The file lives in the app data directory
/// (0600, dir 0700) and is never uploaded or synced. Server output is
/// untrusted data and is written verbatim inside JSON strings.
final class TerminalRecorder {
    let url: URL
    private var handle: FileHandle?
    private let start = Date()

    init?(label: String, cols: Int, rows: Int) {
        do {
            let dir = try AppPaths.dataDir().appendingPathComponent("recordings", isDirectory: true)
            try FileManager.default.createDirectory(
                at: dir, withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o700])
            let f = DateFormatter()
            f.locale = Locale(identifier: "en_US_POSIX")
            f.dateFormat = "yyyyMMdd-HHmmss"
            let safe = String(label.unicodeScalars.map {
                CharacterSet.alphanumerics.contains($0) || $0 == "-" ? Character($0) : "_"
            }.prefix(60))
            let u = dir.appendingPathComponent("\(safe)-\(f.string(from: start)).cast")
            guard FileManager.default.createFile(
                atPath: u.path, contents: nil, attributes: [.posixPermissions: 0o600])
            else { return nil }
            handle = try FileHandle(forWritingTo: u)
            url = u
            let header: [String: Any] = [
                "version": 2, "width": cols, "height": rows,
                "timestamp": Int(start.timeIntervalSince1970),
            ]
            writeLine(header)
        } catch {
            return nil
        }
    }

    func output(_ data: Data) {
        let s = String(decoding: data, as: UTF8.self)
        writeLine([Date().timeIntervalSince(start), "o", s])
    }

    func stop() {
        try? handle?.close()
        handle = nil
    }

    private func writeLine(_ obj: Any) {
        guard let handle,
              let d = try? JSONSerialization.data(withJSONObject: obj, options: [.withoutEscapingSlashes])
        else { return }
        try? handle.write(contentsOf: d + Data([0x0a]))
    }

    deinit { stop() }
}

/// One terminal: a SwiftTerm view bound to a Rust PTY channel on the
/// server's SSH connection (design §2.3). Output arrives on the core
/// thread and is fed to the view on the main actor; keystrokes and
/// resizes go straight to the `TerminalSession`.
@MainActor
final class TerminalController: NSObject, Identifiable {
    let id = UUID()
    /// tmux session `fleet-<slot>` on the server.
    let slot: UInt32
    let serverId: String
    let serverName: String
    let user: String
    let view: TerminalView
    private(set) var title: String
    private(set) var session: TerminalSession?
    private(set) var closed = false
    private(set) var cols = 0
    private(set) var rows = 0
    private(set) var recorder: TerminalRecorder?
    var onChange: (() -> Void)?
    /// Typed input (not emulator answer-backs) for broadcast fan-out.
    var onInput: ((TerminalController, Data) -> Void)?

    /// "web-04 · ops"
    var label: String { "\(displaySafe(serverName, max: 40)) · \(displaySafe(user, max: 32))" }
    var tmuxName: String { "fleet-\(slot)" }

    init(slot: UInt32, serverId: String, serverName: String, user: String) {
        self.slot = slot
        self.serverId = serverId
        self.serverName = serverName
        self.user = user
        title = "fleet-\(slot)"
        view = FleetTerminalView(frame: NSRect(x: 0, y: 0, width: 900, height: 520))
        super.init()
        view.nativeBackgroundColor = NSColor(Self.bg)
        view.nativeForegroundColor = NSColor(Color(hex: 0xc9cbd0))
        view.font = NSFont.monospacedSystemFont(ofSize: 13, weight: .regular)
        view.terminalDelegate = self
    }

    static let bg = Color(hex: 0x0d0e10)

    func connect(api: FleetCore, serverId: String, tmux: Bool) async {
        let t = view.getTerminal()
        let gen = UUID()
        generation = gen
        do {
            let s = try await api.openTerminal(
                serverId: serverId, slot: slot, tmux: tmux,
                cols: UInt32(max(t.cols, 1)), rows: UInt32(max(t.rows, 1)),
                sink: TerminalRelay(controller: self, generation: gen))
            // Closed or reconnected while opening: this session is stale.
            guard generation == gen else {
                s.close()
                return
            }
            session = s
            closed = false
        } catch {
            guard generation == gen else { return }
            feedNotice("\r\n[\(error.fleetMessage)]\r\n")
            closed = true
        }
        onChange?()
    }

    func close() {
        generation = UUID()
        session?.close()
        session = nil
        stopRecording()
    }

    var isRecording: Bool { recorder != nil }

    func startRecording() {
        guard recorder == nil else { return }
        let t = view.getTerminal()
        recorder = TerminalRecorder(label: "\(serverName)-\(tmuxName)", cols: t.cols, rows: t.rows)
        onChange?()
    }

    func stopRecording() {
        recorder?.stop()
        recorder = nil
        onChange?()
    }

    /// Bytes from the operator's keyboard forwarded by a broadcast.
    func write(_ data: Data) { session?.write(data: data) }

    /// The session callbacks are accepted from; replaced on every connect
    /// and close.
    private var generation = UUID()

    fileprivate func received(_ data: Data, generation gen: UUID) {
        guard gen == generation else { return }
        recorder?.output(data)
        view.feed(byteArray: ArraySlice([UInt8](data)))
    }

    fileprivate func ended(status: UInt32?, error: String?, generation gen: UUID) {
        guard gen == generation else { return }
        session = nil
        closed = true
        stopRecording()
        if let error {
            feedNotice("\r\n[connection closed: \(error)]\r\n")
        } else {
            feedNotice("\r\n[session ended\(status.map { " (exit \($0))" } ?? "")]\r\n")
        }
        onChange?()
    }

    private func feedNotice(_ s: String) {
        view.feed(text: s)
    }
}

extension TerminalController: @preconcurrency TerminalViewDelegate {
    func sizeChanged(source: TerminalView, newCols: Int, newRows: Int) {
        cols = newCols
        rows = newRows
        session?.resize(cols: UInt32(max(newCols, 1)), rows: UInt32(max(newRows, 1)))
        onChange?()
    }

    func setTerminalTitle(source: TerminalView, title: String) {
        // Untrusted text from the server: shown as a tab label only.
        self.title = displaySafe(title, max: 40)
        onChange?()
    }

    func hostCurrentDirectoryUpdate(source: TerminalView, directory: String?) {}

    func send(source: TerminalView, data: ArraySlice<UInt8>) {
        let d = Data(data)
        session?.write(data: d)
        onInput?(self, d)
    }

    func scrolled(source: TerminalView, position: Double) {}

    func requestOpenLink(source: TerminalView, link: String, params: [String: String]) {
        // Links come from the server (OSC 8 text can show anything): open
        // only web URLs, after a click, and only once the operator has seen
        // the real host.
        guard let url = URL(string: link),
              ["http", "https"].contains(url.scheme?.lowercased() ?? ""),
              let host = url.host(percentEncoded: false), !host.isEmpty
        else { return }
        let alert = NSAlert()
        alert.messageText = "Open link to \(displaySafe(host, max: 253))?"
        alert.informativeText = "The server's terminal asked to open:\n\(displaySafe(url.absoluteString, max: 500))"
        alert.addButton(withTitle: "Open")
        alert.addButton(withTitle: "Cancel")
        if alert.runModal() == .alertFirstButtonReturn {
            NSWorkspace.shared.open(url)
        }
    }

    func bell(source: TerminalView) {}

    /// OSC 52 writes are ignored: a server must not be able to put text on
    /// the Mac's clipboard (paste-jacking into another terminal).
    func clipboardCopy(source: TerminalView, content: Data) {}

    /// OSC 52 reads: never.
    func clipboardRead(source: TerminalView) -> Data? { nil }

    func iTermContent(source: TerminalView, content: ArraySlice<UInt8>) {}

    func rangeChanged(source: TerminalView, startY: Int, endY: Int) {}
}

/// Core-thread output → main actor. Weak, so the core holding the sink
/// doesn't keep the controller alive; tagged with the session it was made
/// for, so callbacks from an earlier session are dropped.
private final class TerminalRelay: TerminalSink, @unchecked Sendable {
    private weak var controller: TerminalController?
    private let generation: UUID
    init(controller: TerminalController, generation: UUID) {
        self.controller = controller
        self.generation = generation
    }

    func onOutput(data: Data) {
        Task { @MainActor [weak controller, generation] in
            controller?.received(data, generation: generation)
        }
    }

    func onClosed(exitStatus: UInt32?, error: String?) {
        Task { @MainActor [weak controller, generation] in
            controller?.ended(status: exitStatus, error: error, generation: generation)
        }
    }
}

private struct TerminalHost: NSViewRepresentable {
    let controller: TerminalController
    func makeNSView(context: Context) -> TerminalView { controller.view }
    func updateNSView(_ nsView: TerminalView, context: Context) {}
}

/// Terminals of all servers, kept while the app runs so switching tabs or
/// servers doesn't drop sessions. The tab bar mixes servers.
@Observable
@MainActor
final class TerminalStore {
    private(set) var all: [TerminalController] = []
    /// Selected tab per server-detail screen.
    var selected: [String: UUID] = [:]
    /// Bumped when a controller's title/state changes.
    private(set) var revision = 0
    /// Keystrokes typed in one session go to every live session. Off by
    /// default; each enable is confirmed by the operator and it drops back
    /// off when a session is added or fewer than two remain.
    private(set) var broadcasting = false

    func open(server: ServerRow, api: FleetCore, tmux: Bool) {
        let used = Set(all.filter { $0.serverId == server.id }.map(\.slot))
        let slot = (1...UInt32(64)).first { !used.contains($0) } ?? UInt32(used.count + 1)
        let c = TerminalController(
            slot: slot, serverId: server.id, serverName: server.name, user: server.user)
        c.onChange = { [weak self] in self?.revision += 1 }
        c.onInput = { [weak self] src, data in self?.fanOut(from: src, data) }
        all.append(c)
        selected[server.id] = c.id
        // A session the operator did not confirm must not receive input.
        broadcasting = false
        Task { await c.connect(api: api, serverId: server.id, tmux: tmux) }
    }

    func reconnect(_ c: TerminalController, api: FleetCore, tmux: Bool) {
        c.close()
        Task { await c.connect(api: api, serverId: c.serverId, tmux: tmux) }
    }

    func close(_ c: TerminalController) {
        c.close()
        all.removeAll { $0.id == c.id }
        for (k, v) in selected where v == c.id {
            selected[k] = all.last { $0.serverId == k }?.id
        }
        if liveSessions.count < 2 { broadcasting = false }
        revision += 1
    }

    var liveSessions: [TerminalController] { all.filter { $0.session != nil } }

    /// Turns broadcast on after an explicit confirmation naming every
    /// receiving session; turning it off needs none.
    func setBroadcast(_ on: Bool) {
        guard on else { broadcasting = false; return }
        let live = liveSessions
        guard live.count >= 2 else { return }
        let alert = NSAlert()
        alert.alertStyle = .warning
        alert.messageText = "Broadcast keystrokes to \(live.count) sessions?"
        alert.informativeText = "Everything you type in one terminal, including pasted text, is sent to all of these sessions until you turn broadcast off:\n\n"
            + live.map { "• \($0.label) (\($0.tmuxName))" }.joined(separator: "\n")
        alert.addButton(withTitle: "Broadcast")
        alert.addButton(withTitle: "Cancel")
        alert.buttons.first?.setAccessibilityIdentifier("terminal.broadcastConfirm")
        alert.buttons.last?.setAccessibilityIdentifier("terminal.broadcastCancel")
        broadcasting = alert.runModal() == .alertFirstButtonReturn
    }

    private func fanOut(from src: TerminalController, _ data: Data) {
        guard broadcasting else { return }
        for c in all where c.id != src.id { c.write(data) }
    }
}

struct TerminalTab: View {
    @Environment(CoreBridge.self) private var core
    @Environment(TerminalStore.self) private var store
    let server: ServerRow
    @AppStorage("terminal.tmux", store: AppPaths.defaults) private var tmux = true

    private var tabs: [TerminalController] { store.all }
    private var current: TerminalController? {
        let sel = store.selected[server.id]
        return tabs.first { $0.id == sel }
            ?? tabs.last { $0.serverId == server.id }
    }

    var body: some View {
        let _ = store.revision
        VStack(spacing: 0) {
            tabBar
            if let c = current {
                TerminalHost(controller: c)
                    .id(c.id)
                    .padding(8)
                    .background(TerminalController.bg)
            } else {
                ContentUnavailableView {
                    Label("No terminal", systemImage: "terminal")
                } description: {
                    Text(server.state == .ready ? "Open a session backed by tmux on the server."
                                               : "Connect to the server first.")
                } actions: {
                    Button("New terminal") { newTab() }.disabled(server.state != .ready)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
                .background(TerminalController.bg)
            }
            footer
        }
        .clipShape(RoundedRectangle(cornerRadius: 12))
        .overlay(RoundedRectangle(cornerRadius: 12).stroke(Color.border))
        .padding(24)
    }

    private var tabBar: some View {
        HStack(spacing: 4) {
            ForEach(tabs) { c in
                HStack(spacing: 6) {
                    Circle().fill(c.closed ? Tone.critical.dot : Tone.ok.dot).frame(width: 6, height: 6)
                    Text(c.label).lineLimit(1)
                    if c.isRecording {
                        Circle().fill(Tone.critical.dot).frame(width: 6, height: 6)
                            .help("Recording locally")
                    }
                    Button { store.close(c) } label: {
                        Image(systemName: "xmark").font(.system(size: 9, weight: .semibold))
                    }
                    .buttonStyle(.plain).foregroundStyle(Color.textMuted)
                    .accessibilityIdentifier("terminal.tabClose")
                }
                .font(.secondary)
                .foregroundStyle(current?.id == c.id ? Color.text : Color.textSecondary)
                .padding(.horizontal, 10).frame(height: 28)
                .background(current?.id == c.id ? Color.selected : .clear, in: RoundedRectangle(cornerRadius: 8))
                .overlay {
                    if store.broadcasting {
                        RoundedRectangle(cornerRadius: 8).stroke(Tone.warn.dot, lineWidth: 1)
                    }
                }
                .contentShape(Rectangle())
                .onTapGesture { store.selected[server.id] = c.id }
                .accessibilityElement(children: .contain)
                .accessibilityIdentifier("terminal.tab")
            }
            Button { newTab() } label: { Image(systemName: "plus") }
                .buttonStyle(.plain).foregroundStyle(Color.textSecondary)
                .disabled(server.state != .ready)
                .help("New terminal on \(server.name) (tmux session fleet-N)")
                .accessibilityIdentifier("terminal.new")
            Spacer()
            Toggle("Broadcast input", isOn: Binding(
                get: { store.broadcasting },
                set: { store.setBroadcast($0) }))
                .toggleStyle(.switch).controlSize(.mini)
                .disabled(!store.broadcasting && store.liveSessions.count < 2)
                .help("Send what you type to every open session (needs 2 or more; asks first)")
                .accessibilityIdentifier("terminal.broadcast")
            Toggle("Record", isOn: Binding(
                get: { current?.isRecording ?? false },
                set: { on in
                    guard let c = current else { return }
                    if on { c.startRecording() } else { c.stopRecording() }
                }))
                .toggleStyle(.switch).controlSize(.mini)
                .disabled(current?.session == nil && !(current?.isRecording ?? false))
                .help("Record this session's output to a local file (never uploaded)")
                .accessibilityIdentifier("terminal.record")
            Toggle("tmux", isOn: $tmux).toggleStyle(.switch).controlSize(.mini)
                .help("Back new terminals with tmux so they survive disconnects")
                .accessibilityIdentifier("terminal.tmux")
            if let c = current, c.closed, let api = core.api {
                Button("Reconnect") { store.reconnect(c, api: api, tmux: tmux) }
                    .controlSize(.small)
                    .accessibilityIdentifier("terminal.reconnect")
            }
        }
        .font(.secondary)
        .padding(.horizontal, 8).frame(height: 40)
        .background(Color(hex: 0x16171a))
    }

    private var footer: some View {
        HStack(spacing: 12) {
            if let c = current {
                Text(tmux ? "tmux · \(c.tmuxName) · survives disconnects" : "login shell")
            } else {
                Text(tmux ? "tmux · survives disconnects" : "login shell")
            }
            if let c = current, let r = c.recorder {
                Text("Recording → \(r.url.lastPathComponent)")
                    .foregroundStyle(Tone.critical.text)
                    .lineLimit(1).truncationMode(.middle)
                    .accessibilityIdentifier("terminal.recordingFile")
                Button("Reveal") { NSWorkspace.shared.activateFileViewerSelecting([r.url]) }
                    .buttonStyle(.plain).foregroundStyle(Color.accentText)
                    .accessibilityIdentifier("terminal.recordReveal")
            }
            if store.broadcasting {
                Text("Broadcasting to \(store.liveSessions.count) sessions")
                    .foregroundStyle(Tone.warn.text)
                    .accessibilityIdentifier("terminal.broadcastBanner")
            }
            Spacer()
            Text("Secure Enclave key · ecdsa-sha2-nistp256")
            if let c = current, c.cols > 0 {
                Text("\(c.cols) × \(c.rows)").accessibilityIdentifier("terminal.size")
            }
        }
        .font(.caption11).foregroundStyle(Color.textMuted)
        .padding(.horizontal, 12).frame(height: 26)
        .background(Color(hex: 0x16171a))
    }

    private func newTab() {
        guard let api = core.api else { return }
        store.open(server: server, api: api, tmux: tmux)
    }
}
