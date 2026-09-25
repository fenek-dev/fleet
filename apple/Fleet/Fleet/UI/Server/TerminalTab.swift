import AppKit
import SwiftTerm
import SwiftUI

/// One terminal: a SwiftTerm view bound to a Rust PTY channel on the
/// server's SSH connection (design §2.3). Output arrives on the core
/// thread and is fed to the view on the main actor; keystrokes and
/// resizes go straight to the `TerminalSession`.
@MainActor
final class TerminalController: NSObject, Identifiable {
    let id = UUID()
    /// tmux session `fleet-<slot>` on the server.
    let slot: UInt32
    let view: TerminalView
    private(set) var title: String
    private(set) var session: TerminalSession?
    private(set) var closed = false
    var onChange: (() -> Void)?

    init(slot: UInt32) {
        self.slot = slot
        title = "fleet-\(slot)"
        view = TerminalView(frame: NSRect(x: 0, y: 0, width: 900, height: 520))
        super.init()
        view.nativeBackgroundColor = NSColor(Self.bg)
        view.nativeForegroundColor = NSColor(Color(hex: 0xc9cbd0))
        view.font = NSFont.monospacedSystemFont(ofSize: 13, weight: .regular)
        view.terminalDelegate = self
    }

    static let bg = Color(hex: 0x0d0e10)

    func connect(api: FleetCore, serverId: String, tmux: Bool) async {
        let t = view.getTerminal()
        do {
            session = try await api.openTerminal(
                serverId: serverId, slot: slot, tmux: tmux,
                cols: UInt32(max(t.cols, 1)), rows: UInt32(max(t.rows, 1)),
                sink: TerminalRelay(controller: self))
            closed = false
        } catch {
            feedNotice("\r\n[\(error.fleetMessage)]\r\n")
            closed = true
        }
        onChange?()
    }

    func close() {
        session?.close()
        session = nil
    }

    fileprivate func received(_ data: Data) {
        view.feed(byteArray: ArraySlice([UInt8](data)))
    }

    fileprivate func ended(status: UInt32?, error: String?) {
        session = nil
        closed = true
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
        session?.resize(cols: UInt32(max(newCols, 1)), rows: UInt32(max(newRows, 1)))
    }

    func setTerminalTitle(source: TerminalView, title: String) {
        // Untrusted text from the server: shown as a tab label only.
        self.title = String(title.prefix(40))
        onChange?()
    }

    func hostCurrentDirectoryUpdate(source: TerminalView, directory: String?) {}

    func send(source: TerminalView, data: ArraySlice<UInt8>) {
        session?.write(data: Data(data))
    }

    func scrolled(source: TerminalView, position: Double) {}

    func requestOpenLink(source: TerminalView, link: String, params: [String: String]) {
        // Links come from the server: open only web URLs, after a click.
        if let url = URL(string: link), ["http", "https"].contains(url.scheme?.lowercased() ?? "") {
            NSWorkspace.shared.open(url)
        }
    }

    func bell(source: TerminalView) {}

    func clipboardCopy(source: TerminalView, content: Data) {
        if let s = String(data: content, encoding: .utf8) {
            NSPasteboard.general.clearContents()
            NSPasteboard.general.setString(s, forType: .string)
        }
    }

    func iTermContent(source: TerminalView, content: ArraySlice<UInt8>) {}

    func rangeChanged(source: TerminalView, startY: Int, endY: Int) {}
}

/// Core-thread output → main actor.
private final class TerminalRelay: TerminalSink {
    private let controller: TerminalController
    init(controller: TerminalController) { self.controller = controller }

    func onOutput(data: Data) {
        Task { @MainActor [controller] in controller.received(data) }
    }

    func onClosed(exitStatus: UInt32?, error: String?) {
        Task { @MainActor [controller] in controller.ended(status: exitStatus, error: error) }
    }
}

private struct TerminalHost: NSViewRepresentable {
    let controller: TerminalController
    func makeNSView(context: Context) -> TerminalView { controller.view }
    func updateNSView(_ nsView: TerminalView, context: Context) {}
}

/// Terminals per server, kept while the app runs so switching tabs or
/// servers doesn't drop sessions.
@Observable
@MainActor
final class TerminalStore {
    private(set) var tabs: [String: [TerminalController]] = [:]
    var selected: [String: UUID] = [:]
    /// Bumped when a controller's title/state changes.
    private(set) var revision = 0

    func open(serverId: String, api: FleetCore, tmux: Bool) {
        let used = Set((tabs[serverId] ?? []).map(\.slot))
        let slot = (1...UInt32(64)).first { !used.contains($0) } ?? UInt32(used.count + 1)
        let c = TerminalController(slot: slot)
        c.onChange = { [weak self] in self?.revision += 1 }
        tabs[serverId, default: []].append(c)
        selected[serverId] = c.id
        Task { await c.connect(api: api, serverId: serverId, tmux: tmux) }
    }

    func reconnect(_ c: TerminalController, serverId: String, api: FleetCore, tmux: Bool) {
        c.close()
        Task { await c.connect(api: api, serverId: serverId, tmux: tmux) }
    }

    func close(_ c: TerminalController, serverId: String) {
        c.close()
        tabs[serverId]?.removeAll { $0.id == c.id }
        if selected[serverId] == c.id { selected[serverId] = tabs[serverId]?.last?.id }
    }
}

struct TerminalTab: View {
    @Environment(CoreBridge.self) private var core
    @Environment(TerminalStore.self) private var store
    let server: ServerRow
    @AppStorage("terminal.tmux") private var tmux = true

    private var tabs: [TerminalController] { store.tabs[server.id] ?? [] }
    private var current: TerminalController? {
        let sel = store.selected[server.id]
        return tabs.first { $0.id == sel } ?? tabs.last
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
                    Text("\(server.name) · \(c.title)").lineLimit(1)
                    Button { store.close(c, serverId: server.id) } label: {
                        Image(systemName: "xmark").font(.system(size: 9, weight: .semibold))
                    }
                    .buttonStyle(.plain).foregroundStyle(Color.textMuted)
                }
                .font(.secondary)
                .foregroundStyle(current?.id == c.id ? Color.text : Color.textSecondary)
                .padding(.horizontal, 10).frame(height: 28)
                .background(current?.id == c.id ? Color.selected : .clear, in: RoundedRectangle(cornerRadius: 8))
                .onTapGesture { store.selected[server.id] = c.id }
            }
            Button { newTab() } label: { Image(systemName: "plus") }
                .buttonStyle(.plain).foregroundStyle(Color.textSecondary)
                .disabled(server.state != .ready)
                .help("New terminal (tmux session fleet-N)")
            Spacer()
            Toggle("tmux", isOn: $tmux).toggleStyle(.switch).controlSize(.mini)
                .help("Back new terminals with tmux so they survive disconnects")
            if let c = current, c.closed, let api = core.api {
                Button("Reconnect") { store.reconnect(c, serverId: server.id, api: api, tmux: tmux) }
                    .controlSize(.small)
            }
        }
        .padding(.horizontal, 8).frame(height: 40)
        .background(Color(hex: 0x16171a))
    }

    private var footer: some View {
        HStack {
            Text(tmux ? "tmux · survives disconnects" : "login shell")
            Spacer()
            Text("Secure Enclave key · ecdsa-sha2-nistp256")
        }
        .font(.caption11).foregroundStyle(Color.textMuted)
        .padding(.horizontal, 12).frame(height: 26)
        .background(Color(hex: 0x16171a))
    }

    private func newTab() {
        guard let api = core.api else { return }
        store.open(serverId: server.id, api: api, tmux: tmux)
    }
}
