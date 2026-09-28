import SwiftUI

/// Shared pieces of the editing tabs: dates, agent error wording, the
/// confirmation-dialog state and the auto-revert banner (design §4.10).

func fmtDate(_ ms: UInt64?) -> String {
    guard let ms, ms > 0 else { return "–" }
    return Date(timeIntervalSince1970: TimeInterval(ms) / 1000)
        .formatted(date: .abbreviated, time: .shortened)
}

/// Operator wording for the agent's fixed error codes (Rust sends the code
/// name only; messages are made on the Mac).
func agentCodeMessage(_ code: String) -> String {
    if code.hasPrefix("VersionConflict") {
        return "The server's state changed since you loaded it. Reload and make the change again."
    }
    switch code {
    case "ApprovalRequired": return "This change needs Touch ID approval with the root key."
    case "ApprovalInvalid": return "The server did not accept the Touch ID approval."
    case "PolicyDenied": return "The server's policy does not allow this."
    case "InvalidArgument": return "The server rejected the values given."
    case "NotFound": return "Not found on the server."
    case "Busy": return "Another change is still in progress on this server. Try again shortly."
    case "Timeout": return "The operation timed out on the server."
    case "Unsupported": return "This agent version does not support that operation."
    case "Unauthorized": return "This Mac is not authorized on the server."
    case "SignatureInvalid": return "The server rejected this Mac's signature."
    case "Stale", "Replay": return "The command expired in transit. Try again."
    case "Internal": return "The agent hit an internal error. Check its audit log."
    default: return "The agent refused the request (\(code))."
    }
}

/// A pending confirmation: title, button, what runs on confirm.
struct PendingAction: Identifiable {
    let id = UUID()
    let title: String
    var message: String = ""
    let button: String
    var destructive = false
    /// Shown as a note: the action asks for Touch ID (root key).
    var elevated = false
    let run: () -> Void
}

extension View {
    /// Confirmation dialog for mutations; every change goes through one.
    func confirmAction(_ pending: Binding<PendingAction?>) -> some View {
        confirmationDialog(pending.wrappedValue?.title ?? "",
                           isPresented: Binding(get: { pending.wrappedValue != nil },
                                                set: { if !$0 { pending.wrappedValue = nil } }),
                           titleVisibility: .visible,
                           presenting: pending.wrappedValue) { p in
            Button(p.button, role: p.destructive ? .destructive : nil) { p.run() }
            Button("Cancel", role: .cancel) {}
        } message: { p in
            let note = p.elevated ? "Requires Touch ID approval (root key)." : ""
            Text([p.message, note].filter { !$0.isEmpty }.joined(separator: "\n\n"))
        }
    }
}

/// Section card with a title and optional trailing controls.
struct AdminSection<Content: View, Trailing: View>: View {
    let title: String
    @ViewBuilder var trailing: () -> Trailing
    @ViewBuilder var content: () -> Content

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text(title).font(.system(size: 13, weight: .semibold))
                Spacer()
                trailing()
            }
            content()
        }
        .frame(maxWidth: .infinity, alignment: .topLeading)
        .card()
    }
}

extension AdminSection where Trailing == EmptyView {
    init(title: String, @ViewBuilder content: @escaping () -> Content) {
        self.init(title: title, trailing: { EmptyView() }, content: content)
    }
}

// MARK: - Auto-revert

/// Drives one auto-revert change: counts down to the deadline and confirms
/// from a fresh connection as soon as the core has one (the core reconnects
/// the server first; design §4.10 step 3).
@Observable
@MainActor
final class AutoRevertModel {
    enum Phase: Equatable {
        case idle
        case confirming
        case confirmed
        case reverted
        case noConnection
        case failed(String)
    }

    private(set) var phase: Phase = .idle
    private(set) var change: PendingChangeRow?
    private(set) var now = Date()
    @ObservationIgnored private var ticker: Task<Void, Never>?

    var remaining: Int {
        guard let c = change else { return 0 }
        return max(0, Int(Double(c.deadlineMs) / 1000 - now.timeIntervalSince1970))
    }

    var active: Bool { phase != .idle }

    /// Starts confirming `change`; `done` runs after the outcome (reload).
    func confirm(api: FleetCore, serverId: String, change: PendingChangeRow,
                 done: @escaping @MainActor () -> Void = {}) {
        self.change = change
        phase = .confirming
        startTicker()
        Task {
            let outcome: Phase
            do {
                switch try await api.confirmChange(serverId: serverId, changeIdHex: change.changeIdHex,
                                                   deadlineMs: change.deadlineMs) {
                case .confirmed: outcome = .confirmed
                case .reverted: outcome = .reverted
                case .noConnection: outcome = .noConnection
                case .failed(let m): outcome = .failed(agentCodeMessage(m))
                }
            } catch {
                outcome = .failed(error.fleetMessage)
            }
            phase = outcome
            if outcome != .noConnection { ticker?.cancel() }
            done()
        }
    }

    func dismiss() {
        ticker?.cancel()
        phase = .idle
        change = nil
    }

    private func startTicker() {
        ticker?.cancel()
        ticker = Task { [weak self] in
            while !Task.isCancelled {
                self?.now = Date()
                if (self?.remaining ?? 0) == 0 {
                    if self?.phase == .noConnection { self?.phase = .reverted }
                    return
                }
                try? await Task.sleep(for: .seconds(1))
            }
        }
    }
}

/// The confirmation banner from the Firewall mockup.
struct AutoRevertBanner: View {
    let model: AutoRevertModel
    let what: String
    var retry: (() -> Void)?

    var body: some View {
        if model.active {
            HStack(spacing: 12) {
                Image(systemName: icon).foregroundStyle(tone.text)
                VStack(alignment: .leading, spacing: 2) {
                    Text(title).font(.system(size: 13, weight: .semibold)).foregroundStyle(tone.text)
                    Text(detail).font(.secondary).foregroundStyle(Color.textSecondary)
                }
                Spacer()
                if model.phase == .confirming { ProgressView().controlSize(.small) }
                if let retry, canRetry {
                    Button("Confirm change") { retry() }.buttonStyle(.borderedProminent).tint(.accent)
                }
                if model.phase != .confirming {
                    Button("Dismiss") { model.dismiss() }
                }
            }
            .padding(12)
            .background(tone.bg, in: RoundedRectangle(cornerRadius: 12))
            .overlay(RoundedRectangle(cornerRadius: 12).stroke(tone.dot.opacity(0.5)))
            .accessibilityElement(children: .contain)
            .accessibilityIdentifier("autorevert.banner")
        }
    }

    private var canRetry: Bool {
        switch model.phase {
        case .noConnection, .failed: model.remaining > 0
        default: false
        }
    }

    private var countdown: String {
        let r = model.remaining
        return String(format: "%d:%02d", r / 60, r % 60)
    }

    private var title: String {
        switch model.phase {
        case .idle: ""
        case .confirming: "Change applied · confirm within \(countdown)"
        case .confirmed: "Change confirmed"
        case .reverted: "Change reverted"
        case .noConnection: "Could not reconnect · reverts in \(countdown)"
        case .failed: "Confirmation failed · reverts in \(countdown)"
        }
    }

    private var detail: String {
        switch model.phase {
        case .idle: ""
        case .confirming:
            "\(what). Fleet is confirming from a fresh connection; if that fails, the previous state comes back automatically."
        case .confirmed: "\(what). A fresh connection worked, so the change stays."
        case .reverted: "\(what) did not stay: the server restored the previous state."
        case .noConnection:
            "No fresh connection came up. If access is broken, the server restores the previous state at the deadline."
        case .failed(let m): m
        }
    }

    private var tone: Tone {
        switch model.phase {
        case .confirmed: .ok
        case .reverted, .failed: .critical
        case .noConnection: .warn
        default: .info
        }
    }

    private var icon: String {
        switch model.phase {
        case .confirmed: "checkmark.shield"
        case .reverted: "arrow.uturn.backward.circle"
        case .noConnection, .failed: "exclamationmark.triangle"
        default: "clock.arrow.circlepath"
        }
    }
}

/// Colored unified diff (config history, firewall preview).
struct UnifiedDiffView: View {
    let text: String

    var body: some View {
        ScrollView([.vertical, .horizontal]) {
            LazyVStack(alignment: .leading, spacing: 0) {
                ForEach(Array(text.split(separator: "\n", omittingEmptySubsequences: false).enumerated()),
                        id: \.offset) { _, line in
                    Text(line.isEmpty ? " " : String(line))
                        .font(.mono(11))
                        .foregroundStyle(color(line))
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(.horizontal, 6)
                        .background(bg(line))
                }
            }
            .textSelection(.enabled)
        }
        .background(Color.track, in: RoundedRectangle(cornerRadius: 8))
    }

    private func color(_ l: Substring) -> Color {
        if l.hasPrefix("+++") || l.hasPrefix("---") { return Color.textSecondary }
        if l.hasPrefix("+") { return Tone.ok.text }
        if l.hasPrefix("-") { return Tone.critical.text }
        if l.hasPrefix("@@") { return Tone.info.text }
        return Color.text
    }

    private func bg(_ l: Substring) -> Color {
        if l.hasPrefix("+++") || l.hasPrefix("---") { return .clear }
        if l.hasPrefix("+") { return Tone.ok.bg }
        if l.hasPrefix("-") { return Tone.critical.bg }
        return .clear
    }
}
