import SwiftUI

/// Kill / renice from a process row's context menu (`process.signal`,
/// `process.renice`), each behind a confirmation.
struct ProcessActions: ViewModifier {
    @Environment(CoreBridge.self) private var core
    let serverId: String
    let process: ProcessRow
    /// After each action: the error message, if it failed.
    var changed: (String?) -> Void = { _ in }
    @State private var pending: PendingAction?
    @State private var renicing = false
    @State private var nice = 0
    @State private var error: String?

    func body(content: Content) -> some View {
        content
            .contextMenu {
                Button("Terminate (TERM)") { ask(.term, "Terminate", destructive: true) }
                Button("Kill (KILL)") { ask(.kill, "Kill", destructive: true) }
                Button("Hang up (HUP)") { ask(.hup, "Send HUP to", destructive: false) }
                Button("Stop (STOP)") { ask(.stop, "Pause", destructive: false) }
                Button("Continue (CONT)") { ask(.cont, "Resume", destructive: false) }
                Divider()
                Button("Change priority…") { nice = Int(process.nice); renicing = true }
            }
            .confirmAction($pending)
            .popover(isPresented: $renicing) {
                VStack(alignment: .leading, spacing: 10) {
                    Text(verbatim: "Priority of \(process.name) (\(process.pid))").font(.system(size: 13, weight: .semibold))
                    Stepper("nice \(nice)", value: $nice, in: -20...19)
                    Text("Lower is higher priority; below 0 takes CPU from everything else.")
                        .font(.caption11).foregroundStyle(Color.textMuted)
                    HStack {
                        Spacer()
                        Button("Cancel") { renicing = false }
                        Button("Apply") {
                            renicing = false
                            let n = Int8(nice)
                            run { try await $0.processRenice(serverId: serverId, pid: process.pid, nice: n) }
                        }
                        .buttonStyle(.borderedProminent).tint(.accent)
                    }
                    if let error { Text(error).font(.caption11).foregroundStyle(Tone.warn.text) }
                }
                .padding(14)
                .frame(width: 300)
            }
    }

    private func ask(_ s: SignalArg, _ verb: String, destructive: Bool) {
        pending = PendingAction(title: "\(verb) \(process.name) (pid \(process.pid))?",
                                message: "Runs as \(process.user): \(process.cmdline)",
                                button: verb, destructive: destructive) {
            run { try await $0.processSignal(serverId: serverId, pid: process.pid, signal: s) }
        }
    }

    private func run(_ op: @escaping (FleetCore) async throws -> Void) {
        guard let api = core.api else { return }
        Task {
            do {
                try await op(api)
                error = nil
            } catch {
                self.error = error.fleetMessage
            }
            changed(error)
        }
    }
}

extension View {
    func processActions(serverId: String, process: ProcessRow,
                        changed: @escaping (String?) -> Void = { _ in }) -> some View {
        modifier(ProcessActions(serverId: serverId, process: process, changed: changed))
    }
}
