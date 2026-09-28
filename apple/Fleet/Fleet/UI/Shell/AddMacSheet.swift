import SwiftUI

/// Enrolled Mac side of adding a Mac: scan or paste the code, compare the
/// six digits, approve with Touch ID.
struct AddMacSheet: View {
    @Environment(CoreBridge.self) private var core
    @Environment(\.dismiss) private var dismiss

    private enum Mode: String, CaseIterable { case scan = "Scan QR code", paste = "Paste code" }
    @State private var mode: Mode = .scan
    @State private var pasted = ""
    @State private var prompt: AddMacPrompt?
    /// Shown once the new Mac revealed its committed secret.
    @State private var sas: String?
    @State private var poll: Task<Void, Never>?
    @State private var result: RosterChangeResult?
    @State private var busy = false
    @State private var error: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Add a Mac").font(.sectionTitle)
            if let result {
                Text("Added. Roster v\(result.version) reached \(result.current) servers; \(result.queued) will get it when they reconnect.")
                ForEach(result.failed, id: \.self) { Text($0).foregroundStyle(Tone.critical.text) }
                HStack {
                    Spacer()
                    Button("Done") { dismiss() }.keyboardShortcut(.defaultAction)
                        .accessibilityIdentifier("addMac.done")
                }
            } else if let prompt, sas == nil {
                ProgressView("Waiting for “\(prompt.name)” to show its code…")
                HStack { Spacer(); Button("Cancel") { dismiss() } }
            } else if let prompt, let sas {
                Text("Check that “\(prompt.name)” shows this code:")
                Text(Self.spaced(sas))
                    .font(.system(size: 34, weight: .semibold, design: .monospaced))
                    .padding(.vertical, 8)
                Text("Only approve if the codes match exactly. A different code means the pairing code was swapped.")
                    .font(.secondary).foregroundStyle(Color.textSecondary)
                HStack {
                    Button("Codes differ", role: .cancel) { dismiss() }
                        .accessibilityIdentifier("addMac.codesDiffer")
                    Spacer()
                    Button("Codes match — Approve") { approve(prompt) }
                        .accessibilityIdentifier("addMac.approve")
                        .buttonStyle(.borderedProminent).tint(.accent)
                        .disabled(busy)
                }
            } else {
                Text("On the new Mac, choose “Join an existing fleet”. It shows a QR code and a pairing code.")
                    .foregroundStyle(Color.textSecondary)
                Picker("", selection: $mode) {
                    ForEach(Mode.allCases, id: \.self) { Text($0.rawValue).tag($0) }
                }
                .pickerStyle(.segmented)
                .accessibilityIdentifier("addMac.mode")
                switch mode {
                case .scan:
                    QRScannerView { code in begin(code) }
                        .frame(height: 260)
                        .clipShape(RoundedRectangle(cornerRadius: 8))
                case .paste:
                    TextEditor(text: $pasted)
                        .font(.mono(12))
                        .frame(height: 120)
                        .border(Color.borderControl)
                        .accessibilityIdentifier("addMac.pasteCode")
                    HStack {
                        Spacer()
                        Button("Continue") { begin(pasted) }
                            .accessibilityIdentifier("addMac.continue")
                            .disabled(pasted.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || busy)
                    }
                }
                HStack { Spacer(); Button("Cancel") { dismiss() } }
            }
            if let error {
                Text(error).foregroundStyle(Tone.critical.text)
            }
        }
        .padding(24)
        .frame(width: 520)
        .onDisappear { poll?.cancel() }
    }

    private func begin(_ code: String) {
        guard prompt == nil, let api = core.api else { return }
        busy = true
        Task {
            defer { busy = false }
            do {
                let p = try api.beginAddMac(code: code)
                // The new Mac fetches the answer by name, then reveals the
                // secret its code committed to; only then is there a code.
                await core.sync?.upload([p.response])
                prompt = p
                error = nil
                poll = Task { await waitForReveal(p) }
            } catch {
                self.error = error.fleetMessage
            }
        }
    }

    private func waitForReveal(_ p: AddMacPrompt) async {
        guard let api = core.api, let cloud = core.sync?.cloud else { return }
        while !Task.isCancelled && sas == nil {
            do {
                if let r = try await cloud.fetch([p.revealRecord]).first {
                    sas = try api.addMacVerificationCode(deviceId: p.deviceId, reveal: r)
                    return
                }
            } catch {
                self.error = error.fleetMessage
            }
            try? await Task.sleep(for: .seconds(3))
        }
    }

    private func approve(_ p: AddMacPrompt) {
        guard let api = core.api else { return }
        busy = true
        Task {
            defer { busy = false }
            do {
                let r = try await api.approveAddMac(deviceId: p.deviceId)
                await core.sync?.upload(r.upload)
                await core.sync?.cycle()
                result = r
            } catch {
                self.error = error.fleetMessage
            }
        }
    }

    static func spaced(_ code: String) -> String {
        guard code.count == 6 else { return code }
        return "\(code.prefix(3)) \(code.suffix(3))"
    }
}
