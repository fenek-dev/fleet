import AppKit
import SwiftUI

/// Excludes the hosting window from screen capture while `active`
/// (`NSWindow.sharingType = .none`), restoring it afterwards.
private struct CaptureShield: NSViewRepresentable {
    let active: Bool

    func makeNSView(context: Context) -> NSView { NSView() }

    func updateNSView(_ view: NSView, context: Context) {
        let active = active
        DispatchQueue.main.async {
            view.window?.sharingType = active ? .none : .readOnly
        }
    }

    static func dismantleNSView(_ view: NSView, coordinator: ()) {
        view.window?.sharingType = .readOnly
    }
}

/// First launch: create a fleet with this Mac as its first device
/// (design §5.3 genesis roster, §5.11 recovery code).
///
/// Name → recovery words (shown once) → re-type 4 random words →
/// optional passphrase → derive + Touch ID (root key signs the genesis
/// roster) → start. The words live in this view's state only until the
/// check passes, then they are dropped; Rust wipes its copy in `finish`.
struct EnrollmentView: View {
    @Environment(CoreBridge.self) private var core

    private enum Step: Int, CaseIterable {
        case name, words, verify, passphrase, finishing, done
    }

    @State private var step: Step = .name
    @State private var fleetName = ""
    @State private var deviceName = Host.current().localizedName ?? "Mac"
    @State private var enrollment: Enrollment?
    @State private var words: [String] = []
    @State private var challenge: [UInt32] = []
    @State private var answers: [String] = []
    @State private var passphrase = ""
    @State private var passphraseAgain = ""
    @State private var result: EnrollmentResult?
    @State private var error: String?

    var body: some View {
        VStack(spacing: 0) {
            header
            ScrollView {
                VStack(alignment: .leading, spacing: 20) {
                    switch step {
                    case .name: nameStep
                    case .words: wordsStep
                    case .verify: verifyStep
                    case .passphrase: passphraseStep
                    case .finishing: finishingStep
                    case .done: doneStep
                    }
                    if let error {
                        Text(error).font(.base).foregroundStyle(Tone.critical.text)
                    }
                }
                .frame(maxWidth: 640, alignment: .leading)
                .padding(32)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Color.window)
        // Screenshots, screen recording and sharing see a blank window
        // while the recovery words exist in the UI.
        .background(CaptureShield(active: !words.isEmpty))
        .onDisappear { enrollment?.cancel() }
    }

    private var header: some View {
        HStack(spacing: 16) {
            VStack(alignment: .leading, spacing: 2) {
                Text("Create your fleet").font(.toolbarTitle).foregroundStyle(Color.text)
                Text("This Mac becomes the fleet's first device.")
                    .font(.secondary).foregroundStyle(Color.textMuted)
            }
            Spacer()
            HStack(spacing: 6) {
                ForEach(Step.allCases.dropLast(), id: \.rawValue) { s in
                    Capsule()
                        .fill(s.rawValue <= step.rawValue ? Color.accent : Color.control)
                        .frame(width: 28, height: 4)
                }
            }
        }
        .padding(.horizontal, 24)
        .frame(height: 60)
        .background(Color.header)
    }

    // MARK: steps

    private var nameStep: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Names").font(.sectionTitle)
            Form {
                TextField("Fleet name", text: $fleetName, prompt: Text("Production"))
                TextField("This Mac", text: $deviceName)
            }
            .formStyle(.grouped)
            Text("Next you get a 24-word recovery code. It is the only way back in if every Mac is lost. Write it down by hand.")
                .font(.base).foregroundStyle(Color.textSecondary)
            HStack {
                Spacer()
                Button("Continue") { begin() }
                    .buttonStyle(.borderedProminent).tint(.accent)
                    .disabled(fleetName.trimmingCharacters(in: .whitespaces).isEmpty
                              || deviceName.trimmingCharacters(in: .whitespaces).isEmpty)
            }
        }
    }

    private var wordsStep: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Recovery code").font(.sectionTitle)
            Text("Write these 24 words on paper, in order. They are shown once. Don't photograph or print them on a network printer.")
                .font(.base).foregroundStyle(Color.textSecondary)
            LazyVGrid(columns: Array(repeating: GridItem(.flexible(), spacing: 12), count: 4),
                      alignment: .leading, spacing: 10) {
                ForEach(Array(words.enumerated()), id: \.offset) { i, w in
                    HStack(spacing: 8) {
                        Text("\(i + 1)").font(.mono(11)).foregroundStyle(Color.textMuted)
                            .frame(width: 20, alignment: .trailing)
                        Text(w).font(.mono(13)).foregroundStyle(Color.text)
                    }
                    .padding(.vertical, 6).padding(.horizontal, 8)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(Color.control, in: RoundedRectangle(cornerRadius: 8))
                }
            }
            .card()
            .privacySensitive()
            HStack {
                Spacer()
                Button("I wrote them down") { newChallenge() }
                    .buttonStyle(.borderedProminent).tint(.accent)
            }
        }
    }

    private var verifyStep: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Check your copy").font(.sectionTitle)
            Text("Type these words from your paper copy.")
                .font(.base).foregroundStyle(Color.textSecondary)
            Form {
                ForEach(Array(challenge.enumerated()), id: \.offset) { i, pos in
                    TextField("Word \(pos + 1)", text: Binding(
                        get: { answers.indices.contains(i) ? answers[i] : "" },
                        set: { if answers.indices.contains(i) { answers[i] = $0 } }))
                        .autocorrectionDisabled()
                        .font(.mono(13))
                }
            }
            .formStyle(.grouped)
            HStack {
                Button("Show words again") { step = .words; error = nil }
                    .disabled(words.isEmpty)
                Spacer()
                Button("Check") { verify() }
                    .buttonStyle(.borderedProminent).tint(.accent)
                    .keyboardShortcut(.defaultAction)
            }
        }
    }

    private var passphraseStep: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Passphrase (recommended)").font(.sectionTitle)
            Text("A passphrase you memorize and never write down. With it, recovery takes effect at once and the paper alone is useless. Without it, recovery waits 72 hours and a compromised Mac can veto it.")
                .font(.base).foregroundStyle(Color.textSecondary)
            Form {
                SecureField("Passphrase", text: $passphrase)
                SecureField("Repeat", text: $passphraseAgain)
            }
            .formStyle(.grouped)
            Text("For immediate recovery the passphrase must be strong: at least 12 characters using 3 of lowercase, uppercase, digits and symbols, or at least 5 different words of 3+ letters. A weaker passphrase still protects the code but keeps the 72 h delay.")
                .font(.secondary).foregroundStyle(Color.textMuted)
            if passphrase.isEmpty {
                StatusPill(label: "No passphrase: 72 h recovery delay", tone: .warn)
            } else if recoveryPassphraseIsStrong(passphrase: passphrase) {
                StatusPill(label: "Strong: no recovery delay", tone: .ok)
            } else {
                StatusPill(label: "Too weak for immediate recovery: 72 h delay", tone: .warn)
            }
            HStack {
                Spacer()
                Button("Create fleet") { finish() }
                    .buttonStyle(.borderedProminent).tint(.accent)
                    .disabled(passphrase != passphraseAgain)
            }
            Text("Touch ID signs the fleet's first device roster with this Mac's root key.")
                .font(.secondary).foregroundStyle(Color.textMuted)
        }
    }

    private var finishingStep: some View {
        HStack(spacing: 12) {
            ProgressView().controlSize(.small)
            Text("Deriving recovery keys and signing the roster…")
                .foregroundStyle(Color.textSecondary)
        }
    }

    private var doneStep: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Fleet created").font(.sectionTitle)
            if let result {
                LabeledContent("Fleet", value: result.fleetId).font(.mono(12))
                LabeledContent("Recovery delay",
                               value: result.recoveryDelayS == 0 ? "none (strong passphrase)" : "72 hours")
            }
            Text("Next: add a server and install the agent.")
                .foregroundStyle(Color.textSecondary)
            HStack {
                Spacer()
                Button("Open fleet") { core.startManager() }
                    .buttonStyle(.borderedProminent).tint(.accent)
            }
        }
    }

    // MARK: actions

    private func begin() {
        error = nil
        guard let api = core.api else { return }
        do {
            let e = try api.createFleet(fleetName: fleetName, deviceName: deviceName)
            enrollment = e
            words = try e.recoveryWords()
            step = .words
        } catch {
            self.error = error.fleetMessage
        }
    }

    private func newChallenge() {
        error = nil
        do {
            challenge = try enrollment?.challenge() ?? []
            answers = Array(repeating: "", count: challenge.count)
            step = .verify
        } catch {
            self.error = error.fleetMessage
        }
    }

    private func verify() {
        guard let enrollment else { return }
        do {
            if try enrollment.confirmWords(answers: answers) {
                // Drop our copy of the words; Rust keeps the entropy until finish.
                words = []
                answers = []
                error = nil
                step = .passphrase
            } else {
                error = "Those words don't match. Check your copy and try again."
                newChallengeKeepingError()
            }
        } catch {
            self.error = error.fleetMessage
        }
    }

    private func newChallengeKeepingError() {
        let e = error
        newChallenge()
        error = e
    }

    private func finish() {
        guard let enrollment else { return }
        error = nil
        step = .finishing
        let pass = passphrase
        passphrase = ""
        passphraseAgain = ""
        Task {
            do {
                result = try await enrollment.finish(passphrase: pass)
                step = .done
            } catch {
                // The enrollment survives a failed finish (e.g. Touch ID
                // cancelled): retry with the same written words.
                self.error = error.fleetMessage
                step = .passphrase
            }
        }
    }
}
