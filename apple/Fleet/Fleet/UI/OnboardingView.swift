import AppKit
import SwiftUI

/// First launch: create a fleet, join one from another Mac (design §5.12),
/// or recover with the printed code (design §5.11).
struct OnboardingView: View {
    private enum Path { case choose, create, join, recover }
    @State private var path: Path = .choose

    var body: some View {
        switch path {
        case .choose: chooser
        case .create: EnrollmentView()
        case .join: JoinFleetView { path = .choose }
        case .recover: RecoverFleetView { path = .choose }
        }
    }

    private var chooser: some View {
        VStack(alignment: .leading, spacing: 20) {
            Text("Welcome to Fleet").font(.sectionTitle)
            choice("Create a new fleet", "This Mac becomes the fleet's first device.", "plus.circle") { path = .create }
            choice("Join an existing fleet", "Another Mac in your fleet approves this one.", "laptopcomputer.and.arrow.down") { path = .join }
            choice("Recover fleet", "Every Mac is lost: use the 24-word recovery code.", "key") { path = .recover }
        }
        .frame(maxWidth: 560)
        .padding(40)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Color.window)
    }

    private func choice(_ title: String, _ detail: String, _ icon: String, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            HStack(spacing: 14) {
                Image(systemName: icon).font(.system(size: 22)).frame(width: 32)
                VStack(alignment: .leading, spacing: 2) {
                    Text(title).font(.base).foregroundStyle(Color.text)
                    Text(detail).font(.secondary).foregroundStyle(Color.textMuted)
                }
                Spacer()
            }
            .card()
        }
        .buttonStyle(.plain)
    }
}

/// New Mac side of adding a Mac: show the code, compare six digits, wait
/// for the enrolled Mac's approval and key box (through iCloud).
struct JoinFleetView: View {
    let back: () -> Void
    @Environment(CoreBridge.self) private var core
    @State private var deviceName = Host.current().localizedName ?? "Mac"
    @State private var offer: PairingOfferRow?
    @State private var sas: String?
    @State private var waiting = false
    @State private var error: String?
    @State private var poll: Task<Void, Never>?

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            Text("Join an existing fleet").font(.sectionTitle)
            if core.sync?.available != true {
                Text("Joining needs iCloud (a signed build with the CloudKit entitlement, signed in to the same Apple ID as your other Macs).")
                    .foregroundStyle(Tone.warn.text)
            }
            if let offer {
                if let sas {
                    Text("Check that the other Mac shows this code, then approve there:")
                    Text(AddMacSheet.spaced(sas))
                        .font(.system(size: 34, weight: .semibold, design: .monospaced))
                    ProgressView("Waiting for approval…")
                } else {
                    Text("On a Mac already in the fleet: Settings → Devices → Add Mac, then scan this code or paste it.")
                        .foregroundStyle(Color.textSecondary)
                    HStack(alignment: .top, spacing: 20) {
                        QRCodeView(text: offer.code).frame(width: 220, height: 220)
                        VStack(alignment: .leading, spacing: 8) {
                            Text(offer.code).font(.mono(10)).textSelection(.enabled).lineLimit(8)
                            Button("Copy code") {
                                NSPasteboard.general.clearContents()
                                NSPasteboard.general.setString(offer.code, forType: .string)
                            }
                        }
                    }
                    ProgressView("Waiting for the other Mac…")
                }
            } else {
                Form { TextField("This Mac", text: $deviceName) }.formStyle(.grouped)
                HStack {
                    Button("Back") { back() }
                    Spacer()
                    Button("Show pairing code") { start() }
                        .buttonStyle(.borderedProminent).tint(.accent)
                        .disabled(deviceName.trimmingCharacters(in: .whitespaces).isEmpty)
                }
            }
            if let error { Text(error).foregroundStyle(Tone.critical.text) }
        }
        .frame(maxWidth: 640, alignment: .leading)
        .padding(40)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Color.window)
        .onDisappear { poll?.cancel() }
    }

    private func start() {
        guard let api = core.api else { return }
        do {
            core.allowKeyCreation(true)
            let o = try api.createPairingOffer(deviceName: deviceName)
            offer = o
            error = nil
            poll = Task { await wait(o) }
        } catch {
            self.error = error.fleetMessage
        }
    }

    private func wait(_ o: PairingOfferRow) async {
        guard let api = core.api, let cloud = core.sync?.cloud else { return }
        while !Task.isCancelled {
            do {
                if sas == nil, let r = try await cloud.fetch([o.responseRecord]).first {
                    sas = try api.pairingVerificationCode(response: r)
                }
                if sas != nil, let kb = try await cloud.fetch([o.keyboxRecord]).first {
                    let all = try await cloud.changes(since: nil)
                    try api.completePairing(keybox: kb, records: all.records)
                    core.startManager()
                    return
                }
            } catch {
                self.error = error.fleetMessage
            }
            try? await Task.sleep(for: .seconds(3))
        }
    }
}

/// "Recover fleet" on a fresh install (design §5.11).
struct RecoverFleetView: View {
    let back: () -> Void
    @Environment(CoreBridge.self) private var core
    private enum Step { case code, restored, done }
    @State private var step: Step = .code
    @State private var words = ""
    @State private var passphrase = ""
    @State private var session: RecoverySession?
    @State private var restored: RestoreRow?
    @State private var deviceName = Host.current().localizedName ?? "Mac"
    @State private var newPassphrase = ""
    @State private var result: RecoveryResultRow?
    @State private var busy = false
    @State private var error: String?

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                Text("Recover fleet").font(.sectionTitle)
                switch step {
                case .code: codeStep
                case .restored: restoredStep
                case .done: doneStep
                }
                if busy { ProgressView() }
                if let error { Text(error).foregroundStyle(Tone.critical.text) }
            }
            .frame(maxWidth: 680, alignment: .leading)
            .padding(40)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Color.window)
        .onDisappear { session?.cancel() }
    }

    private var codeStep: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Enter the 24 words and the passphrase, if you set one. The keys exist only in memory.")
                .foregroundStyle(Color.textSecondary)
            TextEditor(text: $words).font(.mono(13)).frame(height: 90).border(Color.borderControl)
                .privacySensitive()
            SecureField("Passphrase (optional)", text: $passphrase)
            if core.sync?.available != true {
                Text("Recovery needs the fleet's iCloud data: the server list and pinned keys (roster copies are optional; the servers are asked for their roster). Servers entered by hand can't be recovered: their agent keys can't be verified without the pins.")
                    .font(.secondary).foregroundStyle(Tone.warn.text)
            }
            HStack {
                Button("Back") { back() }
                Spacer()
                Button("Open iCloud escrow") { openEscrow() }
                    .buttonStyle(.borderedProminent).tint(.accent)
                    .disabled(busy || words.split(whereSeparator: \.isWhitespace).count != 24)
            }
        }
    }

    private var restoredStep: some View {
        VStack(alignment: .leading, spacing: 12) {
            if let r = restored {
                Text("Restored \(r.servers) servers and roster v\(r.rosterVersion). These Macs will be removed: \(r.devicesLost.joined(separator: ", ")).")
            }
            Form {
                TextField("This Mac", text: $deviceName)
                SecureField("New passphrase (optional)", text: $newPassphrase)
            }
            .formStyle(.grouped)
            Text("A new recovery code replaces the one you just typed. Servers with a recovery delay wait 72 hours, and any remaining Mac can veto.")
                .font(.secondary).foregroundStyle(Color.textSecondary)
            HStack {
                Spacer()
                Button("Recover") { recover() }
                    .buttonStyle(.borderedProminent).tint(.accent)
                    .disabled(busy)
            }
        }
    }

    private var doneStep: some View {
        VStack(alignment: .leading, spacing: 12) {
            if let r = result {
                ForEach(r.servers, id: \.serverId) { s in
                    LabeledContent(s.name.isEmpty ? s.serverId : s.name, value: Self.status(s))
                }
                Text("New recovery code — write it down now; it is shown once:")
                    .foregroundStyle(Tone.warn.text)
                Text(r.newWords.enumerated().map { "\($0 + 1). \($1)" }.joined(separator: "   "))
                    .font(.mono(13)).privacySensitive()
                HStack {
                    Spacer()
                    Button("I wrote it down") {
                        result = nil
                        core.startManager()
                    }
                    .buttonStyle(.borderedProminent).tint(.accent)
                }
            }
        }
    }

    static func status(_ s: ServerRecoveryRow) -> String {
        switch s.status {
        case .installed: "recovered"
        case .pending:
            "pending until \(Date(timeIntervalSince1970: Double(s.activatesAtMs ?? 0) / 1000).formatted())"
        case .failed: "failed: \(s.error ?? "")"
        }
    }

    private func openEscrow() {
        guard let api = core.api, let cloud = core.sync?.cloud else {
            error = "iCloud isn't available in this build."
            return
        }
        busy = true
        let (w, p) = (words, passphrase)
        Task {
            defer { busy = false }
            do {
                let s = try await api.beginRecovery(words: w, passphrase: p)
                guard let escrow = try await cloud.fetch([s.escrowRecordName()]).first else {
                    error = "No escrow for this code in iCloud."
                    return
                }
                _ = try s.openEscrow(escrow: escrow)
                let all = try await cloud.changes(since: nil)
                // Without roster copies this asks the servers (roster.get).
                restored = try await s.restore(records: all.records)
                session = s
                words = ""
                passphrase = ""
                step = .restored
                error = nil
            } catch {
                self.error = error.fleetMessage
            }
        }
    }

    private func recover() {
        guard let s = session else { return }
        busy = true
        core.allowKeyCreation(true)
        let (n, p) = (deviceName, newPassphrase)
        Task {
            defer { busy = false }
            do {
                let r = try await s.recover(deviceName: n, newPassphrase: p)
                await core.sync?.upload(r.upload, delete: r.delete)
                result = r
                step = .done
                error = nil
            } catch {
                self.error = error.fleetMessage
            }
        }
    }
}
