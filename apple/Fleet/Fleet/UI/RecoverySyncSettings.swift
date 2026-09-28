import SwiftUI

/// Settings → Recovery (design §5.11): pending recoveries (veto), the
/// recovery drill, replacing the code.
struct RecoverySettings: View {
    @Environment(CoreBridge.self) private var core
    @State private var words = ""
    @State private var passphrase = ""
    @State private var drill: [DrillRow] = []
    @State private var newPassphrase = ""
    @State private var newWords: [String] = []
    @State private var busy = false
    @State private var error: String?

    var body: some View {
        Form {
            Section("Pending recoveries") {
                let pending = core.api?.pendingRecoveries() ?? []
                if pending.isEmpty {
                    Text("None.").foregroundStyle(Color.textMuted)
                }
                ForEach(pending, id: \.serverId) { p in
                    HStack {
                        VStack(alignment: .leading) {
                            Text(p.name.isEmpty ? p.serverId : p.name)
                            Text("Activates \(Date(timeIntervalSince1970: Double(p.activatesAtMs) / 1000).formatted())")
                                .font(.secondary).foregroundStyle(Tone.critical.text)
                        }
                        Spacer()
                        Button("Veto…", role: .destructive) { veto(p) }.disabled(busy)
                    }
                }
            }
            Section("Recovery drill") {
                Text("Type the code to check it still matches every server's roster. Nothing changes on the servers.")
                    .font(.secondary).foregroundStyle(Color.textSecondary)
                SecureField("24 words", text: $words)
                SecureField("Passphrase (if any)", text: $passphrase)
                Button("Check code") { runDrill() }
                    .accessibilityIdentifier("recovery.checkCode")
                    .disabled(busy || words.split(separator: " ").count != 24)
                ForEach(drill, id: \.serverId) { r in
                    LabeledContent(r.name.isEmpty ? r.serverId : r.name, value: r.result)
                        .foregroundStyle(r.ok ? Tone.ok.text : Tone.critical.text)
                }
                if !drill.isEmpty {
                    Text("Consider replacing the code now that it was typed into this Mac, especially after any security alert.")
                        .font(.secondary).foregroundStyle(Color.textSecondary)
                }
            }
            Section("Replace the recovery code") {
                if newWords.isEmpty {
                    SecureField("New passphrase (optional)", text: $newPassphrase)
                    Text(recoveryPassphraseIsStrong(passphrase: newPassphrase)
                         ? "Strong passphrase: recovery without delay."
                         : "Without a strong passphrase recovery waits 72 hours and can be vetoed.")
                        .font(.secondary).foregroundStyle(Color.textMuted)
                    Button("Replace with Touch ID") { rotate() }.disabled(busy)
                        .accessibilityIdentifier("recovery.replaceCode")
                } else {
                    Text("Write these words down. The old code keeps working for 72 hours.")
                        .foregroundStyle(Tone.warn.text)
                    Text(newWords.enumerated().map { "\($0 + 1). \($1)" }.joined(separator: "   "))
                        .font(.mono(12)).textSelection(.disabled).privacySensitive()
                    Button("I wrote them down") { newWords = [] }
                        .accessibilityIdentifier("recovery.wroteDown")
                }
            }
            if let error { Text(error).foregroundStyle(Tone.critical.text) }
        }
        .formStyle(.grouped)
        .onDisappear(perform: clearSecrets)
    }

    /// Drops every recovery word and passphrase this view holds (Swift
    /// strings can't be wiped in place; this ends our references).
    private func clearSecrets() {
        words = ""
        passphrase = ""
        newPassphrase = ""
        newWords = []
    }

    private func veto(_ p: PendingRecoveryRow) {
        guard let api = core.api else { return }
        busy = true
        Task {
            defer { busy = false }
            do { try await api.vetoRecovery(serverId: p.serverId, pendingHash: p.pendingHash) } catch {
                self.error = error.fleetMessage
            }
        }
    }

    private func runDrill() {
        guard let api = core.api else { return }
        busy = true
        let (w, p) = (words, passphrase)
        words = ""
        passphrase = ""
        Task {
            defer { busy = false }
            do { drill = try await api.recoveryDrill(words: w, passphrase: p) } catch {
                self.error = error.fleetMessage
            }
        }
    }

    private func rotate() {
        guard let api = core.api else { return }
        busy = true
        let p = newPassphrase
        newPassphrase = ""
        Task {
            defer { busy = false }
            do {
                let r = try await api.rotateRecoveryCode(passphrase: p)
                await core.sync?.upload(r.change.upload)
                newWords = r.newWords
            } catch {
                self.error = error.fleetMessage
            }
        }
    }
}

/// Settings → Sync (design §7.6): status, conflicts, pin changes.
struct SyncSettings: View {
    @Environment(CoreBridge.self) private var core
    @State private var conflicts: [SyncConflictRow] = []
    @State private var pins: [PinChangeRow] = []
    @State private var error: String?

    var body: some View {
        Form {
            Section("iCloud") {
                if let sync = core.sync {
                    LabeledContent("Transport", value: sync.available ? "CloudKit private database" : "Unavailable (build without iCloud entitlement)")
                    LabeledContent("Last sync", value: sync.lastSync?.formatted() ?? "never")
                    if let e = sync.lastError { Text(e).foregroundStyle(Tone.warn.text) }
                    Button("Sync now") { Task { await sync.cycle(); load() } }
                        .accessibilityIdentifier("sync.syncNow")
                        .disabled(sync.running)
                }
                Text("Records are encrypted on this Mac with the fleet's sync key; Apple stores only ciphertext.")
                    .font(.secondary).foregroundStyle(Color.textMuted)
            }
            Section("Pinned-key changes from other Macs") {
                if pins.isEmpty { Text("None.").foregroundStyle(Color.textMuted) }
                ForEach(pins, id: \.serverId) { p in
                    HStack {
                        Text("\(p.serverName.isEmpty ? p.serverId : p.serverName) — by \(p.changedBy)")
                        Spacer()
                        Button("Reject") { act { try core.api?.rejectPinChange(serverId: p.serverId) } }
                        Button("Accept") { act { try core.api?.confirmPinChange(serverId: p.serverId) } }
                    }
                }
            }
            Section("Edited on two Macs") {
                if conflicts.isEmpty { Text("None.").foregroundStyle(Color.textMuted) }
                ForEach(conflicts, id: \.key) { c in
                    VStack(alignment: .leading, spacing: 6) {
                        Text("\(c.collection): \(c.key)")
                        HStack(alignment: .top) {
                            VStack(alignment: .leading) {
                                Text("This Mac").font(.secondary)
                                Text(c.local).font(.mono(11)).lineLimit(8)
                            }
                            Divider()
                            VStack(alignment: .leading) {
                                Text(c.remoteAuthor).font(.secondary)
                                Text(c.remote).font(.mono(11)).lineLimit(8)
                            }
                        }
                        HStack {
                            Button("Keep mine") { resolve(c, .keepLocal) }
                            Button("Take theirs") { resolve(c, .takeRemote) }
                        }
                    }
                }
            }
            if let error { Text(error).foregroundStyle(Tone.critical.text) }
        }
        .formStyle(.grouped)
        .task(id: core.fleetRevision) { load() }
    }

    private func load() {
        conflicts = (try? core.api?.syncConflicts()) ?? []
        pins = (try? core.api?.pinChanges()) ?? []
    }

    private func act(_ f: () throws -> Void) {
        do { try f(); error = nil } catch { self.error = error.fleetMessage }
        load()
    }

    private func resolve(_ c: SyncConflictRow, _ choice: ConflictChoice) {
        act { try core.api?.syncResolve(collection: c.collection, key: c.key, choice: choice, merged: nil) }
    }
}

/// Server detail: reveal the sudo password (Touch ID via the Keychain
/// item's access control; never typed automatically, design §5.9).
struct SudoPasswordButton: View {
    let serverId: String
    let serverName: String
    @Environment(CoreBridge.self) private var core
    @State private var shown: String?
    @State private var error: String?

    var body: some View {
        Button("Sudo password…") { reveal() }
            .accessibilityIdentifier("server.sudoPassword")
            .popover(isPresented: Binding(get: { shown != nil || error != nil },
                                          set: { if !$0 { shown = nil; error = nil } })) {
                VStack(alignment: .leading, spacing: 8) {
                    if let shown {
                        Text(shown).font(.mono(14)).textSelection(.enabled).privacySensitive()
                        Text("Type it yourself; Fleet never types it.").font(.secondary).foregroundStyle(Color.textMuted)
                    }
                    if let error { Text(error).foregroundStyle(Tone.critical.text) }
                }
                .padding(16)
            }
    }

    private func reveal() {
        Task {
            do {
                if !SyncKeychain.hasSudoPassword(serverId) {
                    // Synced from another Mac but not in this Keychain yet.
                    _ = try core.api?.restoreSudoPassword(serverId: serverId)
                }
                shown = try await SyncKeychain.revealSudoPassword(serverId, serverName: serverName)
            } catch SignerError.Missing {
                error = "No sudo password for this server yet."
            } catch SignerError.Cancelled {
                error = nil
            } catch {
                self.error = error.fleetMessage
            }
        }
    }
}
