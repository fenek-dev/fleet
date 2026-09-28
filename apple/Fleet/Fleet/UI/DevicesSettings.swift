import SwiftUI

/// Settings → Devices (design §5.12, §7.5): the roster's Macs, servers still
/// waiting for the latest roster, roster alerts, add and revoke.
struct DevicesSettings: View {
    @Environment(CoreBridge.self) private var core
    @State private var status: RosterStatusRow?
    @State private var error: String?
    @State private var addShown = false
    @State private var revoking: DeviceRow?
    @State private var busy = false
    @State private var lastResult: RosterChangeResult?

    var body: some View {
        Form {
            if let status {
                Section("Macs (roster v\(status.version), epoch \(status.epoch))") {
                    ForEach(status.devices, id: \.id) { d in
                        HStack {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(d.name + (d.thisMac ? " (this Mac)" : ""))
                                Text("Added \(Self.date(d.addedAtMs)) by \(d.addedBy)")
                                    .font(.secondary).foregroundStyle(Color.textMuted)
                            }
                            Spacer()
                            if !d.thisMac {
                                Button("Revoke…", role: .destructive) { revoking = d }
                                    .disabled(busy)
                            }
                        }
                    }
                    Button("Add Mac…") { addShown = true }
                    LabeledContent("Fleet fingerprint") {
                        Text(status.fleetFingerprint).font(.mono(12)).textSelection(.enabled)
                    }
                    .help("Keep this with the recovery code: a recovery shows it for comparison.")
                }
                Section("Servers waiting for the latest roster") {
                    if status.pending.isEmpty {
                        Text("All servers are up to date.").foregroundStyle(Color.textMuted)
                    } else {
                        Text("Until they get it, these servers still trust any Mac removed since.")
                            .font(.secondary).foregroundStyle(Tone.warn.text)
                        ForEach(status.pending, id: \.serverId) { p in
                            LabeledContent(p.name.isEmpty ? p.serverId : p.name,
                                           value: p.seenVersion.map { "has v\($0)" } ?? "not confirmed")
                        }
                        Button("Push now") { push() }.disabled(busy)
                    }
                }
            }
            if let r = lastResult {
                Section("Last change") {
                    Text("Roster v\(r.version): \(r.current) servers updated, \(r.queued) queued.")
                    ForEach(r.failed, id: \.self) { Text($0).foregroundStyle(Tone.critical.text) }
                }
            }
            FleetAlertsSection()
            if let error {
                Text(error).foregroundStyle(Tone.critical.text)
            }
        }
        .formStyle(.grouped)
        .task(id: core.fleetRevision) { load() }
        .sheet(isPresented: $addShown, onDismiss: load) { AddMacSheet() }
        .confirmationDialog(
            "Revoke \(revoking?.name ?? "")?",
            isPresented: Binding(get: { revoking != nil }, set: { if !$0 { revoking = nil } })
        ) {
            Button("Revoke with Touch ID", role: .destructive) {
                if let d = revoking { revoke(d) }
            }
        } message: {
            Text("A new roster goes to every server, its sessions are closed and the sync key is replaced. Offline servers keep trusting it until they reconnect.")
        }
    }

    private func load() {
        do {
            status = try core.api?.rosterStatus()
            error = nil
        } catch {
            self.error = error.fleetMessage
        }
    }

    private func revoke(_ d: DeviceRow) {
        guard let api = core.api else { return }
        busy = true
        Task {
            defer { busy = false }
            do {
                let r = try await api.revokeMac(deviceId: d.id)
                await core.sync?.upload(r.upload, delete: r.delete)
                lastResult = r
                load()
            } catch {
                self.error = error.fleetMessage
            }
        }
    }

    private func push() {
        guard let api = core.api else { return }
        busy = true
        Task {
            defer { busy = false }
            do {
                lastResult = try await api.pushPendingRosters()
                load()
            } catch {
                self.error = error.fleetMessage
            }
        }
    }

    static func date(_ ms: UInt64) -> String {
        Date(timeIntervalSince1970: Double(ms) / 1000).formatted(date: .abbreviated, time: .omitted)
    }
}

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
                HStack { Spacer(); Button("Done") { dismiss() }.keyboardShortcut(.defaultAction) }
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
                    Spacer()
                    Button("Codes match — Approve") { approve(prompt) }
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
                    HStack {
                        Spacer()
                        Button("Continue") { begin(pasted) }
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

/// Fleet alerts with their one-click actions.
struct FleetAlertsSection: View {
    @Environment(CoreBridge.self) private var core
    @State private var error: String?

    var body: some View {
        Section("Roster and sync alerts") {
            if core.fleetAlerts.isEmpty {
                Text("None.").foregroundStyle(Color.textMuted)
            }
            ForEach(Array(core.fleetAlerts.enumerated()), id: \.offset) { _, a in
                VStack(alignment: .leading, spacing: 4) {
                    HStack {
                        StatusPill(label: Self.label(a.kind), tone: Self.tone(a.kind))
                        Text(a.title)
                    }
                    Text(a.detail).font(.secondary).foregroundStyle(Color.textSecondary)
                    HStack {
                        if a.kind == .macAdded, let id = a.deviceId {
                            Button("Revoke this Mac", role: .destructive) { revoke(id, a) }
                        }
                        if a.kind == .recoveryPending, let s = a.serverId, let h = a.pendingHash {
                            Button("Veto with Touch ID", role: .destructive) { veto(s, h, a) }
                        }
                        Spacer()
                        Button("Dismiss") { core.dismissFleetAlert(a) }
                    }
                }
            }
            if let error { Text(error).foregroundStyle(Tone.critical.text) }
        }
    }

    private func revoke(_ id: String, _ a: FleetAlertRow) {
        guard let api = core.api else { return }
        Task {
            do {
                let r = try await api.revokeMac(deviceId: id)
                await core.sync?.upload(r.upload, delete: r.delete)
                core.dismissFleetAlert(a)
            } catch { self.error = error.fleetMessage }
        }
    }

    private func veto(_ server: String, _ hash: String, _ a: FleetAlertRow) {
        guard let api = core.api else { return }
        Task {
            do {
                try await api.vetoRecovery(serverId: server, pendingHash: hash)
                core.dismissFleetAlert(a)
            } catch { self.error = error.fleetMessage }
        }
    }

    static func tone(_ k: FleetAlertKind) -> Tone {
        switch k {
        case .removedFromFleet, .recoveryPending, .rosterPushFailed, .syncRejected, .rosterFork, .auditTampered: .critical
        case .macAdded, .macRevoked, .rosterChanged, .pinChange: .warn
        case .syncConflict, .waitingForRoster, .recoveryVetoed: .info
        }
    }

    static func label(_ k: FleetAlertKind) -> String {
        switch k {
        case .macAdded: "Mac added"
        case .macRevoked: "Mac revoked"
        case .rosterChanged: "Roster"
        case .recoveryPending: "Recovery"
        case .recoveryVetoed: "Vetoed"
        case .removedFromFleet: "Removed"
        case .waitingForRoster: "Waiting"
        case .rosterPushFailed: "Push failed"
        case .pinChange: "Pins"
        case .syncConflict: "Conflict"
        case .syncRejected: "Sync"
        case .rosterFork: "Roster fork"
        case .auditTampered: "Audit log"
        }
    }
}
