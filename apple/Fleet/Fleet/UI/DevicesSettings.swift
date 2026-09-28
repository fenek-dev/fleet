import IOKit.ps
import SwiftUI

/// Settings → Devices (design §5.12, §7.5, Settings.dc.html): roster
/// status, the roster's Macs, and summaries of recovery, AI and sync.
struct DevicesSettings: View {
    @Environment(CoreBridge.self) private var core
    @Environment(AIModel.self) private var ai
    @Environment(\.fleetLocked) private var locked
    var goTo: (SettingsSection) -> Void = { _ in }

    @State private var status: RosterStatusRow?
    @State private var extras: RosterExtrasRow?
    @State private var aiToday: UInt32?
    @State private var error: String?
    @State private var addShown = false
    @State private var revoking: DeviceRow?
    @State private var busy = false
    @State private var lastResult: RosterChangeResult?

    var body: some View {
        SettingsPage("Devices",
                     subtitle: "Each Mac holds its own Secure Enclave keys. All devices are full admins.") {
            Button { addShown = true } label: { Label("Add a Mac", systemImage: "plus") }
                .buttonStyle(.fleetPrimary)
                .disabled(locked)
                .accessibilityIdentifier("devices.addMac")
        } content: {
            if let status {
                rosterCard(status)
                VStack(spacing: 10) {
                    ForEach(status.devices, id: \.id) { deviceRow($0) }
                }
                SettingsCard {
                    HStack {
                        VStack(alignment: .leading, spacing: 2) {
                            Text("Fleet fingerprint").font(.base.weight(.medium)).foregroundStyle(Color.text)
                            Text("Keep this with the recovery code: a recovery shows it for comparison.")
                                .font(.secondary).foregroundStyle(Color.textMuted)
                        }
                        Spacer()
                        Text(status.fleetFingerprint).font(.mono(12)).textSelection(.enabled)
                            .accessibilityIdentifier("devices.fingerprint")
                    }
                }
                if let r = lastResult {
                    SettingsCard {
                        VStack(alignment: .leading, spacing: 4) {
                            Text("Last change").font(.base.weight(.medium))
                            Text("Roster v\(r.version): \(r.current) servers updated, \(r.queued) queued.")
                                .foregroundStyle(Color.textSecondary)
                            ForEach(r.failed, id: \.self) { Text($0).foregroundStyle(Tone.critical.text) }
                        }
                    }
                }
                summaries
            } else if error == nil {
                ProgressView().controlSize(.small)
            }
            FleetAlertsSection()
            if let error { Text(error).foregroundStyle(Tone.critical.text) }
        }
        .task(id: core.fleetRevision) { await load() }
        .sheet(isPresented: $addShown, onDismiss: { Task { await load() } }) { AddMacSheet() }
        .confirmationDialog(
            "Revoke \(revoking?.name ?? "")?",
            isPresented: Binding(get: { revoking != nil }, set: { if !$0 { revoking = nil } })
        ) {
            Button("Revoke with Touch ID", role: .destructive) {
                if let d = revoking { revoke(d) }
            }
            .accessibilityIdentifier("devices.revokeConfirm")
        } message: {
            Text("A new roster goes to every server, its sessions are closed and the sync key is replaced. Offline servers keep trusting it until they reconnect.")
        }
    }

    // MARK: roster

    private var managedCount: Int { core.servers.filter(\.agentPinned).count }

    private func rosterCard(_ s: RosterStatusRow) -> some View {
        let pending = s.pending
        let updated = max(0, managedCount - pending.count)
        return SettingsCard {
            HStack(spacing: 14) {
                Image(systemName: "checkmark.shield").font(.system(size: 18))
                    .foregroundStyle(Color.textSecondary)
                VStack(alignment: .leading, spacing: 2) {
                    Text("Device roster v\(s.version)").font(.base.weight(.medium))
                        .foregroundStyle(Color.text)
                        .accessibilityIdentifier("devices.rosterTitle")
                    Text(rosterSubtitle(updated: updated))
                        .font(.secondary).foregroundStyle(Color.textMuted)
                }
                Spacer()
                if pending.isEmpty {
                    StatusPill(label: "All servers up to date", tone: .ok)
                } else {
                    StatusPill(label: pendingLabel(pending), tone: .warn)
                    Button("Push now") { push() }
                        .buttonStyle(.fleetSecondary)
                        .disabled(busy || locked)
                        .accessibilityIdentifier("devices.pushNow")
                }
            }
        }
    }

    private func rosterSubtitle(updated: Int) -> String {
        var parts: [String] = []
        if let e = extras {
            parts.append("Signed by \(e.signedBy) · \(Self.dateTime(e.issuedAtMs))")
        }
        parts.append("\(updated) of \(managedCount) servers updated")
        return parts.joined(separator: " · ")
    }

    private func pendingLabel(_ p: [PendingServerRow]) -> String {
        let first = p[0].name.isEmpty ? p[0].serverId : p[0].name
        let offline = core.servers.first { $0.id == p[0].serverId }.map { $0.state == .offline || $0.state == .disconnected } ?? false
        let base = p.count == 1 ? "\(first) pending" : "\(first) and \(p.count - 1) more pending"
        return offline && p.count == 1 ? base + " · offline" : base
    }

    private func deviceRow(_ d: DeviceRow) -> some View {
        SettingsCard {
            HStack(spacing: 16) {
                Image(systemName: Self.isLaptop(d) ? "laptopcomputer" : "desktopcomputer")
                    .font(.system(size: 18))
                    .foregroundStyle(Color(hex: 0xc3c6cb))
                    .frame(width: 40, height: 40)
                    .background(Color.control, in: RoundedRectangle(cornerRadius: 10))
                VStack(alignment: .leading, spacing: 4) {
                    HStack(spacing: 8) {
                        Text(d.name).font(.base.weight(.semibold)).foregroundStyle(Color.text)
                        if d.thisMac { Chip(text: "This Mac", tone: .info) }
                    }
                    Text(meta(d)).font(.secondary).foregroundStyle(Color.textMuted)
                }
                Spacer(minLength: 12)
                HStack(spacing: 6) {
                    Chip(text: "Secure Enclave keys")
                    Chip(text: "Full admin")
                }
                Text(activity(d)).font(.secondary).foregroundStyle(Color.textSecondary)
                    .frame(minWidth: 110, alignment: .trailing)
                if !d.thisMac {
                    Button("Revoke") { revoking = d }
                        .buttonStyle(.fleetDestructive)
                        .disabled(busy || locked)
                        .accessibilityIdentifier("devices.revoke")
                }
            }
        }
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier("devices.row.\(d.name)")
    }

    private func meta(_ d: DeviceRow) -> String {
        let added = "Added \(Self.date(d.addedAtMs))"
        return d.addedBy == d.name ? "\(added) · first device" : "\(added) · approved by \(d.addedBy)"
    }

    private func activity(_ d: DeviceRow) -> String {
        if d.thisMac { return "Active now" }
        guard let ms = extras?.devices.first(where: { $0.deviceId == d.id })?.lastActiveMs else {
            return "No activity seen"
        }
        return "Active " + Date(timeIntervalSince1970: Double(ms) / 1000)
            .formatted(.relative(presentation: .named))
    }

    static func isLaptop(_ d: DeviceRow) -> Bool {
        if d.thisMac { return HostModel.isLaptop }
        let n = d.name.lowercased()
        return n.contains("macbook") || n.contains("laptop") || n.contains("air") || n.contains("book")
    }

    // MARK: summaries (Recovery, AI agents, Sync)

    private var summaries: some View {
        VStack(spacing: 14) {
            SectionCard(icon: "key", title: "Recovery code", pill: recoveryPill) {
                Text("24 words on paper, plus an optional passphrase. \(recoveryCreated)")
                    .font(.base).foregroundStyle(Color.textSecondary)
                Button("Run recovery drill") { goTo(.recovery) }
                    .buttonStyle(.fleetSecondary)
                    .accessibilityIdentifier("devices.recoveryDrill")
            }
            SectionCard(icon: "sparkles", title: "AI agents",
                        pill: ai.paused ? ("Paused", Tone.warn) : ("Full access", Tone.info)) {
                Text(aiSummary).font(.base).foregroundStyle(Color.textSecondary)
                Text("Keys, roster and policies always need Touch ID.")
                    .font(.secondary).foregroundStyle(Color.textMuted)
                Button { ai.setPaused(!ai.paused) } label: {
                    Label(ai.paused ? "Resume AI agents" : "Pause AI agents",
                          systemImage: ai.paused ? "play" : "pause")
                }
                .buttonStyle(.fleetSecondary)
                .accessibilityIdentifier("devices.aiPause")
            }
            SectionCard(icon: "icloud", title: "Sync", pill: syncPill) {
                Text("iCloud, end-to-end encrypted with a key only your Macs hold. Apple stores ciphertext only.")
                    .font(.base).foregroundStyle(Color.textSecondary)
                Text(syncedList + ".").font(.secondary).foregroundStyle(Color.textMuted)
                Button("Sync now") { Task { await core.sync?.cycle() } }
                    .buttonStyle(.fleetSecondary)
                    .disabled(core.sync?.running ?? false)
                    .accessibilityIdentifier("devices.syncNow")
            }
        }
    }

    private var recoveryPill: (String, Tone) {
        guard let ms = extras?.lastDrillMs else { return ("Never tested", Tone.warn) }
        return ("Tested " + Date(timeIntervalSince1970: Double(ms) / 1000)
            .formatted(.relative(presentation: .named)), Tone.ok)
    }

    private var recoveryCreated: String {
        extras.map { "Created \(Self.date($0.recoveryCreatedMs))." } ?? ""
    }

    private var aiSummary: String {
        AIActivity.summary(clients: ai.clients, actionsToday: aiToday)
    }

    private var syncPill: (String, Tone) {
        guard let sync = core.sync, sync.available else { return ("Unavailable", Tone.neutral) }
        guard let last = sync.lastSync else { return ("Never synced", Tone.warn) }
        return (last.formatted(.relative(presentation: .named)), Tone.ok)
    }

    private var syncedList: String {
        let c = syncedCollections()
        guard let last = c.last, c.count > 1 else { return c.first ?? "" }
        return c.dropLast().joined(separator: ", ") + " and " + last.lowercased()
    }

    // MARK: actions

    private func load() async {
        guard let api = core.api else { return }
        do {
            status = try api.rosterStatus()
            error = nil
        } catch {
            self.error = error.fleetMessage
        }
        extras = await Task.detached { try? api.rosterExtras() }.value
        aiToday = await AIActivity.actionsToday(api)
        ai.reloadClients()
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
                await load()
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
                await load()
            } catch {
                self.error = error.fleetMessage
            }
        }
    }

    static func date(_ ms: UInt64) -> String {
        Date(timeIntervalSince1970: Double(ms) / 1000).formatted(date: .abbreviated, time: .omitted)
    }

    static func dateTime(_ ms: UInt64) -> String {
        let d = Date(timeIntervalSince1970: Double(ms) / 1000)
        if Calendar.current.isDateInToday(d) {
            return "today " + d.formatted(date: .omitted, time: .shortened)
        }
        return d.formatted(date: .abbreviated, time: .shortened)
    }
}

/// Whether this Mac is a laptop: it has a battery.
enum HostModel {
    static let isLaptop: Bool = {
        let info = IOPSCopyPowerSourcesInfo().takeRetainedValue()
        let list = IOPSCopyPowerSourcesList(info).takeRetainedValue() as [CFTypeRef]
        return !list.isEmpty
    }()
}

/// Fleet alerts (roster, recovery, sync) with their one-click actions.
struct FleetAlertsSection: View {
    @Environment(CoreBridge.self) private var core
    @State private var error: String?

    var body: some View {
        if !core.fleetAlerts.isEmpty || error != nil {
            VStack(alignment: .leading, spacing: 10) {
                Text("Roster and sync alerts").font(Typeface.ui(14, .semibold)).foregroundStyle(Color.text)
                ForEach(Array(core.fleetAlerts.enumerated()), id: \.offset) { _, a in
                    SettingsCard {
                        VStack(alignment: .leading, spacing: 6) {
                            HStack {
                                StatusPill(label: Self.label(a.kind), tone: Self.tone(a.kind))
                                Text(a.title)
                            }
                            Text(a.detail).font(.secondary).foregroundStyle(Color.textSecondary)
                            HStack {
                                if a.kind == .macAdded, let id = a.deviceId {
                                    Button("Revoke this Mac") { revoke(id, a) }
                                        .buttonStyle(.fleetDestructive)
                                }
                                if a.kind == .recoveryPending, let s = a.serverId, let h = a.pendingHash {
                                    Button("Veto with Touch ID") { veto(s, h, a) }
                                        .buttonStyle(.fleetDestructive)
                                }
                                Spacer()
                                Button("Dismiss") { core.dismissFleetAlert(a) }
                                    .buttonStyle(.fleetSecondary)
                            }
                        }
                    }
                }
                if let error { Text(error).foregroundStyle(Tone.critical.text) }
            }
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
