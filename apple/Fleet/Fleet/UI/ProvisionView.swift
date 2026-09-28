import SwiftUI

/// Provisioning wizard (design §9.1, mockup `Provision.dc.html`):
/// Connect (add server, host key, agent) → Profile → Review plan →
/// Apply (phases, auto-revert countdown) → Verify (score before/after).
/// The core keeps the wizard state per server, so a failed or
/// interrupted run resumes where it stopped.
struct ProvisionView: View {
    @Environment(CoreBridge.self) private var core
    @Binding var selection: NavItem?

    @State private var serverId: String?
    @State private var state: ProvisionStateRow?
    @State private var form = ProvisionForm()
    @State private var editingProfile = false
    @State private var running = false
    @State private var run = ProvisionRun()
    @State private var error: String?
    @State private var addSheet: AddSheet?
    @State private var cloudInitShown = false
    @State private var exportId = ""
    /// Agent-only servers (design §5.4) refuse `profile.apply`: hardening
    /// is disabled here until the operator switches to Managed.
    @State private var securityMode: SecurityModeStatus = .unknown

    private struct AddSheet: Identifiable {
        let id = UUID()
        let existing: ServerRow?
    }

    private enum Stage: Int, CaseIterable {
        case connect, profile, review, apply, verify
        var label: String {
            switch self {
            case .connect: "Connect"
            case .profile: "Profile"
            case .review: "Review plan"
            case .apply: "Apply"
            case .verify: "Verify"
            }
        }
    }

    private var server: ServerRow? { core.servers.first { $0.id == serverId } }

    private var stage: Stage {
        guard let server, server.agentPinned else { return .connect }
        guard let state, !editingProfile else { return .profile }
        switch state.step {
        case .pushRoster, .auditBefore, .plan: return running ? .review : .profile
        case .review: return .review
        case .done: return .verify
        default: return .apply
        }
    }

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider().overlay(Color.divider)
            ScrollView {
                VStack(alignment: .leading, spacing: 20) {
                    StepsBar(labels: Stage.allCases.map(\.label), current: stage.rawValue)
                    // Apply shows its own failed step and Resume.
                    if let error = error ?? (stage == .apply ? nil : state?.lastError) {
                        Text(error).font(.base).foregroundStyle(Tone.critical.text)
                            .textSelection(.enabled)
                    }
                    switch stage {
                    case .connect: connect
                    case .profile: profile
                    case .review: review
                    case .apply: apply
                    case .verify: verify
                    }
                }
                .padding(24)
                .frame(maxWidth: 1100, alignment: .leading)
            }
        }
        .background(Color.window)
        .navigationTitle("Provisioning")
        .sheet(item: $addSheet, onDismiss: {
            core.reload()
            refreshSecurityMode()
        }) { s in
            AddServerSheet(existing: s.existing)
        }
        .sheet(isPresented: $cloudInitShown) {
            CloudInitExportSheet(adminUser: form.adminUser)
        }
        .onChange(of: serverId) { _, _ in load() }
        .onChange(of: server?.state) { _, new in
            // The connection just came back: `securityMode` needs a live
            // session to resolve, so re-check rather than sit on `Unknown`.
            if new == .ready { refreshSecurityMode() }
        }
        .onAppear(perform: pickInProgress)
    }

    // MARK: header

    private var header: some View {
        HStack(alignment: .firstTextBaseline) {
            VStack(alignment: .leading, spacing: 4) {
                Text("Provision a server").font(.sectionTitle)
                Text(subtitle).font(.secondary).foregroundStyle(Color.textMuted)
            }
            Spacer()
            Button("Export as cloud-init") { cloudInitShown = true }
        }
        .padding(.horizontal, 24)
        .padding(.vertical, 16)
        .background(Color.header)
    }

    private var subtitle: String {
        guard let s = server else { return "Choose or add a fresh Debian/Ubuntu server" }
        let key = s.hostKeyPinned ? "host key pinned" : "host key not confirmed"
        let agent = s.agentPinned ? " · agent installed" : ""
        return "Connected to \(s.host) as \(s.user) · \(key)\(agent)"
    }

    // MARK: connect

    private var connect: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Fleet connects with the provider's access and this Mac's SSH key (added to the provider user's authorized_keys, or by a Fleet cloud-init file), pins the host key, installs the agent, then applies the profile phase by phase.")
                .font(.base).foregroundStyle(Color.textSecondary)
            VStack(alignment: .leading, spacing: 10) {
                Picker("Server", selection: $serverId) {
                    Text("Choose…").tag(String?.none)
                    ForEach(core.servers, id: \.id) { s in
                        Text("\(s.name) (\(s.host))").tag(Optional(s.id))
                    }
                }
                .frame(maxWidth: 420)
                HStack {
                    Button("Add server…") { addSheet = AddSheet(existing: nil) }
                    if let s = server, !s.agentPinned {
                        Button(s.hostKeyPinned ? "Install agent…" : "Confirm host key and install…") {
                            addSheet = AddSheet(existing: s)
                        }
                        .buttonStyle(.borderedProminent).tint(.accent)
                    }
                }
            }
            .card()
            if let s = server, !s.hostKeyPinned {
                VStack(alignment: .leading, spacing: 8) {
                    Text("Created from a Fleet cloud-init file?").font(.system(size: 13, weight: .semibold))
                    Text("Its host key was generated and pinned on this Mac when you exported it, so nothing is trusted on first use.")
                        .font(.secondary).foregroundStyle(Color.textSecondary)
                    HStack {
                        TextField("Export id (ci_…)", text: $exportId)
                            .font(.mono(12)).frame(maxWidth: 260)
                        if !CloudInitExports.recent.isEmpty {
                            Menu("Recent") {
                                ForEach(CloudInitExports.recent, id: \.id) { e in
                                    Button("\(e.label) · \(e.id)") { exportId = e.id }
                                }
                            }
                            .frame(width: 90)
                        }
                        Button("Pin host key") { pinExport(s) }
                            .disabled(exportId.isEmpty)
                    }
                }
                .card()
            }
        }
    }

    // MARK: profile

    private var profile: some View {
        HStack(alignment: .top, spacing: 20) {
            VStack(alignment: .leading, spacing: 16) {
                ProfileFormView(form: $form, groups: core.groups)
                if securityMode == .agentOnly {
                    Text("This server is Agent only: Fleet won't apply hardening here. Switch it to Managed from the server's Overview tab first.")
                        .font(.secondary).foregroundStyle(Tone.warn.text)
                } else if securityMode == .unknown {
                    Text("This server's security mode is unknown (refresh the connection). Hardening stays disabled until it's confirmed Managed.")
                        .font(.secondary).foregroundStyle(Tone.warn.text)
                }
                HStack {
                    if form.isCustom {
                        Text("Source ranges or a reboot window make this a custom profile: each phase needs Touch ID.")
                            .font(.secondary).foregroundStyle(Color.textMuted)
                    }
                    Spacer()
                    if state != nil {
                        Button("Back") { editingProfile = false }
                    }
                    Button("Review plan") { begin() }
                        .buttonStyle(.borderedProminent).tint(.accent)
                        .disabled(running || form.name.isEmpty || form.adminUser.isEmpty
                                  || securityMode != .managed)
                }
            }
            .frame(maxWidth: .infinity)
            PlanPreview(state: state, running: running)
                .frame(width: 360)
        }
    }

    // MARK: review

    private var review: some View {
        HStack(alignment: .top, spacing: 20) {
            VStack(alignment: .leading, spacing: 12) {
                if running && state?.step != .review {
                    progressList
                } else if let state {
                    Text("\(state.plan.count) changes").font(.system(size: 15, weight: .semibold))
                    ForEach(Indexed.wrap(state.plan)) { c in PlanChangeView(change: c.value) }
                    if state.plan.isEmpty {
                        Text("Nothing to change: the server already matches the profile.")
                            .foregroundStyle(Color.textSecondary)
                    }
                    HStack {
                        Button("Edit profile") { editingProfile = true }
                        Button("Cancel provisioning", role: .destructive) { cancel() }
                        Spacer()
                        Button("Apply") { approve() }
                            .buttonStyle(.borderedProminent).tint(.accent)
                            .disabled(running || securityMode != .managed)
                    }
                }
            }
            .frame(maxWidth: .infinity, alignment: .topLeading)
            PlanPreview(state: state, running: running).frame(width: 360)
        }
    }

    // MARK: apply

    private var apply: some View {
        VStack(alignment: .leading, spacing: 16) {
            progressList
            if let deadline = run.revertDeadlineMs ?? state?.pendingDeadlineMs,
               state?.step == .confirmAccess || run.current == .confirmAccess {
                RevertCountdown(deadlineMs: deadline)
            }
            if let e = state?.lastError, !running {
                VStack(alignment: .leading, spacing: 8) {
                    Text(e).font(.base).foregroundStyle(Tone.critical.text).textSelection(.enabled)
                    HStack {
                        Button("Resume") { advance() }
                            .buttonStyle(.borderedProminent).tint(.accent)
                        Button("Cancel provisioning", role: .destructive) { cancel() }
                    }
                }
                .card()
            } else if !running {
                Button("Resume") { advance() }.buttonStyle(.borderedProminent).tint(.accent)
            }
            if !(state?.modules.isEmpty ?? true) {
                VStack(alignment: .leading, spacing: 6) {
                    Text("Modules").font(.system(size: 13, weight: .semibold))
                    ForEach(Indexed.wrap(state?.modules ?? [])) { m in ModuleLine(m: m.value) }
                }
                .card()
            }
        }
    }

    private static let applySteps: [(ProvisionStepRow, String)] = [
        (.pushRoster, "Push the roster"),
        (.auditBefore, "Audit the current state"),
        (.plan, "Plan"),
        (.accounts, "Phase 1: admin user, keys, sudo password"),
        (.verifyAdmin, "Verify the admin login (second connection)"),
        (.access, "Phase 2: SSH and firewall (auto-revert armed)"),
        (.confirmAccess, "Confirm from a fresh connection"),
        (.system, "Phase 3: system hardening and roles"),
        (.auditAfter, "Audit the result"),
        (.addToFleet, "Add to the fleet"),
    ]

    private var progressList: some View {
        let current = running ? (run.current ?? state?.step) : state?.step
        let order = Self.applySteps.map(\.0)
        let idx = current.flatMap { c in order.firstIndex(of: c) } ?? (state?.step == .done ? order.count : 0)
        return VStack(alignment: .leading, spacing: 8) {
            ForEach(Self.applySteps.indices, id: \.self) { i in
                let (_, label) = Self.applySteps[i]
                HStack(spacing: 10) {
                    Group {
                        if i < idx {
                            Image(systemName: "checkmark.circle.fill").foregroundStyle(Tone.ok.text)
                        } else if i == idx && running {
                            ProgressView().controlSize(.small)
                        } else if i == idx && state?.lastError != nil {
                            Image(systemName: "xmark.circle").foregroundStyle(Tone.critical.text)
                        } else {
                            Image(systemName: "circle").foregroundStyle(Color.textMuted)
                        }
                    }
                    .frame(width: 18)
                    Text(label).foregroundStyle(i <= idx ? Color.text : Color.textMuted)
                    if i == idx, running, let w = run.waiting {
                        Text("waiting for the package manager (\(w))")
                            .font(.secondary).foregroundStyle(Tone.warn.text)
                    }
                }
            }
        }
        .card()
    }

    // MARK: verify

    private var verify: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack(spacing: 24) {
                ScoreBox(title: "Before", score: state?.scoreBefore)
                Image(systemName: "arrow.right").foregroundStyle(Color.textMuted)
                ScoreBox(title: "After", score: state?.scoreAfter)
                if let p = state?.profileScore {
                    ScoreBox(title: "Profile (with roles)", score: p)
                }
            }
            Text("The server is hardened and in the fleet. SSH and firewall changes were confirmed from a fresh connection as \(state?.choice.adminUser ?? "the admin"); the sudo password is in the Keychain (reveal it in the server's Overview, behind Touch ID).")
                .font(.base).foregroundStyle(Color.textSecondary)
            HStack {
                Button("Provision another") {
                    serverId = nil
                    state = nil
                    form = ProvisionForm()
                }
                Spacer()
                if let id = serverId {
                    Button("Open server") { selection = .server(id) }
                        .buttonStyle(.borderedProminent).tint(.accent)
                }
            }
        }
    }

    // MARK: actions

    private func pickInProgress() {
        guard serverId == nil, let api = core.api else { return }
        if let first = try? api.provisionInProgress().first {
            serverId = first.serverId
        }
    }

    /// A live round trip (`agent.health`), so it needs a Task; guarded
    /// against a stale answer landing after the operator picked another
    /// server. Called on server change, after the install sheet closes
    /// (install can just have set the mode) and when the connection comes
    /// back up (`securityMode` needs a live session to resolve at all).
    private func refreshSecurityMode() {
        guard let api = core.api, let id = serverId else { return }
        Task {
            let mode = (try? await api.securityMode(serverId: id)) ?? .unknown
            if id == serverId { securityMode = mode }
        }
    }

    private func load() {
        error = nil
        run = ProvisionRun()
        editingProfile = false
        securityMode = .unknown
        refreshSecurityMode()
        guard let api = core.api, let id = serverId else {
            state = nil
            return
        }
        do {
            state = try api.provisionState(serverId: id)
        } catch {
            self.error = error.fleetMessage
        }
        if let st = state {
            form = ProvisionForm(st.choice)
        } else if let s = server {
            form.name = s.name
            form.groupId = s.groupId
            form.tags = s.tags.joined(separator: ", ")
            if form.adminUser.isEmpty { form.adminUser = s.user == "root" ? "ops" : s.user }
        }
    }

    private func pinExport(_ s: ServerRow) {
        guard let api = core.api else { return }
        do {
            try api.pinCloudInitHostKey(serverId: s.id, exportId: exportId.trimmingCharacters(in: .whitespaces))
            core.reload()
            error = nil
        } catch {
            self.error = error.fleetMessage
        }
    }

    private func begin() {
        guard let api = core.api, let id = serverId else { return }
        error = nil
        do {
            state = try api.provisionBegin(serverId: id, choice: form.row)
            editingProfile = false
            advance()
        } catch {
            self.error = error.fleetMessage
        }
    }

    private func approve() {
        guard let api = core.api, let id = serverId, let hash = state?.planHash else { return }
        do {
            state = try api.provisionApprovePlan(serverId: id, planHash: hash)
            advance()
        } catch {
            self.error = error.fleetMessage
        }
    }

    private func advance() {
        guard let api = core.api, let id = serverId else { return }
        error = nil
        let run = ProvisionRun()
        self.run = run
        running = true
        let relay = ProvisionRelay { e in Task { @MainActor in run.apply(e) } }
        Task {
            do {
                state = try await api.provisionAdvance(serverId: id, listener: relay)
            } catch {
                // The core saved the failed step and its error.
                state = (try? api.provisionState(serverId: id)) ?? state
                if state?.lastError == nil { self.error = error.fleetMessage }
            }
            running = false
            core.reload()
        }
    }

    private func cancel() {
        guard let api = core.api, let id = serverId else { return }
        try? api.provisionCancel(serverId: id)
        state = nil
    }
}

// MARK: - form

struct ProvisionForm: Equatable {
    var name = ""
    var groupId: String?
    var tags = ""
    var level: ProfileLevelRow = .baseline
    var docker = false
    var web = false
    var game = false
    var adminUser = ""
    var sshFromAnywhere = true
    var allowFrom = ""
    var rebootWindow = RebootChoice.never

    enum RebootChoice: String, CaseIterable, Identifiable {
        case sunday = "Sun 04:00-05:00 UTC"
        case daily = "Daily 03:00-04:00 UTC"
        case never = "Never reboot automatically"
        var id: String { rawValue }
    }

    init() {}

    init(_ c: ProvisionChoiceRow) {
        name = c.name
        groupId = c.groupId
        tags = c.tags.joined(separator: ", ")
        level = c.level
        docker = c.roles.contains(.docker)
        web = c.roles.contains(.web)
        game = c.roles.contains(.game)
        adminUser = c.adminUser
        sshFromAnywhere = c.allowFrom.isEmpty
        allowFrom = c.allowFrom.joined(separator: ", ")
        rebootWindow = RebootChoice(rawValue: c.rebootWindow ?? "") ?? .never
    }

    private static func list(_ s: String) -> [String] {
        s.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
    }

    var ranges: [String] { sshFromAnywhere ? [] : Self.list(allowFrom) }

    var isCustom: Bool { !ranges.isEmpty || rebootWindow != .never }

    var row: ProvisionChoiceRow {
        var roles: [ProfileRoleRow] = []
        if docker { roles.append(.docker) }
        if web { roles.append(.web) }
        if game { roles.append(.game) }
        return ProvisionChoiceRow(
            level: level, roles: roles, adminUser: adminUser.trimmingCharacters(in: .whitespaces),
            allowFrom: ranges, rebootWindow: rebootWindow == .never ? nil : rebootWindow.rawValue,
            name: name.trimmingCharacters(in: .whitespaces), groupId: groupId, tags: Self.list(tags))
    }
}

private struct ProfileFormView: View {
    @Binding var form: ProvisionForm
    let groups: [GroupRow]

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            section("Server") {
                HStack(spacing: 12) {
                    TextField("Name", text: $form.name)
                    Picker("Group", selection: $form.groupId) {
                        Text("None").tag(String?.none)
                        ForEach(groups, id: \.id) { Text($0.name).tag(Optional($0.id)) }
                    }
                    TextField("Tags", text: $form.tags, prompt: Text("web, docker, eu-central"))
                }
            }
            section("Security profile") {
                Picker("", selection: $form.level) {
                    VStack(alignment: .leading) {
                        Text("Baseline")
                        Text("Safe on any server. Key-only SSH, default-drop firewall, kernel and service hardening.")
                            .font(.secondary).foregroundStyle(Color.textSecondary)
                    }
                    .tag(ProfileLevelRow.baseline)
                    VStack(alignment: .leading) {
                        Text("Strict")
                        Text("CIS Level 2 style. Adds noexec /tmp and immutable audit rules; may break some installers.")
                            .font(.secondary).foregroundStyle(Color.textSecondary)
                    }
                    .tag(ProfileLevelRow.strict)
                }
                .pickerStyle(.radioGroup)
                .labelsHidden()
            }
            section("Roles") {
                role("Docker / Compose", "Ports bind to localhost unless you publish them.", $form.docker)
                role("Web / reverse proxy", "TLS, security headers, scanner bans.", $form.web)
                role("Game server", "Pick a template later: ports, backups, RCON.", $form.game)
            }
            section("Access") {
                TextField("Admin user", text: $form.adminUser, prompt: Text("ops"))
                    .frame(maxWidth: 260)
                Picker("SSH reachable from", selection: $form.sshFromAnywhere) {
                    Text("Anywhere, rate-limited").tag(true)
                    Text("Only these ranges").tag(false)
                }
                .pickerStyle(.radioGroup)
                if !form.sshFromAnywhere {
                    TextField("CIDR ranges", text: $form.allowFrom, prompt: Text("203.0.113.0/24, 2001:db8::/32"))
                        .font(.mono(12))
                }
                Picker("Reboot window", selection: $form.rebootWindow) {
                    ForEach(ProvisionForm.RebootChoice.allCases) { Text($0.rawValue).tag($0) }
                }
                .frame(maxWidth: 360)
            }
        }
    }

    private func role(_ title: String, _ detail: String, _ on: Binding<Bool>) -> some View {
        Toggle(isOn: on) {
            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                Text(detail).font(.secondary).foregroundStyle(Color.textSecondary)
            }
        }
        .toggleStyle(.checkbox)
    }

    private func section(_ title: String, @ViewBuilder _ content: () -> some View) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(title).font(.system(size: 13, weight: .semibold))
            content()
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .card()
    }
}

// MARK: - pieces

private struct StepsBar: View {
    let labels: [String]
    let current: Int

    var body: some View {
        HStack(spacing: 8) {
            ForEach(labels.indices, id: \.self) { i in
                HStack(spacing: 6) {
                    ZStack {
                        Circle().fill(i < current ? Tone.ok.bg : i == current ? Color.accent : Color.control)
                            .frame(width: 20, height: 20)
                        if i < current {
                            Image(systemName: "checkmark").font(.system(size: 10, weight: .bold))
                                .foregroundStyle(Tone.ok.text)
                        } else {
                            Text("\(i + 1)").font(.caption11).foregroundStyle(Color.text)
                        }
                    }
                    Text(labels[i])
                        .font(.system(size: 13, weight: i == current ? .semibold : .medium))
                        .foregroundStyle(i > current ? Color.textMuted : Color.text)
                }
                .accessibilityElement(children: .combine)
                .accessibilityAddTraits(i == current ? .isSelected : [])
                if i < labels.count - 1 {
                    Rectangle().fill(Color.border).frame(width: 28, height: 1)
                }
            }
        }
    }
}

private struct PlanPreview: View {
    let state: ProvisionStateRow?
    let running: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text("Plan preview").font(.system(size: 13, weight: .semibold))
                Spacer()
                if let s = state, s.planHash != nil {
                    Text("\(s.plan.count) changes").font(.secondary).foregroundStyle(Color.textMuted)
                }
            }
            if let s = state, s.planHash != nil {
                ForEach(s.planGroups, id: \.label) { g in
                    HStack {
                        Text(g.label)
                        Spacer()
                        Text("\(g.changes)").font(.mono(12)).foregroundStyle(Color.textSecondary)
                    }
                    .font(.base)
                }
            } else {
                Text(running ? "Planning…" : "Review the plan to see every change first.")
                    .font(.secondary).foregroundStyle(Color.textMuted)
            }
            if let before = state?.scoreBefore {
                HStack {
                    Text("Hardening score").font(.secondary)
                    Spacer()
                    Text("now").font(.caption11).foregroundStyle(Color.textMuted)
                    Text("\(before)").font(.system(size: 15, weight: .semibold))
                    if let after = state?.scoreAfter {
                        Image(systemName: "arrow.right").foregroundStyle(Color.textMuted)
                        Text("\(after)").font(.system(size: 15, weight: .semibold))
                            .foregroundStyle(Tone.ok.text)
                    }
                }
                ProgressView(value: Double(state?.scoreAfter ?? before), total: 100)
            }
            HStack(alignment: .top, spacing: 8) {
                Image(systemName: "checkmark.shield").foregroundStyle(Tone.ok.text)
                Text("Lockout-safe: root and password login are turned off only after a second connection proves the admin login works. SSH and firewall changes revert unless confirmed.")
                    .font(.secondary).foregroundStyle(Color.textSecondary)
            }
        }
        .card()
    }
}

private struct PlanChangeView: View {
    let change: PlanChangeRow
    @State private var open = false

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Button { open.toggle() } label: {
                HStack(spacing: 8) {
                    Image(systemName: open ? "chevron.down" : "chevron.right")
                        .font(.caption11).foregroundStyle(Color.textMuted)
                    Text(change.module).font(.mono(12)).foregroundStyle(Color.textSecondary)
                        .frame(width: 150, alignment: .leading)
                    Text(change.description).foregroundStyle(Color.text)
                    Spacer()
                    if change.autoRevert { StatusPill(label: "auto-revert", tone: .info) }
                }
            }
            .buttonStyle(.plain)
            if open && !change.diff.isEmpty {
                Text(change.diff).font(.mono(11)).foregroundStyle(Color.textSecondary)
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(8)
                    .background(Color.track, in: RoundedRectangle(cornerRadius: 6))
            }
        }
        .font(.base)
        .card(padding: 10)
    }
}

private struct ModuleLine: View {
    let m: ModuleResultRow

    var body: some View {
        HStack(spacing: 10) {
            StatusPill(label: m.outcome.lowercased(), tone: tone)
            Text(m.module).font(.mono(12)).frame(width: 160, alignment: .leading)
            Text(m.detail).font(.secondary).foregroundStyle(Color.textSecondary).lineLimit(2)
        }
    }

    private var tone: Tone {
        switch m.outcome {
        case "Applied": .ok
        case "Failed": .critical
        case "Skipped": .neutral
        default: .info
        }
    }
}

struct ScoreBox: View {
    let title: String
    let score: UInt8?

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title).font(.secondary).foregroundStyle(Color.textMuted)
            Text(score.map { "\($0)" } ?? "–").font(.system(size: 28, weight: .semibold))
                .foregroundStyle(tone.text)
        }
        .frame(minWidth: 110, alignment: .leading)
        .card(padding: 12)
    }

    private var tone: Tone {
        guard let s = score else { return .neutral }
        return s >= 85 ? .ok : s >= 60 ? .warn : .critical
    }
}

/// Seconds until the SSH/firewall phase reverts unless confirmed.
private struct RevertCountdown: View {
    let deadlineMs: UInt64

    var body: some View {
        TimelineView(.periodic(from: .now, by: 1)) { ctx in
            let left = max(0, Int(Double(deadlineMs) / 1000 - ctx.date.timeIntervalSince1970))
            HStack(spacing: 8) {
                Image(systemName: "timer").foregroundStyle(Tone.warn.text)
                Text("Auto-revert armed: SSH and firewall changes roll back in \(left) s unless a fresh connection confirms them.")
                    .font(.base).foregroundStyle(Tone.warn.text)
            }
            .card(padding: 12)
        }
    }
}

// MARK: - progress relay

@Observable
@MainActor
final class ProvisionRun {
    private(set) var current: ProvisionStepRow?
    private(set) var waiting: UInt32?
    private(set) var revertDeadlineMs: UInt64?

    func apply(_ e: ProvisionEventRow) {
        switch e {
        case .step(let step, _):
            current = step
            waiting = nil
        case .waiting(let attempt):
            waiting = attempt
        case .revertArmed(let deadlineMs):
            revertDeadlineMs = deadlineMs
        case .modules:
            break
        }
    }
}

private final class ProvisionRelay: ProvisionListener {
    private let handler: @Sendable (ProvisionEventRow) -> Void
    init(_ handler: @escaping @Sendable (ProvisionEventRow) -> Void) { self.handler = handler }
    func onEvent(event: ProvisionEventRow) { handler(event) }
}
