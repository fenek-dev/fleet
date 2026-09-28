import SwiftUI

// Bulk action sheet (design §7.3, mockup docs/ui-reference/BulkRun.dc.html):
// what to run, targets, rollout (canary, batch size, stop on failure),
// preview / dry run, then live per-server progress.

/// Live state of one bulk run (or snippet / runbook run).
@Observable
@MainActor
final class BulkProgress {
    struct Row: Identifiable {
        let id: String
        var status: BulkStatusRow?
        var detail = ""
        var started: Date?
        var finished: Date?
    }

    private(set) var rows: [Row] = []
    private(set) var total = 0
    private(set) var needsApproval = false
    private(set) var approved = false
    private(set) var canaryPassed: String?
    private(set) var summary: BulkSummaryRow?
    private(set) var error: String?
    private(set) var step: String?
    private(set) var runbookResult: Bool?
    var handle: BulkRunHandle?

    var isRunning: Bool { handle != nil && summary == nil && error == nil && runbookResult == nil }
    var done: Int { rows.filter { [.succeeded, .failed, .skipped, .cancelled, .planned].contains($0.status) }.count }
    var running: Int { rows.filter { $0.status == .running }.count }
    var queued: Int { rows.filter { $0.status == nil }.count }

    init(targets: [String] = []) {
        rows = targets.map { Row(id: $0) }
    }

    func reset(targets: [String]) {
        rows = targets.map { Row(id: $0) }
        total = targets.count
        summary = nil
        error = nil
        approved = false
        needsApproval = false
        canaryPassed = nil
        runbookResult = nil
        step = nil
    }

    func cancel() { handle?.cancel() }

    fileprivate func apply(_ e: BulkEventRow) {
        switch e {
        case .started(let total, let needsApproval):
            self.total = Int(total)
            self.needsApproval = needsApproval
            summary = nil
        case .approved:
            approved = true
        case .server(let id, let status, let detail):
            if let i = rows.firstIndex(where: { $0.id == id }) {
                if status == .running { rows[i].started = .now } else { rows[i].finished = .now }
                rows[i].status = status
                rows[i].detail = detail
            } else {
                rows.append(Row(id: id, status: status, detail: detail))
            }
        case .canaryPassed(let id):
            canaryPassed = id
        case .done(let s):
            summary = s
        case .error(let message):
            error = message
        case .stepStarted(let index, let name):
            step = "Step \(index + 1): \(name)"
            for i in rows.indices { rows[i] = Row(id: rows[i].id) }
            summary = nil
        case .stepSkipped(let index):
            step = "Step \(index + 1) skipped"
        case .runbookFinished(let ok):
            runbookResult = ok
        }
    }

    /// A listener that feeds this model (callbacks arrive on the core thread).
    func listener() -> BulkListener { Listener(model: self) }

    private final class Listener: BulkListener, @unchecked Sendable {
        weak var model: BulkProgress?
        init(model: BulkProgress) { self.model = model }
        func onEvent(event: BulkEventRow) {
            Task { @MainActor [weak model] in model?.apply(event) }
        }
    }
}

/// Editable operation, mapped to `BulkOpRow`.
struct OpDraft: Equatable {
    enum Kind: String, CaseIterable, Identifiable {
        case agentHealth = "agent.health"
        case unit = "unit.*"
        case pkgRefresh = "pkg.refresh"
        case pkgUpgrade = "pkg.upgrade"
        case container = "docker.containers.*"
        case composePull = "compose.pull"
        case composeRestart = "compose.restart"
        case configRollback = "config.rollback"
        case profileCheck = "profile.check"
        case reboot = "system.reboot"
        case shell = "shell.exec"
        var id: String { rawValue }
    }

    var kind: Kind = .pkgUpgrade
    var unit = ""
    var unitAction: ServiceActionRow = .restart
    var securityOnly = true
    var container = ""
    var containerAction: ContainerActionRow = .restart
    var project = ""
    var path = ""
    var version: UInt64 = 1
    var strict = false
    var delay: UInt32 = 0
    var user = ""
    var command = ""
    var timeout: UInt32 = 60

    var row: BulkOpRow {
        switch kind {
        case .agentHealth: .agentHealth
        case .unit: .unit(unit: unit, action: unitAction)
        case .pkgRefresh: .pkgRefresh
        case .pkgUpgrade: .pkgUpgrade(securityOnly: securityOnly)
        case .container: .container(container: container, action: containerAction)
        case .composePull: .composePull(project: project)
        case .composeRestart: .composeRestart(project: project)
        case .configRollback: .configRollback(path: path, version: version)
        case .profileCheck: .profileCheck(level: strict ? .strict : .baseline)
        case .reboot: .systemReboot(delayS: delay)
        case .shell: .shellExec(user: user, command: command, timeoutS: timeout)
        }
    }

    init() {}

    init(row: BulkOpRow) {
        switch row {
        case .agentHealth, .systemInfo: kind = .agentHealth
        case .unit(let u, let a): kind = .unit; unit = u; unitAction = a
        case .pkgRefresh: kind = .pkgRefresh
        case .pkgUpgrade(let s): kind = .pkgUpgrade; securityOnly = s
        case .container(let c, let a): kind = .container; container = c; containerAction = a
        case .composePull(let p): kind = .composePull; project = p
        case .composeRestart(let p): kind = .composeRestart; project = p
        case .composeDeploy(let p, _, _): kind = .composePull; project = p
        case .configRollback(let p, let v): kind = .configRollback; path = p; version = v
        case .profileCheck(let l): kind = .profileCheck; strict = l == .strict
        case .systemReboot(let d): kind = .reboot; delay = d
        case .shellExec(let u, let c, let t): kind = .shell; user = u; command = c; timeout = t
        }
    }
}

struct OpEditor: View {
    @Binding var draft: OpDraft

    var body: some View {
        Picker("Operation", selection: $draft.kind) {
            ForEach(OpDraft.Kind.allCases) { Text($0.rawValue).tag($0) }
        }
        .accessibilityIdentifier("bulk.operation")
        switch draft.kind {
        case .unit:
            TextField("Unit", text: $draft.unit, prompt: Text("nginx.service"))
                .accessibilityIdentifier("bulk.unit")
            Picker("Action", selection: $draft.unitAction) {
                Text("Restart").tag(ServiceActionRow.restart)
                Text("Reload").tag(ServiceActionRow.reload)
                Text("Start").tag(ServiceActionRow.start)
                Text("Stop").tag(ServiceActionRow.stop)
                Text("Enable").tag(ServiceActionRow.enable)
                Text("Disable").tag(ServiceActionRow.disable)
            }
            .accessibilityIdentifier("bulk.unitAction")
        case .pkgUpgrade:
            Picker("Scope", selection: $draft.securityOnly) {
                Text("Security only").tag(true)
                Text("All upgradable").tag(false)
            }
            .pickerStyle(.segmented)
            .accessibilityIdentifier("bulk.scope")
        case .container:
            TextField("Container", text: $draft.container)
                .accessibilityIdentifier("bulk.container")
            Picker("Action", selection: $draft.containerAction) {
                Text("Restart").tag(ContainerActionRow.restart)
                Text("Start").tag(ContainerActionRow.start)
                Text("Stop").tag(ContainerActionRow.stop)
            }
        case .composePull, .composeRestart:
            TextField("Project", text: $draft.project)
                .accessibilityIdentifier("bulk.project")
        case .configRollback:
            TextField("Path", text: $draft.path, prompt: Text("/etc/nginx/nginx.conf"))
                .accessibilityIdentifier("bulk.path")
            TextField("Version", value: $draft.version, format: .number)
                .accessibilityIdentifier("bulk.version")
        case .profileCheck:
            Toggle("Strict profile", isOn: $draft.strict)
                .accessibilityIdentifier("bulk.strict")
        case .reboot:
            TextField("Delay (s)", value: $draft.delay, format: .number)
                .accessibilityIdentifier("bulk.delay")
        case .shell:
            TextField("Run as user", text: $draft.user)
                .accessibilityIdentifier("bulk.shellUser")
            TextEditor(text: $draft.command)
                .font(.system(size: 12, design: .monospaced))
                .frame(minHeight: 60)
                .accessibilityIdentifier("bulk.shellCommand")
            TextField("Timeout (s)", value: $draft.timeout, format: .number)
                .accessibilityIdentifier("bulk.shellTimeout")
            Text("Runs `/bin/sh -c` on each server, where the server policy allows shell.exec (off by default).")
                .font(.caption11).foregroundStyle(Color.textMuted)
        case .agentHealth, .pkgRefresh:
            EmptyView()
        }
    }
}

/// Servers with checkboxes, plus group shortcuts.
struct TargetPicker: View {
    @Environment(CoreBridge.self) private var core
    @Binding var selected: [String]

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Button("All") { selected = core.servers.map(\.id) }
                    .accessibilityIdentifier("bulk.targets.all")
                Button("Online") { selected = core.servers.filter { $0.state == .ready }.map(\.id) }
                    .accessibilityIdentifier("bulk.targets.online")
                ForEach(core.groups, id: \.id) { g in
                    Button(g.name) { selected = core.servers.filter { $0.groupId == g.id }.map(\.id) }
                        .accessibilityIdentifier("bulk.targets.group.\(g.name)")
                }
                Button("None") { selected = [] }
                    .accessibilityIdentifier("bulk.targets.none")
            }
            .controlSize(.small)
            ForEach(core.servers, id: \.id) { s in
                Toggle(isOn: Binding(
                    get: { selected.contains(s.id) },
                    set: { on in
                        if on { if !selected.contains(s.id) { selected.append(s.id) } }
                        else { selected.removeAll { $0 == s.id } }
                    }
                )) {
                    HStack(spacing: 6) {
                        Circle().fill(s.state.tone.dot).frame(width: 6, height: 6)
                        Text(s.name)
                        if selected.first == s.id {
                            Text("canary").font(.caption11).foregroundStyle(Tone.info.text)
                        }
                    }
                }
                .accessibilityIdentifier("bulk.target.\(s.name)")
            }
        }
    }
}

/// Per-server progress table.
struct BulkProgressView: View {
    @Environment(CoreBridge.self) private var core
    let progress: BulkProgress

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 12) {
                Text("\(progress.done) done").foregroundStyle(Color.text)
                Text("\(progress.running) running").foregroundStyle(Tone.info.text)
                Text("\(progress.queued) queued").foregroundStyle(Color.textMuted)
                if let c = progress.canaryPassed {
                    Text("Canary passed (\(name(c)))").foregroundStyle(Tone.ok.text)
                }
                Spacer()
                if progress.needsApproval {
                    StatusPill(label: progress.approved ? "Approved once for all" : "Needs Touch ID",
                               tone: progress.approved ? .ok : .warn)
                }
            }
            .font(.secondary)
            if let step = progress.step {
                Text(step).font(.secondary).foregroundStyle(Color.textSecondary)
            }
            Table(progress.rows) {
                TableColumn("Server") { r in Text(name(r.id)) }
                    .width(min: 90, ideal: 120)
                TableColumn("Status") { r in StatusPill(label: label(r.status), tone: tone(r.status)) }
                    .width(min: 80, ideal: 100)
                TableColumn("Detail") { r in
                    Text(r.detail).lineLimit(2).help(r.detail)
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundStyle(Color.textSecondary)
                }
                TableColumn("Time") { r in Text(elapsed(r)).foregroundStyle(Color.textMuted) }
                    .width(50)
            }
            .frame(minHeight: 200)
            if let s = progress.summary {
                Text(summaryText(s)).font(.secondary)
                    .foregroundStyle(s.failed > 0 || s.stop != nil ? Tone.warn.text : Tone.ok.text)
            }
            if let e = progress.error {
                Text(e).font(.secondary).foregroundStyle(Tone.critical.text)
            }
            Text("Each command is signed by this Mac, bound to one server, and written to that server's audit log.")
                .font(.caption11).foregroundStyle(Color.textMuted)
        }
    }

    private func name(_ id: String) -> String { core.servers.first { $0.id == id }?.name ?? id }

    private func label(_ s: BulkStatusRow?) -> String {
        switch s {
        case .none: "Queued"
        case .running: "Running"
        case .succeeded: "Done"
        case .failed: "Failed"
        case .skipped: "Skipped"
        case .cancelled: "Unknown"
        case .planned: "Planned"
        }
    }

    private func tone(_ s: BulkStatusRow?) -> Tone {
        switch s {
        case .none, .skipped: .neutral
        case .running, .planned: .info
        case .succeeded: .ok
        case .failed: .critical
        case .cancelled: .warn
        }
    }

    private func elapsed(_ r: BulkProgress.Row) -> String {
        guard let s = r.started else { return "—" }
        return "\(Int((r.finished ?? .now).timeIntervalSince(s))) s"
    }

    private func summaryText(_ s: BulkSummaryRow) -> String {
        var parts = ["\(s.succeeded) succeeded"]
        if s.failed > 0 { parts.append("\(s.failed) failed") }
        if s.skipped > 0 { parts.append("\(s.skipped) skipped") }
        if s.cancelled > 0 { parts.append("\(s.cancelled) outcome unknown") }
        if s.planned > 0 { parts.append("\(s.planned) planned") }
        var t = parts.joined(separator: " · ")
        if let stop = s.stop { t += " — \(stop)" }
        return t
    }
}

struct BulkRunSheet: View {
    @Environment(CoreBridge.self) private var core
    @Environment(\.dismiss) private var dismiss
    @State var draft = OpDraft()
    @State var targets: [String]
    @State private var canary = true
    @State private var healthCheck = true
    @State private var concurrency = 16
    @State private var stopOnFailure = true
    @State private var timeout: UInt32 = 0
    @State private var preview: BulkPreviewRow?
    @State private var previewError: String?
    @State private var progress = BulkProgress()
    @State private var confirmShown = false

    init(targets: [String], draft: OpDraft = OpDraft()) {
        _targets = State(initialValue: targets)
        _draft = State(initialValue: draft)
    }

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Run on servers").font(.toolbarTitle)
                    Text("\(preview?.opName ?? draft.kind.rawValue) · \(targets.count) targets")
                        .font(.secondary).foregroundStyle(Color.textMuted)
                }
                Spacer()
                if progress.isRunning {
                    Button("Cancel", role: .destructive) { progress.cancel() }
                        .accessibilityIdentifier("bulk.cancel")
                }
                Button("Close") { dismiss() }
                    .accessibilityIdentifier("bulk.close")
                    .keyboardShortcut(.cancelAction)
            }
            .padding(16)
            Divider()
            HSplitView {
                form.frame(minWidth: 320, idealWidth: 360)
                BulkProgressView(progress: progress)
                    .padding(16)
                    .frame(minWidth: 420)
            }
        }
        .frame(minWidth: 900, minHeight: 600)
        .background(Color.window)
        .onChange(of: draft) { refreshPreview() }
        .onAppear { refreshPreview() }
        .confirmationDialog(confirmTitle, isPresented: $confirmShown) {
            Button("Run", role: .destructive) { run(dryRun: false) }
                .accessibilityIdentifier("bulk.confirmRun")
        } message: {
            Text(preview?.command ?? "")
        }
    }

    private var form: some View {
        Form {
            Section("What to run") {
                OpEditor(draft: $draft)
                if let p = preview {
                    if p.elevated {
                        Label("Elevated: one Touch ID approves all \(targets.count) servers.",
                              systemImage: "touchid")
                            .foregroundStyle(Tone.warn.text)
                    } else {
                        Text("A typed operation: validated arguments, signed separately for every server.")
                            .font(.caption11).foregroundStyle(Color.textMuted)
                    }
                }
                if let e = previewError {
                    Text(e).font(.caption11).foregroundStyle(Tone.critical.text)
                }
            }
            Section("Targets · \(targets.count) servers") {
                TargetPicker(selected: $targets)
            }
            Section("Rollout") {
                Toggle("Canary: first server, then health check", isOn: $canary)
                    .accessibilityIdentifier("bulk.canary")
                Toggle("Health check after canary", isOn: $healthCheck).disabled(!canary)
                    .accessibilityIdentifier("bulk.healthCheck")
                Stepper("At most \(concurrency) at a time", value: $concurrency, in: 1...64)
                    .accessibilityIdentifier("bulk.concurrency")
                Toggle("Stop on first failure", isOn: $stopOnFailure)
                    .accessibilityIdentifier("bulk.stopOnFailure")
                TextField("Per-server timeout (s, 0 = default)", value: $timeout, format: .number)
                    .accessibilityIdentifier("bulk.timeout")
            }
            Section {
                HStack {
                    Button("Dry run") { run(dryRun: true) }
                        .help(preview?.hasPlan == true ? "Fetches the plan from each server" : "Shows the command for each server")
                        .accessibilityIdentifier("bulk.dryRun")
                    Spacer()
                    Button("Run on \(targets.count) servers") { confirmShown = true }
                        .accessibilityIdentifier("bulk.run")
                        .buttonStyle(.borderedProminent)
                        .disabled(targets.isEmpty || preview == nil || progress.isRunning)
                }
                .disabled(targets.isEmpty || preview == nil || progress.isRunning)
            }
        }
        .formStyle(.grouped)
    }

    private var confirmTitle: String {
        "Run \(preview?.opName ?? "") on \(targets.count) servers?"
    }

    private func refreshPreview() {
        guard let api = core.api else { return }
        do {
            preview = try api.bulkPreview(op: draft.row)
            previewError = nil
        } catch {
            preview = nil
            previewError = error.fleetMessage
        }
    }

    private func run(dryRun: Bool) {
        guard let api = core.api else { return }
        progress.reset(targets: targets)
        let opts = BulkOptionsRow(
            concurrency: UInt32(concurrency), canary: canary, healthCheck: canary && healthCheck,
            stopOnFailure: stopOnFailure, perServerTimeoutS: timeout, dryRun: dryRun)
        do {
            progress.handle = try api.bulkRun(
                targets: targets, op: draft.row, options: opts, listener: progress.listener())
        } catch {
            previewError = error.fleetMessage
        }
    }
}
