import SwiftUI

// Snippets and runbooks (design §2.3). Snippets are saved shell commands
// run through shell.exec (policy-gated, Touch ID once) or over SSH as the
// admin user, always after the exact text is shown. Runbooks are typed
// steps with conditions and an optional schedule the app runs while open.

struct RunbooksView: View {
    @Environment(CoreBridge.self) private var core
    @State private var snippets: [SnippetRow] = []
    @State private var runbooks: [RunbookRow] = []
    @State private var error: String?
    @State private var editingSnippet: SnippetRow?
    @State private var editingRunbook: RunbookRow?
    @State private var runningSnippet: SnippetRow?
    @State private var runningRunbook: RunbookRow?
    @State private var bulkShown = false

    var body: some View {
        List {
            Section {
                ForEach(snippets, id: \.id) { s in
                    HStack(alignment: .top) {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(s.name).foregroundStyle(Color.text)
                            Text(s.command).lineLimit(2)
                                .font(.system(size: 11, design: .monospaced))
                                .foregroundStyle(Color.textSecondary)
                        }
                        Spacer()
                        Button("Run…") { runningSnippet = s }
                        Button("Edit") { editingSnippet = s }
                        Button(role: .destructive) { delete(snippet: s) } label: { Image(systemName: "trash") }
                    }
                    .controlSize(.small)
                }
            } header: {
                HStack {
                    Text("Snippets")
                    Spacer()
                    Button("New snippet") {
                        editingSnippet = SnippetRow(id: "", name: "", description: "", command: "", updatedMs: 0)
                    }
                }
            }
            Section {
                ForEach(runbooks, id: \.id) { r in
                    HStack {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(r.name).foregroundStyle(Color.text)
                            Text(subtitle(r)).font(.secondary).foregroundStyle(Color.textMuted)
                        }
                        Spacer()
                        Button("Run…") { runningRunbook = r }
                        Button("Edit") { editingRunbook = r }
                        Button(role: .destructive) { delete(runbook: r) } label: { Image(systemName: "trash") }
                    }
                    .controlSize(.small)
                }
            } header: {
                HStack {
                    Text("Runbooks")
                    Spacer()
                    Button("New runbook") {
                        editingRunbook = RunbookRow(
                            id: "", name: "", description: "", targets: [], params: [],
                            steps: [], scheduleMinutes: nil, lastRunMs: nil, updatedMs: 0)
                    }
                }
            }
            if let error {
                Text(error).foregroundStyle(Tone.critical.text)
            }
        }
        .scrollContentBackground(.hidden)
        .background(Color.window)
        .navigationTitle("Runbooks")
        .toolbar {
            Button("Run on servers…") { bulkShown = true }
        }
        .task { reload() }
        .sheet(isPresented: $bulkShown) {
            BulkRunSheet(targets: core.servers.filter { $0.state == .ready }.map(\.id))
        }
        .sheet(item: $editingSnippet) { s in
            SnippetEditor(snippet: s) { reload() }
        }
        .sheet(item: $editingRunbook) { r in
            RunbookEditor(runbook: r) { reload() }
        }
        .sheet(item: $runningSnippet) { s in RunSnippetSheet(snippet: s) }
        .sheet(item: $runningRunbook) { r in RunRunbookSheet(runbook: r) { reload() } }
    }

    private func subtitle(_ r: RunbookRow) -> String {
        var s = "\(r.steps.count) steps · \(r.targets.count) servers"
        if let m = r.scheduleMinutes { s += " · every \(m) min" }
        if let last = r.lastRunMs {
            s += " · last run " + Date(timeIntervalSince1970: Double(last) / 1000)
                .formatted(date: .abbreviated, time: .shortened)
        }
        return s
    }

    private func reload() {
        guard let api = core.api else { return }
        do {
            snippets = try api.listSnippets()
            runbooks = try api.listRunbooks()
            error = nil
        } catch {
            core.report(error)
            self.error = error.fleetMessage
        }
    }

    private func delete(snippet: SnippetRow) {
        try? core.api?.deleteSnippet(id: snippet.id)
        reload()
    }

    private func delete(runbook: RunbookRow) {
        try? core.api?.deleteRunbook(id: runbook.id)
        reload()
    }
}

extension SnippetRow: Identifiable {}
extension RunbookRow: Identifiable {}

private struct SnippetEditor: View {
    @Environment(CoreBridge.self) private var core
    @Environment(\.dismiss) private var dismiss
    @State var snippet: SnippetRow
    let saved: () -> Void
    @State private var error: String?

    var body: some View {
        Form {
            TextField("Name", text: $snippet.name)
            TextField("Description", text: $snippet.description)
            Section("Command") {
                TextEditor(text: $snippet.command)
                    .font(.system(size: 12, design: .monospaced))
                    .frame(minHeight: 120)
            }
            if let error { Text(error).foregroundStyle(Tone.critical.text) }
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }
                Button("Save") { save() }.buttonStyle(.borderedProminent)
            }
        }
        .formStyle(.grouped)
        .frame(width: 520, height: 400)
    }

    private func save() {
        do {
            _ = try core.api?.saveSnippet(snippet: snippet)
            saved()
            dismiss()
        } catch {
            self.error = error.fleetMessage
        }
    }
}

private struct RunSnippetSheet: View {
    @Environment(CoreBridge.self) private var core
    @Environment(\.dismiss) private var dismiss
    let snippet: SnippetRow
    @State private var targets: [String] = []
    @State private var viaShellExec = false
    @State private var user = ""
    @State private var timeout: UInt32 = 60
    @State private var confirmed = false
    @State private var progress = BulkProgress()
    @State private var error: String?

    var body: some View {
        HSplitView {
            Form {
                Section("Exact command (runs as written)") {
                    Text(snippet.command)
                        .font(.system(size: 12, design: .monospaced))
                        .textSelection(.enabled)
                }
                Section("How") {
                    Picker("Run", selection: $viaShellExec) {
                        Text("SSH as admin user (not root)").tag(false)
                        Text("shell.exec (policy-gated, Touch ID)").tag(true)
                    }
                    if viaShellExec { TextField("Run as user", text: $user) }
                    TextField("Timeout (s)", value: $timeout, format: .number)
                }
                Section("Targets · \(targets.count)") { TargetPicker(selected: $targets) }
                Toggle("I checked the command and the targets", isOn: $confirmed)
                if let error { Text(error).foregroundStyle(Tone.critical.text) }
                HStack {
                    Button("Close") { dismiss() }
                    Spacer()
                    if progress.isRunning { Button("Cancel") { progress.cancel() } }
                    Button("Run") { run() }
                        .buttonStyle(.borderedProminent)
                        .disabled(!confirmed || targets.isEmpty || progress.isRunning)
                }
            }
            .formStyle(.grouped)
            .frame(minWidth: 340)
            BulkProgressView(progress: progress).padding(16).frame(minWidth: 420)
        }
        .frame(minWidth: 860, minHeight: 560)
    }

    private func run() {
        guard let api = core.api else { return }
        progress.reset(targets: targets)
        let mode: SnippetModeRow = viaShellExec
            ? .shellExec(user: user, timeoutS: timeout) : .ssh(timeoutS: timeout)
        let opts = BulkOptionsRow(concurrency: 16, canary: targets.count > 1, healthCheck: false,
                                  stopOnFailure: true, perServerTimeoutS: 0, dryRun: false)
        do {
            progress.handle = try api.runSnippet(
                id: snippet.id, targets: targets, mode: mode, options: opts,
                listener: progress.listener())
        } catch {
            self.error = error.fleetMessage
        }
    }
}

private struct RunRunbookSheet: View {
    @Environment(CoreBridge.self) private var core
    @Environment(\.dismiss) private var dismiss
    let runbook: RunbookRow
    let finished: () -> Void
    @State private var values: [String: String] = [:]
    @State private var progress = BulkProgress()
    @State private var error: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(runbook.name).font(.toolbarTitle)
            if !runbook.params.isEmpty {
                Form {
                    ForEach(runbook.params, id: \.name) { p in
                        TextField(p.name, text: Binding(
                            get: { values[p.name] ?? p.defaultValue ?? "" },
                            set: { values[p.name] = $0 }))
                    }
                }
                .formStyle(.grouped)
                .frame(maxHeight: 160)
            }
            if let error { Text(error).foregroundStyle(Tone.critical.text) }
            if let ok = progress.runbookResult {
                Text(ok ? "Runbook finished: every step succeeded." : "Runbook finished with failures.")
                    .foregroundStyle(ok ? Tone.ok.text : Tone.warn.text)
            }
            BulkProgressView(progress: progress)
            HStack {
                Button("Close") { finished(); dismiss() }
                Spacer()
                if progress.isRunning { Button("Cancel") { progress.cancel() } }
                Button("Run \(runbook.steps.count) steps on \(runbook.targets.count) servers") { run() }
                    .buttonStyle(.borderedProminent)
                    .disabled(progress.isRunning)
            }
        }
        .padding(16)
        .frame(minWidth: 760, minHeight: 520)
    }

    private func run() {
        guard let api = core.api else { return }
        progress.reset(targets: runbook.targets)
        var params: [String: String] = [:]
        for p in runbook.params {
            if let v = values[p.name] ?? p.defaultValue { params[p.name] = v }
        }
        do {
            progress.handle = try api.runRunbook(id: runbook.id, params: params, listener: progress.listener())
        } catch {
            self.error = error.fleetMessage
        }
    }
}

private struct RunbookEditor: View {
    @Environment(CoreBridge.self) private var core
    @Environment(\.dismiss) private var dismiss
    @State var runbook: RunbookRow
    let saved: () -> Void
    @State private var drafts: [OpDraft] = []
    @State private var error: String?

    init(runbook: RunbookRow, saved: @escaping () -> Void) {
        _runbook = State(initialValue: runbook)
        _drafts = State(initialValue: runbook.steps.map { OpDraft(row: $0.op) })
        self.saved = saved
    }

    var body: some View {
        Form {
            TextField("Name", text: $runbook.name)
            TextField("Description", text: $runbook.description)
            Section("Parameters (use as {{name}} in step fields)") {
                ForEach(runbook.params.indices, id: \.self) { i in
                    HStack {
                        TextField("name", text: $runbook.params[i].name)
                        TextField("default", text: Binding(
                            get: { runbook.params[i].defaultValue ?? "" },
                            set: { runbook.params[i].defaultValue = $0.isEmpty ? nil : $0 }))
                        Button { runbook.params.remove(at: i) } label: { Image(systemName: "minus.circle") }
                    }
                }
                Button("Add parameter") { runbook.params.append(RunbookParamRow(name: "", defaultValue: nil)) }
            }
            ForEach(runbook.steps.indices, id: \.self) { i in
                Section("Step \(i + 1)") {
                    TextField("Name", text: $runbook.steps[i].name)
                    OpEditor(draft: $drafts[i])
                    Picker("Run when", selection: $runbook.steps[i].when) {
                        Text("Always").tag(StepConditionRow.always)
                        Text("Previous step succeeded").tag(StepConditionRow.previousSucceeded)
                        Text("Previous step failed").tag(StepConditionRow.previousFailed)
                    }
                    Toggle("Canary", isOn: $runbook.steps[i].canary)
                    Toggle("Stop on failure", isOn: $runbook.steps[i].stopOnFailure)
                    Button("Remove step", role: .destructive) {
                        runbook.steps.remove(at: i)
                        drafts.remove(at: i)
                    }
                }
            }
            Button("Add step") {
                let d = OpDraft()
                drafts.append(d)
                runbook.steps.append(RunbookStepRow(
                    name: "Step \(runbook.steps.count + 1)", op: d.row, when: .previousSucceeded,
                    canary: false, stopOnFailure: true, concurrency: nil))
            }
            Section("Targets · \(runbook.targets.count)") { TargetPicker(selected: $runbook.targets) }
            Section("Schedule") {
                Toggle("Run on a schedule while Fleet is open", isOn: Binding(
                    get: { runbook.scheduleMinutes != nil },
                    set: { runbook.scheduleMinutes = $0 ? (runbook.scheduleMinutes ?? 60) : nil }))
                if runbook.scheduleMinutes != nil {
                    TextField("Every (minutes, 5–10080)", value: Binding(
                        get: { runbook.scheduleMinutes ?? 60 },
                        set: { runbook.scheduleMinutes = $0 }), format: .number)
                    Text("Scheduled runbooks can't contain elevated steps.")
                        .font(.caption11).foregroundStyle(Color.textMuted)
                }
            }
            if let error { Text(error).foregroundStyle(Tone.critical.text) }
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }
                Button("Save") { save() }.buttonStyle(.borderedProminent)
            }
        }
        .formStyle(.grouped)
        .frame(width: 640, height: 720)
    }

    private func save() {
        for i in runbook.steps.indices { runbook.steps[i].op = drafts[i].row }
        do {
            _ = try core.api?.saveRunbook(runbook: runbook)
            saved()
            dismiss()
        } catch {
            self.error = error.fleetMessage
        }
    }
}

/// Runs scheduled runbooks every minute while the app is open and
/// unlocked (design §2.3). Results are kept for the last run only.
@Observable
@MainActor
final class RunbookScheduler {
    private(set) var lastResults: [String: BulkProgress] = [:]
    @ObservationIgnored private var timer: Timer?

    func start(core: FleetCore, isLocked: @escaping @MainActor @Sendable () -> Bool) {
        guard timer == nil else { return }
        timer = Timer.scheduledTimer(withTimeInterval: 60, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.tick(core: core, locked: isLocked()) }
        }
    }

    private func tick(core: FleetCore, locked: Bool) {
        guard !locked else { return }
        let now = UInt64(Date().timeIntervalSince1970 * 1000)
        guard let due = try? core.dueRunbooks(nowMs: now) else { return }
        for id in due {
            if let running = lastResults[id], running.isRunning { continue }
            let progress = BulkProgress()
            progress.handle = try? core.runRunbook(id: id, params: [:], listener: progress.listener())
            lastResults[id] = progress
        }
    }
}
