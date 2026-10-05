import SwiftUI

// Bulk action sheet (design §7.3, mockup docs/ui-reference/BulkRun.dc.html):
// what to run (typed operation or shell), targets (groups, tags, suggested
// exclusions), rollout (canary, then batches), dry run, then live per-server
// progress with stages.

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
        /// "Canary" or "Batch n"; empty when the run has no stages.
        var stage = ""
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
    private(set) var paused = false
    private(set) var started: Date?
    /// Batches after the canary (0 when the run has no stages).
    private(set) var batchCount = 0
    private(set) var hasCanary = false
    var handle: BulkRunHandle?

    var isRunning: Bool { handle != nil && summary == nil && error == nil && runbookResult == nil }
    var done: Int { rows.filter { [.succeeded, .failed, .skipped, .cancelled, .planned].contains($0.status) }.count }
    var running: Int { rows.filter { $0.status == .running }.count }
    var queued: Int { rows.filter { $0.status == nil }.count }

    init(targets: [String] = []) {
        rows = targets.map { Row(id: $0) }
    }

    /// `batchSize` > 0 labels the rows: the first is the canary (when
    /// `canary`), the rest run in batches of `batchSize`.
    func reset(targets: [String], canary: Bool = false, batchSize: Int = 0) {
        var new = targets.map { Row(id: $0) }
        hasCanary = canary && batchSize > 0 && !targets.isEmpty
        batchCount = 0
        if batchSize > 0 {
            let lead = hasCanary ? 1 : 0
            for i in new.indices {
                if i < lead { new[i].stage = "Canary" }
                else { new[i].stage = "Batch \((i - lead) / batchSize + 1)" }
            }
            batchCount = max(0, (targets.count - lead + batchSize - 1) / batchSize)
        }
        rows = new
        total = targets.count
        summary = nil
        error = nil
        approved = false
        needsApproval = false
        canaryPassed = nil
        runbookResult = nil
        step = nil
        paused = false
        started = .now
    }

    func cancel() {
        handle?.cancel()
        paused = false
    }

    func pause() {
        handle?.pause()
        paused = true
    }

    func resume() {
        handle?.resume()
        paused = false
    }

    /// The batch now running, e.g. "batch 2 of 3"; nil without stages.
    var batchText: String? {
        guard batchCount > 0, isRunning else { return nil }
        let active = rows.filter { $0.status == .running }.map(\.stage)
        let last = rows.filter { $0.status != nil && $0.status != .running }.map(\.stage)
        guard let s = (active.first ?? last.last), s.hasPrefix("Batch "),
              let n = Int(s.dropFirst(6)) else { return nil }
        return "batch \(n) of \(batchCount)"
    }

    /// Appends a line to a row (post-run follow-ups such as reboots).
    func note(_ id: String, _ line: String) {
        guard let i = rows.firstIndex(where: { $0.id == id }) else { return }
        rows[i].detail += (rows[i].detail.isEmpty ? "" : "\n") + line
    }

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
            paused = false
        case .error(let message):
            error = message
        case .stepStarted(let index, let name):
            step = "Step \(index + 1): \(name)"
            for i in rows.indices { rows[i] = Row(id: rows[i].id, stage: rows[i].stage) }
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

extension BulkProgress.Row {
    fileprivate init(id: String, stage: String) {
        self.init(id: id)
        self.stage = stage
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

        /// Typed operations (everything but the shell).
        static var typed: [Kind] { allCases.filter { $0 != .shell } }
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
    /// `system.reboot.schedule`: reboot at the start of a daily window in
    /// each server's local time (minutes since local midnight) instead of
    /// after `delay`.
    var rebootWindow = false
    var windowStart: UInt32 = 180
    var windowEnd: UInt32 = 300
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
        case .reboot:
            rebootWindow ? .systemRebootWindow(startMin: windowStart, endMin: windowEnd)
                : .systemReboot(delayS: delay)
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
        case .systemRebootWindow(let s, let e):
            kind = .reboot; rebootWindow = true; windowStart = s; windowEnd = e
        case .shellExec(let u, let c, let t): kind = .shell; user = u; command = c; timeout = t
        }
    }
}

struct OpEditor: View {
    @Binding var draft: OpDraft
    /// The typed operation chosen last, restored when switching back from Shell.
    @State private var lastTyped: OpDraft.Kind = .pkgUpgrade

    private var runType: Binding<Bool> {
        Binding(
            get: { draft.kind == .shell },
            set: { shell in
                if shell {
                    if draft.kind != .shell { lastTyped = draft.kind }
                    draft.kind = .shell
                } else {
                    draft.kind = lastTyped
                }
            })
    }

    var body: some View {
        Picker("Run type", selection: runType) {
            Text("Operation").tag(false)
            Text("Shell").tag(true)
        }
        .fleetSegmented()
        .accessibilityIdentifier("bulk.runType")
        if draft.kind != .shell {
            Picker("Operation", selection: $draft.kind) {
                ForEach(OpDraft.Kind.typed) { Text($0.rawValue).tag($0) }
            }
            .accessibilityIdentifier("bulk.operation")
        }
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
            .fleetSegmented()
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
            Picker("When", selection: $draft.rebootWindow) {
                Text("After a delay").tag(false)
                Text("In a daily window").tag(true)
            }
            .fleetSegmented()
            .accessibilityIdentifier("bulk.rebootWhen")
            if draft.rebootWindow {
                RebootWindowFields(start: $draft.windowStart, end: $draft.windowEnd)
            } else {
                TextField("Delay (s)", value: $draft.delay, format: .number)
                    .accessibilityIdentifier("bulk.delay")
            }
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

/// Targets by group and tag chips, quick sets, and a per-server checklist.
struct TargetPicker: View {
    @Environment(CoreBridge.self) private var core
    @Binding var selected: [String]
    @State private var groupChips = Set<String>()
    @State private var tagChips = Set<String>()

    private var tags: [String] {
        Array(Set(core.servers.flatMap(\.tags))).sorted()
    }

    /// Servers matching the active chips: any chosen group, and any chosen tag.
    private func matching() -> [String] {
        core.servers.filter { s in
            (groupChips.isEmpty || s.groupId.map(groupChips.contains) == true)
                && (tagChips.isEmpty || !tagChips.isDisjoint(with: s.tags))
        }.map(\.id)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            FlowLayout(spacing: 6) {
                ForEach(core.groups, id: \.id) { g in
                    chip("Group: \(g.name)", on: groupChips.contains(g.id),
                         id: "bulk.targets.group.\(g.name)") {
                        toggle(&groupChips, g.id)
                    }
                }
                ForEach(tags, id: \.self) { t in
                    chip("Tag: \(t)", on: tagChips.contains(t), id: "bulk.targets.tag.\(t)") {
                        toggle(&tagChips, t)
                    }
                }
            }
            HStack {
                Button("All") { reset(); selected = core.servers.map(\.id) }
                    .accessibilityIdentifier("bulk.targets.all")
                Button("Online") {
                    reset()
                    selected = core.servers.filter { $0.state == .ready }.map(\.id)
                }
                .accessibilityIdentifier("bulk.targets.online")
                Button("None") { reset(); selected = [] }
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

    private func reset() {
        groupChips = []
        tagChips = []
    }

    private func toggle(_ set: inout Set<String>, _ v: String) {
        if set.contains(v) { set.remove(v) } else { set.insert(v) }
        selected = matching()
    }

    private func chip(_ title: String, on: Bool, id: String,
                      action: @escaping () -> Void) -> some View {
        Button(action: action) {
            Text(title).font(.secondary)
                .padding(.horizontal, 10).frame(height: 26)
                .background(on ? Color.accent.opacity(0.35) : Color.selected,
                            in: RoundedRectangle(cornerRadius: 7))
                .foregroundStyle(on ? Color.text : Color.textSecondary)
        }
        .buttonStyle(.plain)
        .accessibilityIdentifier(id)
        .accessibilityAddTraits(on ? .isSelected : [])
    }
}

/// Left-to-right wrapping layout for chips.
struct FlowLayout: Layout {
    var spacing: CGFloat = 6

    func sizeThatFits(proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) -> CGSize {
        arrange(width: proposal.width ?? 400, subviews: subviews).size
    }

    func placeSubviews(in bounds: CGRect, proposal: ProposedViewSize, subviews: Subviews,
                       cache: inout ()) {
        let laid = arrange(width: bounds.width, subviews: subviews)
        for (i, p) in laid.points.enumerated() {
            subviews[i].place(at: CGPoint(x: bounds.minX + p.x, y: bounds.minY + p.y),
                              proposal: .unspecified)
        }
    }

    private func arrange(width: CGFloat, subviews: Subviews) -> (size: CGSize, points: [CGPoint]) {
        var points: [CGPoint] = []
        var x: CGFloat = 0, y: CGFloat = 0, rowH: CGFloat = 0, maxX: CGFloat = 0
        for s in subviews {
            let sz = s.sizeThatFits(.unspecified)
            if x > 0, x + sz.width > width { x = 0; y += rowH + spacing; rowH = 0 }
            points.append(CGPoint(x: x, y: y))
            x += sz.width + spacing
            rowH = max(rowH, sz.height)
            maxX = max(maxX, x - spacing)
        }
        return (CGSize(width: maxX, height: y + rowH), points)
    }
}

/// Per-server progress: stage bar, counts, and the server table.
struct BulkProgressView: View {
    @Environment(CoreBridge.self) private var core
    let progress: BulkProgress
    /// Pause / Cancel and the state pill (the bulk sheet turns these on;
    /// other hosts have their own buttons).
    var controls = false
    @State private var selectedRow: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            if controls { controlsBar }
            stageBar
            HStack(spacing: 12) {
                Text("\(progress.done) done").foregroundStyle(Color.text)
                Text("\(progress.running) running").foregroundStyle(Tone.info.text)
                Text("\(progress.queued) queued").foregroundStyle(Color.textMuted)
                if let b = progress.batchText {
                    Text(b).foregroundStyle(Color.textSecondary)
                        .accessibilityIdentifier("bulk.batchText")
                }
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
            if progress.rows.isEmpty {
                // An empty Table still draws its header and a stray scroller.
                Text("Nothing has run yet.").font(.secondary).foregroundStyle(Color.textMuted)
            } else {
                Table(progress.rows, selection: $selectedRow) {
                    TableColumn("") { r in statusIcon(r.status) }
                        .width(24)
                    TableColumn("Server") { r in Text(name(r.id)).fontWeight(.medium) }
                        .width(min: 90, ideal: 120)
                    TableColumn("Stage") { r in
                        Text(r.stage).foregroundStyle(Color.textSecondary)
                    }
                    .width(70)
                    TableColumn("Status") { r in
                        Text(statusText(r))
                            .lineLimit(1)
                            .help(r.detail)
                            .foregroundStyle(color(r.status))
                    }
                    TableColumn("Time") { r in
                        Text(elapsed(r)).foregroundStyle(Color.textMuted).monospacedDigit()
                    }
                    .width(50)
                }
                .accessibilityIdentifier("bulk.rows")
                .alternatingRowBackgrounds(.disabled)
                .scrollContentBackground(.hidden)
                // Fit the rows (header + 28 pt each) so no filler rows show; scroll past 8.
                .frame(height: 32 + 28 * CGFloat(min(progress.rows.count, 8)))
            }
            if let id = selectedRow, let r = progress.rows.first(where: { $0.id == id }),
               !r.detail.isEmpty {
                ScrollView {
                    Text(r.detail).font(.mono(11)).foregroundStyle(Color.textSecondary)
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
                .frame(maxHeight: 120)
                .padding(8)
                .background(Color.track, in: RoundedRectangle(cornerRadius: 8))
                .accessibilityIdentifier("bulk.rowDetail")
            }
            if let s = progress.summary {
                Text(summaryText(s)).font(.secondary)
                    .foregroundStyle(s.failed > 0 || s.stop != nil ? Tone.warn.text : Tone.ok.text)
                    .accessibilityIdentifier("bulk.summary")
            }
            if let e = progress.error {
                Text(e).font(.secondary).foregroundStyle(Tone.critical.text)
            }
            Label("Each command is signed by \(Self.deviceName), bound to one server, and written to that server's audit log.",
                  systemImage: "lock")
                .font(.caption11).foregroundStyle(Color.textMuted)
        }
    }

    /// This Mac's name for the footer ("MacBook Pro 16").
    private static var deviceName: String {
        Host.current().localizedName ?? "this Mac"
    }

    // MARK: pieces

    private var controlsBar: some View {
        HStack(spacing: 10) {
            Text("Rollout").font(.system(size: 14, weight: .semibold))
            Spacer()
            if progress.isRunning {
                let tone: Tone = progress.paused ? .warn : .info
                StatusPill(label: progress.paused ? "Paused" : "Running", tone: tone)
                    .accessibilityIdentifier("bulk.state")
                Button(progress.paused ? "Resume" : "Pause") {
                    if progress.paused { progress.resume() } else { progress.pause() }
                }
                .accessibilityIdentifier("bulk.pause")
                Button("Cancel", role: .destructive) { progress.cancel() }
                    .accessibilityIdentifier("bulk.cancel")
            } else if let s = progress.summary {
                let bad = s.failed > 0 || s.stop != nil
                StatusPill(label: bad ? "Stopped" : "Finished", tone: bad ? .warn : .ok)
                    .accessibilityIdentifier("bulk.state")
            }
        }
    }

    /// One segment per stage, filled by finished servers.
    @ViewBuilder
    private var stageBar: some View {
        let stages = stageGroups()
        if !stages.isEmpty {
            HStack(spacing: 3) {
                ForEach(stages, id: \.name) { g in
                    GeometryReader { geo in
                        ZStack(alignment: .leading) {
                            Capsule().fill(Color.border)
                            Capsule().fill(Color.accent)
                                .frame(width: geo.size.width * g.fraction)
                        }
                    }
                    .frame(height: 8)
                    .layoutPriority(Double(g.count))
                    .frame(maxWidth: .infinity)
                }
            }
            .accessibilityHidden(true)
        }
    }

    private struct StageGroup { let name: String; let count: Int; let fraction: CGFloat }

    private func stageGroups() -> [StageGroup] {
        var order: [String] = []
        var counts: [String: (n: Int, done: Int)] = [:]
        for r in progress.rows where !r.stage.isEmpty {
            if counts[r.stage] == nil { order.append(r.stage) }
            var c = counts[r.stage] ?? (0, 0)
            c.n += 1
            if let s = r.status, s != .running { c.done += 1 }
            counts[r.stage] = c
        }
        return order.map { StageGroup(name: $0, count: counts[$0]!.n,
                                      fraction: CGFloat(counts[$0]!.done) / CGFloat(counts[$0]!.n)) }
    }

    @ViewBuilder
    private func statusIcon(_ s: BulkStatusRow?) -> some View {
        switch s {
        case .none:
            Circle().strokeBorder(Color.textSecondary, style: StrokeStyle(lineWidth: 1.5, dash: [2, 2]))
                .frame(width: 12, height: 12)
        case .running:
            ProgressView().controlSize(.small).scaleEffect(0.7)
        case .succeeded, .planned:
            Image(systemName: "checkmark.circle.fill").foregroundStyle(Tone.ok.dot)
        case .failed:
            Image(systemName: "xmark.circle.fill").foregroundStyle(Tone.critical.dot)
        case .skipped:
            Image(systemName: "minus.circle").foregroundStyle(Color.textMuted)
        case .cancelled:
            Image(systemName: "questionmark.circle").foregroundStyle(Tone.warn.dot)
        }
    }

    private func name(_ id: String) -> String { core.servers.first { $0.id == id }?.name ?? id }

    /// First line of the outcome, or the state.
    private func statusText(_ r: BulkProgress.Row) -> String {
        let first = r.detail.split(separator: "\n", maxSplits: 1, omittingEmptySubsequences: true)
            .first.map(String.init) ?? ""
        switch r.status {
        case .none: return "Queued"
        case .running: return "Running…"
        case .succeeded: return first.isEmpty ? "Done" : first
        case .failed: return first.isEmpty ? "Failed" : "Failed · \(first)"
        case .skipped: return first.isEmpty ? "Skipped" : "Skipped · \(first)"
        case .cancelled: return "Outcome unknown"
        case .planned: return first.isEmpty ? "Planned" : first
        }
    }

    private func color(_ s: BulkStatusRow?) -> Color {
        switch s {
        case .none, .skipped: Color.textMuted
        case .running: Tone.info.text
        case .planned: Tone.info.text
        case .succeeded: Color.text
        case .failed: Tone.critical.text
        case .cancelled: Tone.warn.text
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

/// Minutes since midnight as `HH:MM`.
enum MinuteOfDay {
    static func text(_ minutes: UInt32) -> String {
        String(format: "%02d:%02d", minutes / 60, minutes % 60)
    }
}

/// A time of day (minutes since midnight) as a compact picker.
struct MinuteOfDayPicker: View {
    let title: String
    @Binding var minutes: UInt32

    private var date: Binding<Date> {
        Binding(
            get: {
                Calendar.current.date(
                    bySettingHour: Int(minutes / 60) % 24, minute: Int(minutes % 60), second: 0,
                    of: Date()) ?? Date()
            },
            set: { d in
                let c = Calendar.current.dateComponents([.hour, .minute], from: d)
                minutes = UInt32((c.hour ?? 0) * 60 + (c.minute ?? 0))
            })
    }

    var body: some View {
        DatePicker(title, selection: date, displayedComponents: .hourAndMinute)
    }
}

/// From/To of a reboot window: the server's local time, minutes since its
/// midnight; an end before the start wraps past midnight.
struct RebootWindowFields: View {
    @Binding var start: UInt32
    @Binding var end: UInt32

    var body: some View {
        HStack {
            MinuteOfDayPicker(title: "From", minutes: $start)
                .accessibilityIdentifier("bulk.windowStart")
            MinuteOfDayPicker(title: "To", minutes: $end)
                .accessibilityIdentifier("bulk.windowEnd")
        }
        Text(start == end
            ? "The window needs different start and end times."
            : "Server-local time. Each server reboots at the window's start, or right away when the window is open now.")
            .font(.caption11).foregroundStyle(start == end ? Tone.critical.text : Color.textMuted)
            .accessibilityIdentifier("bulk.windowNote")
    }
}

/// Schedules a reboot on servers whose upgrade said one is required, after
/// the rollout finished. Progress lines land on the run's rows.
private final class RebootFollowUp: BulkListener, @unchecked Sendable {
    weak var progress: BulkProgress?
    let scheduledNote: String
    init(progress: BulkProgress, scheduledNote: String) {
        self.progress = progress
        self.scheduledNote = scheduledNote
    }
    func onEvent(event: BulkEventRow) {
        guard case .server(let id, let status, let detail) = event else { return }
        switch status {
        case .succeeded:
            Task { @MainActor [weak progress, scheduledNote] in progress?.note(id, scheduledNote) }
        case .failed:
            Task { @MainActor [weak progress] in
                progress?.note(id, "Reboot not scheduled: \(detail.prefix(200))")
            }
        default: break
        }
    }
}

struct BulkRunSheet: View {
    @Environment(CoreBridge.self) private var core
    @Environment(\.dismiss) private var dismiss
    @State var draft = OpDraft()
    @State var targets: [String]
    @State private var canary = true
    @State private var healthCheck = true
    @State private var batchSize = 4
    @State private var stopOnFailure = true
    @State private var rebootIfRequired = false
    /// Reboot in a daily window (server-local time) instead of 60 s after.
    @State private var rebootInWindow = false
    @State private var rebootStart: UInt32 = 180
    @State private var rebootEnd: UInt32 = 300
    @State private var timeout: UInt32 = 0
    @State private var preview: BulkPreviewRow?
    @State private var previewError: String?
    @State private var progress = BulkProgress()
    @State private var confirmShown = false
    /// Servers taken out of `targets` by a suggested exclusion.
    @State private var skipped = Set<String>()
    @State private var considered = Set<String>()
    @State private var lastRunDry = false
    @State private var showPlan = false
    @State private var saveShown = false
    @State private var runbookName = ""
    @State private var savedNote: String?

    init(targets: [String], draft: OpDraft = OpDraft()) {
        _targets = State(initialValue: targets)
        _draft = State(initialValue: draft)
    }

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider()
            HSplitView {
                form.frame(minWidth: 360, idealWidth: 440, maxHeight: .infinity)
                VStack(alignment: .leading, spacing: 12) {
                    BulkProgressView(progress: progress, controls: true)
                }
                .padding(16)
                // The progress table is sized to its rows: pin the pane to
                // the top so the split view still fills the sheet.
                .frame(minWidth: 460, maxHeight: .infinity, alignment: .top)
            }
            .frame(maxHeight: .infinity)
            Divider()
            footer
        }
        .frame(minWidth: 960, minHeight: 640)
        .background(Color.window)
        .onChange(of: draft) { refreshPreview() }
        .onChange(of: targets) { applySuggestions() }
        .onAppear { refreshPreview(); applySuggestions() }
        .confirmationDialog(confirmTitle, isPresented: $confirmShown) {
            Button("Run", role: .destructive) { run(dryRun: false) }
                .accessibilityIdentifier("bulk.confirmRun")
        } message: {
            Text(preview?.command ?? "")
        }
        .sheet(isPresented: $showPlan) { planSheet }
        .alert("Save as runbook", isPresented: $saveShown) {
            TextField("Name", text: $runbookName)
            Button("Save") { saveRunbook() }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("Saves this operation, targets and rollout for repeat runs.")
        }
    }

    private var header: some View {
        HStack {
            VStack(alignment: .leading, spacing: 2) {
                Text("Run on servers").font(.toolbarTitle)
                Text(subtitle)
                    .font(.secondary).foregroundStyle(Color.textMuted)
                    .accessibilityIdentifier("bulk.subtitle")
            }
            Spacer()
            if let savedNote {
                Text(savedNote).font(.secondary).foregroundStyle(Tone.ok.text)
                    .accessibilityIdentifier("bulk.savedNote")
            }
            Button("Save as runbook") {
                runbookName = ""
                saveShown = true
            }
            .buttonStyle(.fleetSecondary)
            .disabled(effectiveTargets.isEmpty || preview == nil)
            .accessibilityIdentifier("bulk.saveRunbook")
        }
        .padding(16)
    }

    /// Always visible, so Run is never scrolled out of the form.
    private var footer: some View {
        HStack(spacing: 8) {
            Spacer()
            // "Close", not "Cancel": dismissing doesn't stop a running rollout.
            Button("Close") { dismiss() }
                .buttonStyle(.fleetSecondary)
                .accessibilityIdentifier("bulk.close")
                .keyboardShortcut(.cancelAction)
            Button("Dry run") { run(dryRun: true) }
                .buttonStyle(.fleetSecondary)
                .disabled(runDisabled)
                .help(preview?.hasPlan == true ? "Fetches the plan from each server" : "Shows the command for each server")
                .accessibilityIdentifier("bulk.dryRun")
            Button("Run on \(effectiveTargets.count) server\(effectiveTargets.count == 1 ? "" : "s")") { confirmShown = true }
                .buttonStyle(.fleetPrimary)
                .disabled(runDisabled)
                .accessibilityIdentifier("bulk.run")
        }
        .padding(.horizontal, 16).padding(.vertical, 12)
        .background(Color.header)
    }

    private var runDisabled: Bool {
        effectiveTargets.isEmpty || preview == nil || progress.isRunning
    }

    private var subtitle: String {
        var s = "\(preview?.opName ?? draft.kind.rawValue) · \(effectiveTargets.count) targets"
        if let t = progress.started {
            s += " · started " + t.formatted(date: .omitted, time: .shortened)
        }
        return s
    }

    private var effectiveTargets: [String] { targets }

    // MARK: form

    private var form: some View {
        Form {
            Section("What to run") {
                OpEditor(draft: $draft)
                if let p = preview {
                    if p.elevated {
                        Label("Elevated: one Touch ID approves all \(effectiveTargets.count) servers.",
                              systemImage: "touchid")
                            .foregroundStyle(Tone.warn.text)
                    } else {
                        Text("A typed operation: validated arguments, no shell involved, signed separately for every server.")
                            .font(.caption11).foregroundStyle(Color.textMuted)
                    }
                }
                if let e = previewError {
                    Text(e).font(.caption11).foregroundStyle(Tone.critical.text)
                }
            }
            Section("Targets · \(effectiveTargets.count) servers") {
                TargetPicker(selected: $targets)
                suggestions
            }
            Section("Rollout") {
                Toggle("Canary: 1 server, then health check", isOn: $canary)
                    .accessibilityIdentifier("bulk.canary")
                Toggle("Health check after canary", isOn: $healthCheck).disabled(!canary)
                    .accessibilityIdentifier("bulk.healthCheck")
                Stepper("Then in batches of \(batchSize)", value: $batchSize, in: 1...64)
                    .accessibilityIdentifier("bulk.concurrency")
                Toggle("Stop on first failure", isOn: $stopOnFailure)
                    .accessibilityIdentifier("bulk.stopOnFailure")
                if draft.kind == .pkgUpgrade {
                    Toggle("Reboot if required", isOn: $rebootIfRequired)
                        .accessibilityIdentifier("bulk.reboot")
                        .help("Servers whose upgrade says a reboot is required are rebooted once the whole rollout finished")
                    if rebootIfRequired {
                        Picker("When", selection: $rebootInWindow) {
                            Text("60 s after the rollout").tag(false)
                            Text("In a daily window").tag(true)
                        }
                        .accessibilityIdentifier("bulk.rebootTiming")
                        if rebootInWindow {
                            RebootWindowFields(start: $rebootStart, end: $rebootEnd)
                        }
                    }
                }
                TextField("Per-server timeout (s, 0 = default)", value: $timeout, format: .number)
                    .accessibilityIdentifier("bulk.timeout")
            }
            Section {
                dryRunCard
            }
        }
        .formStyle(.grouped)
    }

    // MARK: suggested exclusions

    private struct Suggestion: Identifiable {
        let id: String
        let text: String
    }

    /// Servers that are offline or nearly out of disk.
    private func problem(_ s: ServerRow) -> String? {
        if s.state == .offline { return "offline" }
        if let d = s.diskPercent, d >= 90 { return "disk at \(Int(d.rounded()))%" }
        return nil
    }

    private var suggestionList: [Suggestion] {
        core.servers.compactMap { s in
            guard targets.contains(s.id) || skipped.contains(s.id), let p = problem(s) else { return nil }
            return Suggestion(id: s.id, text: "Skip \(s.name) · \(p)")
        }
    }

    @ViewBuilder
    private var suggestions: some View {
        ForEach(suggestionList) { s in
            Toggle(s.text, isOn: Binding(
                get: { skipped.contains(s.id) },
                set: { skip in
                    if skip { skipped.insert(s.id); targets.removeAll { $0 == s.id } }
                    else { skipped.remove(s.id); if !targets.contains(s.id) { targets.append(s.id) } }
                }))
            .accessibilityIdentifier("bulk.skip.\(core.servers.first { $0.id == s.id }?.name ?? s.id)")
        }
    }

    /// Newly chosen problem servers start out skipped.
    private func applySuggestions() {
        for s in core.servers where targets.contains(s.id) && problem(s) != nil {
            if considered.insert(s.id).inserted {
                skipped.insert(s.id)
                targets.removeAll { $0 == s.id }
            }
        }
    }

    // MARK: dry run

    private struct DryResult {
        let ok: Bool
        let text: String
    }

    private var dryResult: DryResult? {
        guard lastRunDry, let s = progress.summary else { return nil }
        let planned = progress.rows.filter { $0.status == .planned }
        let packages = planned.reduce(0) { $0 + Self.packageCount($1.detail) }
        let isPkg = planned.contains { Self.packageCount($0.detail) > 0 }
        let servers = planned.count
        if s.failed > 0 {
            return DryResult(ok: false, text: "Dry run failed on \(s.failed) of \(progress.rows.count) servers")
        }
        let base = isPkg
            ? "\(packages) package\(packages == 1 ? "" : "s") across \(servers) server\(servers == 1 ? "" : "s")"
            : "\(servers) server\(servers == 1 ? "" : "s") planned"
        return DryResult(ok: true, text: base)
    }

    /// N from a "Would upgrade N packages" first line.
    private static func packageCount(_ detail: String) -> Int {
        let first = detail.split(separator: "\n").first.map(String.init) ?? ""
        guard first.hasPrefix("Would upgrade ") else { return 0 }
        return Int(first.dropFirst("Would upgrade ".count).prefix { $0.isNumber }) ?? 0
    }

    @ViewBuilder
    private var dryRunCard: some View {
        if let r = dryResult {
            HStack(spacing: 12) {
                Image(systemName: r.ok ? "checkmark" : "exclamationmark.triangle")
                    .foregroundStyle(r.ok ? Tone.ok.dot : Tone.warn.dot)
                VStack(alignment: .leading, spacing: 2) {
                    Text(r.ok ? "Dry run passed" : "Dry run failed").fontWeight(.medium)
                    Text(r.text).font(.secondary).foregroundStyle(Color.textMuted)
                }
                Spacer()
                Button("View plan") { showPlan = true }
                    .accessibilityIdentifier("bulk.viewPlan")
            }
            .accessibilityElement(children: .contain)
            .accessibilityIdentifier("bulk.dryResult")
        }
    }

    private var planSheet: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text("Dry-run plan").font(.toolbarTitle)
                Spacer()
                Button("Close") { showPlan = false }
                    .keyboardShortcut(.cancelAction)
                    .accessibilityIdentifier("bulk.plan.close")
            }
            ScrollView {
                VStack(alignment: .leading, spacing: 12) {
                    ForEach(progress.rows) { r in
                        VStack(alignment: .leading, spacing: 3) {
                            Text(core.servers.first { $0.id == r.id }?.name ?? r.id)
                                .fontWeight(.medium)
                            Text(r.detail.isEmpty ? "Nothing to change" : r.detail)
                                .font(.mono(11)).foregroundStyle(Color.textSecondary)
                                .textSelection(.enabled)
                        }
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
        .padding(20)
        .frame(width: 560, height: 420)
        .background(Color.window)
    }

    // MARK: actions

    private var confirmTitle: String {
        "Run \(preview?.opName ?? "") on \(effectiveTargets.count) servers?"
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

    private func saveRunbook() {
        guard let api = core.api else { return }
        let name = runbookName.trimmingCharacters(in: .whitespaces)
        guard !name.isEmpty else { return }
        let step = RunbookStepRow(
            name: preview?.opName ?? draft.kind.rawValue, op: draft.row, when: .always,
            canary: canary && effectiveTargets.count > 1, stopOnFailure: stopOnFailure,
            concurrency: UInt16(batchSize))
        let rb = RunbookRow(
            id: "", name: name, description: "", targets: effectiveTargets, params: [],
            steps: [step], scheduleMinutes: nil, lastRunMs: nil, updatedMs: 0)
        do {
            _ = try api.saveRunbook(runbook: rb)
            savedNote = "Saved runbook \(name)"
        } catch {
            previewError = error.fleetMessage
        }
    }

    private func run(dryRun: Bool) {
        guard let api = core.api else { return }
        lastRunDry = dryRun
        let ids = effectiveTargets
        progress.reset(targets: ids, canary: canary && ids.count > 1, batchSize: batchSize)
        let opts = BulkOptionsRow(
            concurrency: UInt32(batchSize), canary: canary, healthCheck: canary && healthCheck,
            stopOnFailure: stopOnFailure, perServerTimeoutS: timeout, dryRun: dryRun,
            batched: true)
        do {
            progress.handle = try api.bulkRun(
                targets: ids, op: draft.row, options: opts, listener: progress.listener())
            if !dryRun, rebootIfRequired, draft.kind == .pkgUpgrade {
                scheduleReboots(after: progress)
            }
        } catch {
            previewError = error.fleetMessage
        }
    }

    /// When the upgrade run ends, reboot the servers that asked for it.
    private func scheduleReboots(after run: BulkProgress) {
        Task { @MainActor in
            while run.isRunning || run.summary == nil && run.error == nil {
                try? await Task.sleep(for: .milliseconds(500))
                if run.handle == nil { return }
            }
            // A cancelled or failed-out run does not reboot anything.
            guard let api = core.api, let s = run.summary, s.stop == nil else { return }
            let ids = run.rows.filter {
                $0.status == .succeeded && $0.detail.contains("reboot required")
            }.map(\.id)
            guard !ids.isEmpty else { return }
            let opts = BulkOptionsRow(
                concurrency: 4, canary: false, healthCheck: false, stopOnFailure: false,
                perServerTimeoutS: 0, dryRun: false)
            let op: BulkOpRow = rebootInWindow
                ? .systemRebootWindow(startMin: rebootStart, endMin: rebootEnd)
                : .systemReboot(delayS: 60)
            let note = rebootInWindow
                ? "Reboot scheduled for the window \(MinuteOfDay.text(rebootStart))–\(MinuteOfDay.text(rebootEnd)) (server time)"
                : "Reboot scheduled in 60 s"
            _ = try? api.bulkRun(
                targets: ids, op: op, options: opts,
                listener: RebootFollowUp(progress: run, scheduledNote: note))
        }
    }
}
