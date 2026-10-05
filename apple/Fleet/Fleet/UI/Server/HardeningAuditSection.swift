import SwiftUI

/// State of the hardening audit (design §2.4, §9.9), shared by the
/// Hardening card and the Needs-attention list on the Security tab: the
/// score, every finding, one-click fixes (plan first, diff, apply after
/// confirmation; SSH/firewall fixes are auto-reverted unless a fresh
/// connection confirms them) and the exceptions the operator accepted.
@Observable
@MainActor
final class HardeningModel {
    var report: AuditReportRow?
    var level: ProfileLevelRow?
    var loading = false
    var error: String?
    var fix: AuditFixPlanRow?
    var fixing: String?
    var result: String?
    var auditedAt: Date?
    /// Modules the operator accepted on this server (local to this Mac).
    var accepted: Set<String> = []

    func passing(_ r: AuditReportRow) -> Int {
        r.findings.filter { $0.status == "compliant" || $0.status == "pending_reboot" }.count
    }

    func toFix(_ r: AuditReportRow) -> [AuditFindingRow] {
        r.findings.filter { ($0.status == "drifted" || $0.status == "error") && !accepted.contains($0.module) }
    }

    func exceptions(_ r: AuditReportRow) -> [AuditFindingRow] {
        r.findings.filter { $0.status != "compliant" && accepted.contains($0.module) }
    }

    func pendingReboot(_ r: AuditReportRow) -> Int {
        r.findings.filter { $0.status == "pending_reboot" }.count
    }

    func loadAccepted(api: FleetCore, serverId: String) {
        accepted = Set((try? api.auditExceptions(serverId: serverId)) ?? [])
    }

    func run(api: FleetCore, serverId: String) async {
        loading = true
        defer { loading = false }
        error = nil
        do {
            report = try await api.auditRun(serverId: serverId, level: level)
            auditedAt = Date()
        } catch {
            self.error = error.fleetMessage
        }
    }

    func setAccepted(api: FleetCore, serverId: String, module: String, _ on: Bool) {
        do {
            try api.auditExceptionSet(serverId: serverId, module: module, accepted: on)
            if on { accepted.insert(module) } else { accepted.remove(module) }
        } catch {
            self.error = error.fleetMessage
        }
    }

    func plan(api: FleetCore, serverId: String, module: String) {
        fixing = module
        result = nil
        Task {
            defer { fixing = nil }
            do {
                fix = try await api.auditFixPlan(serverId: serverId, module: module)
            } catch {
                self.error = error.fleetMessage
            }
        }
    }

    func apply(api: FleetCore, serverId: String, plan: AuditFixPlanRow) {
        fixing = plan.module
        Task {
            defer { fixing = nil }
            do {
                let r = try await api.auditFixApply(serverId: serverId, module: plan.module,
                                                    planHash: plan.planHash)
                result = "\(plan.module) fixed (profile score \(r.scoreBefore) → \(r.scoreAfter))"
                    + (r.confirmed ? ", confirmed from a fresh connection." : ".")
                await run(api: api, serverId: serverId)
            } catch {
                self.error = error.fleetMessage
            }
        }
    }
}

/// Security tab, Hardening card: score ring, check counts and the findings.
struct HardeningAuditSection: View {
    @Environment(CoreBridge.self) private var core
    let server: ServerRow
    @Bindable var model: HardeningModel
    let security: SecurityModeModel
    @State private var showCompliant = false

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text("Hardening").font(.system(size: 13, weight: .semibold))
                if let at = model.auditedAt {
                    Text("Audited \(at.formatted(date: .omitted, time: .shortened))")
                        .font(.secondary).foregroundStyle(Color.textMuted)
                }
                if model.loading { ProgressView().controlSize(.small) }
                Spacer()
                Picker("Level", selection: $model.level) {
                    Text("As provisioned").tag(ProfileLevelRow?.none)
                    Text("Baseline").tag(Optional(ProfileLevelRow.baseline))
                    Text("Strict").tag(Optional(ProfileLevelRow.strict))
                }
                .labelsHidden()
                .frame(width: 150)
                .accessibilityIdentifier("hardening.level")
                Button(model.report == nil ? "Run audit" : "Re-run audit") {
                    Task { await run() }
                }
                .disabled(model.loading || core.api == nil)
                .accessibilityIdentifier("hardening.run")
            }
            if let error = model.error {
                Text(error).font(.secondary).foregroundStyle(Tone.warn.text)
            }
            if let result = model.result {
                Text(result).font(.secondary).foregroundStyle(Tone.ok.text)
            }
            if let r = model.report {
                summary(r)
                let open = r.findings.filter { $0.status != "compliant" }
                ForEach(Indexed.wrap(open)) { f in finding(f.value) }
                let done = r.findings.filter { $0.status == "compliant" }
                if !done.isEmpty {
                    DisclosureGroup("\(done.count) passing checks", isExpanded: $showCompliant) {
                        VStack(alignment: .leading, spacing: 6) {
                            ForEach(Indexed.wrap(done)) { f in finding(f.value) }
                        }
                        .padding(.top, 6)
                    }
                    .font(.secondary)
                    .accessibilityIdentifier("hardening.passing")
                }
            } else if !model.loading {
                Text("Compares the server with the Baseline or Strict profile. Nothing changes until you apply a fix.")
                    .font(.secondary).foregroundStyle(Color.textMuted)
            }
        }
        .frame(maxWidth: .infinity, alignment: .topLeading)
        .card()
        .task(id: server.id) {
            if let api = core.api { model.loadAccepted(api: api, serverId: server.id) }
        }
        .sheet(item: $model.fix) { plan in
            FixPlanSheet(plan: plan) {
                if let api = core.api { model.apply(api: api, serverId: server.id, plan: plan) }
            }
        }
    }

    private func summary(_ r: AuditReportRow) -> some View {
        HStack(spacing: 20) {
            ScoreRing(score: r.score)
            VStack(alignment: .leading, spacing: 6) {
                Text(levelName(r.level)).font(.base).foregroundStyle(Color.textSecondary)
                HStack(spacing: 8) {
                    StatusPill(label: "\(model.passing(r)) checks passing", tone: model.passing(r) == 0 ? .neutral : .ok)
                        .accessibilityIdentifier("hardening.passingCount")
                    StatusPill(label: "\(model.toFix(r).count) to fix",
                               tone: model.toFix(r).isEmpty ? .neutral : .warn)
                        .accessibilityIdentifier("hardening.toFixCount")
                    StatusPill(label: "\(model.exceptions(r).count) accepted exception\(model.exceptions(r).count == 1 ? "" : "s")",
                               tone: .neutral)
                        .accessibilityIdentifier("hardening.acceptedCount")
                }
                if model.pendingReboot(r) > 0 {
                    Text("\(model.pendingReboot(r)) take effect at the next reboot")
                        .font(.secondary).foregroundStyle(Tone.info.text)
                }
            }
            Spacer()
        }
    }

    private func levelName(_ l: ProfileLevelRow) -> String {
        switch l {
        case .baseline: "Baseline profile"
        case .strict: "Strict profile"
        }
    }

    private func finding(_ f: AuditFindingRow) -> some View {
        let isAccepted = model.accepted.contains(f.module)
        let open = f.status == "drifted" || f.status == "error"
        return HStack(spacing: 10) {
            StatusPill(label: isAccepted && open ? "accepted" : label(f.status),
                       tone: isAccepted && open ? .neutral : tone(f.status))
            Text(f.module).font(.mono(11)).frame(width: 140, alignment: .leading)
            Text(f.title).lineLimit(2)
            Spacer()
            Text(f.severity).font(.caption11).foregroundStyle(Color.textMuted)
                .frame(width: 56, alignment: .leading)
            // Fixed-width action slot keeps the severity column aligned on rows without buttons.
            HStack(spacing: 6) {
            if open {
                if isAccepted {
                    Button("Undo") { accept(f.module, false) }
                        .controlSize(.small)
                        .accessibilityIdentifier("hardening.unaccept.\(f.module)")
                } else {
                    if f.fixable && f.status == "drifted" {
                        Button(model.fixing == f.module ? "Planning…" : "Fix") { plan(f.module) }
                            .controlSize(.small)
                            .disabled(model.fixing != nil || core.api == nil || !security.allowsChanges)
                            .help(security.blockedReason ?? "")
                            .accessibilityIdentifier("hardening.fix.\(f.module)")
                    }
                    Button("Accept") { accept(f.module, true) }
                        .controlSize(.small)
                        .help("Leave this as it is and stop counting it as a problem (kept on this Mac only)")
                        .accessibilityIdentifier("hardening.accept.\(f.module)")
                }
            }
            }
            .frame(width: 120, alignment: .trailing)
        }
        .font(.secondary)
    }

    private func label(_ s: String) -> String {
        switch s {
        case "pending_reboot": "pending reboot"
        case "not_applicable": "n/a"
        default: s
        }
    }

    private func tone(_ s: String) -> Tone {
        switch s {
        case "compliant": .ok
        case "pending_reboot": .info
        case "drifted": .warn
        case "error": .critical
        default: .neutral
        }
    }

    private func run() async {
        guard let api = core.api else { return }
        await model.run(api: api, serverId: server.id)
    }

    private func plan(_ module: String) {
        guard let api = core.api else { return }
        model.plan(api: api, serverId: server.id, module: module)
    }

    private func accept(_ module: String, _ on: Bool) {
        guard let api = core.api else { return }
        model.setAccepted(api: api, serverId: server.id, module: module, on)
    }
}

extension AuditFixPlanRow: Identifiable { public var id: String { planHash } }

private struct FixPlanSheet: View {
    @Environment(\.dismiss) private var dismiss
    let plan: AuditFixPlanRow
    let apply: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Fix \(plan.module)").font(.sectionTitle)
            if plan.autoRevert {
                StatusPill(label: "SSH/firewall: reverts unless a fresh connection confirms it", tone: .info)
            }
            ScrollView {
                VStack(alignment: .leading, spacing: 8) {
                    ForEach(Indexed.wrap(plan.changes)) { c in
                        VStack(alignment: .leading, spacing: 4) {
                            Text(c.value.description).font(.base)
                            if !c.value.diff.isEmpty {
                                Text(c.value.diff).font(.mono(11)).foregroundStyle(Color.textSecondary)
                                    .textSelection(.enabled)
                                    .frame(maxWidth: .infinity, alignment: .leading)
                                    .padding(8)
                                    .background(Color.track, in: RoundedRectangle(cornerRadius: 6))
                            }
                        }
                    }
                    if plan.changes.isEmpty {
                        Text("Nothing to change.").foregroundStyle(Color.textMuted)
                    }
                }
            }
            .frame(maxHeight: 360)
            HStack {
                Button("Cancel") { dismiss() }
                Spacer()
                Button("Apply fix") {
                    dismiss()
                    apply()
                }
                .buttonStyle(.borderedProminent).tint(.accent)
                .disabled(plan.changes.isEmpty)
                .accessibilityIdentifier("hardening.applyFix")
            }
        }
        .padding(24)
        .frame(width: 620)
    }
}
