import SwiftUI

/// Security tab: hardening audit (design §2.4, §9.9) with the score, every
/// finding and a one-click fix: plan first (`only = [module]`), show the
/// diff, apply after confirmation. SSH/firewall fixes are auto-reverted
/// unless a fresh connection confirms them.
struct HardeningAuditSection: View {
    @Environment(CoreBridge.self) private var core
    let server: ServerRow
    @State private var report: AuditReportRow?
    @State private var level: ProfileLevelRow?
    @State private var loading = false
    @State private var error: String?
    @State private var fix: AuditFixPlanRow?
    @State private var fixing: String?
    @State private var result: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Text("Hardening audit").font(.system(size: 13, weight: .semibold))
                if loading { ProgressView().controlSize(.small) }
                Spacer()
                Picker("Level", selection: $level) {
                    Text("As provisioned").tag(ProfileLevelRow?.none)
                    Text("Baseline").tag(Optional(ProfileLevelRow.baseline))
                    Text("Strict").tag(Optional(ProfileLevelRow.strict))
                }
                .labelsHidden()
                .frame(width: 150)
                Button("Run audit") { Task { await load() } }
            }
            if let error {
                Text(error).font(.secondary).foregroundStyle(Tone.warn.text)
            }
            if let result {
                Text(result).font(.secondary).foregroundStyle(Tone.ok.text)
            }
            if let r = report {
                HStack(spacing: 16) {
                    ScoreBox(title: "Score", score: r.score)
                    VStack(alignment: .leading, spacing: 4) {
                        Text("\(drifted(r)) drifted · \(fixable(r)) fixable")
                        if pending(r) > 0 {
                            Text("\(pending(r)) take effect at the next reboot")
                                .foregroundStyle(Tone.info.text)
                        }
                    }
                    .font(.secondary).foregroundStyle(Color.textSecondary)
                }
                ForEach(Indexed.wrap(r.findings)) { f in finding(f.value) }
            } else if !loading {
                Text("Compares the server with the Baseline or Strict profile. Nothing changes until you apply a fix.")
                    .font(.secondary).foregroundStyle(Color.textMuted)
            }
        }
        .frame(maxWidth: .infinity, alignment: .topLeading)
        .card()
        .sheet(item: $fix) { plan in
            FixPlanSheet(plan: plan) { apply(plan) }
        }
    }

    private func finding(_ f: AuditFindingRow) -> some View {
        HStack(spacing: 10) {
            StatusPill(label: label(f.status), tone: tone(f.status))
            Text(f.module).font(.mono(11)).frame(width: 140, alignment: .leading)
            Text(f.title).lineLimit(2)
            Spacer()
            Text(f.severity).font(.caption11).foregroundStyle(Color.textMuted)
            if f.fixable && f.status == "drifted" {
                Button(fixing == f.module ? "Planning…" : "Fix") { plan(f.module) }
                    .controlSize(.small)
                    .disabled(fixing != nil || core.api == nil)
            }
        }
        .font(.secondary)
    }

    private func drifted(_ r: AuditReportRow) -> Int { r.findings.filter { $0.status == "drifted" }.count }
    private func fixable(_ r: AuditReportRow) -> Int { r.findings.filter { $0.fixable }.count }
    private func pending(_ r: AuditReportRow) -> Int { r.findings.filter { $0.status == "pending_reboot" }.count }

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

    private func load() async {
        guard let api = core.api else { return }
        loading = true
        defer { loading = false }
        error = nil
        do {
            report = try await api.auditRun(serverId: server.id, level: level)
        } catch {
            self.error = error.fleetMessage
        }
    }

    private func plan(_ module: String) {
        guard let api = core.api else { return }
        fixing = module
        result = nil
        Task {
            defer { fixing = nil }
            do {
                fix = try await api.auditFixPlan(serverId: server.id, module: module)
            } catch {
                self.error = error.fleetMessage
            }
        }
    }

    private func apply(_ plan: AuditFixPlanRow) {
        guard let api = core.api else { return }
        fixing = plan.module
        Task {
            defer { fixing = nil }
            do {
                let r = try await api.auditFixApply(serverId: server.id, module: plan.module,
                                                    planHash: plan.planHash)
                result = "\(plan.module) fixed (profile score \(r.scoreBefore) → \(r.scoreAfter))"
                    + (r.confirmed ? ", confirmed from a fresh connection." : ".")
                await load()
            } catch {
                self.error = error.fleetMessage
            }
        }
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
            }
        }
        .padding(24)
        .frame(width: 620)
    }
}
