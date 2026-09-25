import SwiftUI

/// One rule as the editor holds it (text fields, validated in the core).
struct RuleDraft: Identifiable, Equatable {
    let id = UUID()
    var chain: FwChainArg = .input
    var action: FwActionArg = .accept
    var proto: FwProtoArg = .tcp
    var ports = ""
    var source = ""
    var rate = ""
    var burst = "10"
    var comment = ""

    init() {}

    init(_ a: FirewallRuleArgs) {
        chain = a.chain
        action = a.action
        proto = a.proto
        ports = a.ports.joined(separator: ", ")
        source = a.source ?? ""
        rate = a.ratePerMinute.map(String.init) ?? ""
        burst = String(a.rateBurst)
        comment = a.comment
    }

    var args: FirewallRuleArgs {
        FirewallRuleArgs(
            chain: chain, action: action, proto: proto,
            ports: ports.split(whereSeparator: { $0 == "," || $0 == " " }).map(String.init),
            source: source.trimmingCharacters(in: .whitespaces).isEmpty ? nil : source,
            ratePerMinute: UInt32(rate.trimmingCharacters(in: .whitespaces)),
            rateBurst: UInt16(burst.trimmingCharacters(in: .whitespaces)) ?? 10,
            comment: comment)
    }
}

/// Firewall (design §4.8): edit Fleet's own table, preview the diff, apply
/// with auto-revert and confirm from a fresh connection; bans and exempt
/// ranges; other tables read-only.
struct FirewallTab: View {
    @Environment(CoreBridge.self) private var core
    let server: ServerRow
    @State private var fw: FirewallRow?
    @State private var managed = true
    @State private var drafts: [RuleDraft] = []
    @State private var bans: BansRow?
    @State private var banConfig: BanConfigRow?
    @State private var exemptText = ""
    @State private var loading = false
    @State private var error: String?
    @State private var showForeign = false
    @State private var diff: [DiffLineRow]?
    @State private var pending: PendingAction?
    @State private var revert = AutoRevertModel()

    private var baseArgs: FirewallRulesetArgs? {
        fw.map { FirewallRulesetArgs(managed: $0.managed, rules: firewallRulesToArgs(rules: $0.rules)) }
    }

    private var proposed: FirewallRulesetArgs {
        FirewallRulesetArgs(managed: managed, rules: managed ? drafts.map(\.args) : [])
    }

    private var dirty: Bool {
        guard let base = baseArgs else { return false }
        return base != proposed
    }

    private var problems: [String] { firewallCheck(ruleset: proposed, sshPort: server.port) }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                TabHeader(title: "Firewall", loading: loading, error: error, refresh: { Task { await load() } })
                AutoRevertBanner(model: revert, what: "Firewall rules changed", retry: retryConfirm)
                if let fw {
                    rulesCard(fw)
                    bansCard
                    foreign(fw)
                    Text("Cooperative mode: Fleet manages only its own table (inet fleet). Docker's rules and other tables are never flushed or edited.")
                        .font(.caption11).foregroundStyle(Color.textMuted)
                } else if !loading {
                    Text("No data").foregroundStyle(Color.textMuted)
                }
            }
            .padding(24)
        }
        .task(id: server.id) { await load() }
        .confirmAction($pending)
        .sheet(isPresented: Binding(get: { diff != nil }, set: { if !$0 { diff = nil } })) {
            diffSheet
        }
    }

    // MARK: rules

    private func rulesCard(_ fw: FirewallRow) -> some View {
        AdminSection(title: "Inbound rules · table inet fleet · v\(fw.version)") {
            HStack(spacing: 8) {
                Picker("Mode", selection: $managed) {
                    Text("Managed").tag(true)
                    Text("Bans only").tag(false)
                }
                .pickerStyle(.segmented).labelsHidden().frame(width: 200)
                Button("Add rule", systemImage: "plus") { drafts.append(RuleDraft()) }
                    .disabled(!managed)
                Button("Revert edits") { resetDrafts() }.disabled(!dirty)
                Button("Preview diff") { preview() }.disabled(!dirty)
                Button("Apply…") { askApply(fw) }
                    .buttonStyle(.borderedProminent).tint(.accent)
                    .disabled(!dirty || !problems.isEmpty || revert.phase == .confirming)
            }
        } content: {
            if managed {
                header
                List {
                    ForEach($drafts) { $d in ruleRow($d) }
                        .onMove { drafts.move(fromOffsets: $0, toOffset: $1) }
                        .onDelete { drafts.remove(atOffsets: $0) }
                }
                .listStyle(.plain)
                .scrollContentBackground(.hidden)
                .frame(minHeight: CGFloat(max(drafts.count, 1)) * 36 + 12)
                HStack {
                    Text("—").frame(width: 24)
                    StatusPill(label: "Drop", tone: .critical)
                    Text("All other inbound traffic · \(fw.banned) addresses currently banned")
                        .font(.secondary).foregroundStyle(Color.textSecondary)
                }
            } else {
                Text("Bans only: the chains accept by default and hold only the ban sets. The server's existing firewall stays in charge.")
                    .font(.secondary).foregroundStyle(Color.textSecondary)
            }
            ForEach(problems, id: \.self) { p in
                Label(p, systemImage: "exclamationmark.triangle").font(.secondary)
                    .foregroundStyle(Tone.critical.text)
            }
            Text("Drag to reorder. SSH (tcp/\(server.port)) must stay allowed; enrolled Macs keep SSH through the exempt set even with a source-restricted rule.")
                .font(.caption11).foregroundStyle(Color.textMuted)
        }
    }

    private var header: some View {
        HStack(spacing: 8) {
            Text("Chain").frame(width: 90, alignment: .leading)
            Text("Action").frame(width: 90, alignment: .leading)
            Text("Proto").frame(width: 70, alignment: .leading)
            Text("Ports").frame(width: 130, alignment: .leading)
            Text("Source").frame(width: 150, alignment: .leading)
            Text("Rate / min").frame(width: 110, alignment: .leading)
            Text("Comment").frame(maxWidth: .infinity, alignment: .leading)
        }
        .font(.caption11).foregroundStyle(Color.textMuted).padding(.leading, 8)
    }

    private func ruleRow(_ d: Binding<RuleDraft>) -> some View {
        HStack(spacing: 8) {
            Picker("", selection: d.chain) {
                Text("input").tag(FwChainArg.input)
                Text("forward").tag(FwChainArg.forward)
            }
            .labelsHidden().frame(width: 90)
            Picker("", selection: d.action) {
                Text("Allow").tag(FwActionArg.accept)
                Text("Drop").tag(FwActionArg.drop)
                Text("Reject").tag(FwActionArg.reject)
            }
            .labelsHidden().frame(width: 90)
            Picker("", selection: d.proto) {
                Text("tcp").tag(FwProtoArg.tcp)
                Text("udp").tag(FwProtoArg.udp)
            }
            .labelsHidden().frame(width: 70)
            TextField("22, 8000-8100", text: d.ports).frame(width: 130)
            TextField("any", text: d.source).frame(width: 150)
            HStack(spacing: 2) {
                TextField("–", text: d.rate).frame(width: 50)
                TextField("burst", text: d.burst).frame(width: 50)
            }
            .frame(width: 110)
            TextField("Comment", text: d.comment)
            Button { drafts.removeAll { $0.id == d.wrappedValue.id } } label: {
                Image(systemName: "minus.circle")
            }
            .buttonStyle(.plain).help("Remove rule")
        }
        .font(.mono(11))
        .textFieldStyle(.roundedBorder)
        .listRowBackground(Color.clear)
    }

    // MARK: bans

    private var bansCard: some View {
        HStack(alignment: .top, spacing: 16) {
            AdminSection(title: "Bans") {
                ForEach(Indexed.wrap(bans?.bans ?? [])) { b in
                    HStack {
                        Text("\(b.value.addr)/\(b.value.prefix)").font(.mono(11))
                        Text(b.value.reason).foregroundStyle(Color.textSecondary)
                        Spacer()
                        Text("until \(fmtDate(b.value.untilMs))").foregroundStyle(Color.textMuted)
                        Button("Unban") { askUnban(b.value.addr) }.controlSize(.small)
                    }
                    .font(.secondary)
                }
                if bans?.bans.isEmpty ?? true {
                    Text("None").font(.secondary).foregroundStyle(Color.textMuted)
                }
            }
            AdminSection(title: "Never ban") {
                Button("Save") { askSaveExempt() }
                    .disabled(banConfig == nil || exemptLines == banConfig?.exempt)
            } content: {
                TextEditor(text: $exemptText)
                    .font(.mono(11)).frame(height: 90)
                    .scrollContentBackground(.hidden)
                    .background(Color.track, in: RoundedRectangle(cornerRadius: 8))
                Text("One CIDR per line. Learned: \((bans?.learnedExempt ?? []).joined(separator: ", "))")
                    .font(.caption11).foregroundStyle(Color.textMuted)
                if let c = banConfig {
                    Text("Ban after \(c.threshold) failures in \(c.windowS) s")
                        .font(.caption11).foregroundStyle(Color.textMuted)
                }
            }
        }
    }

    private var exemptLines: [String] {
        exemptText.split(whereSeparator: \.isNewline)
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
    }

    private func foreign(_ fw: FirewallRow) -> some View {
        DisclosureGroup("Other rules on this server (not managed by Fleet)", isExpanded: $showForeign) {
            ScrollView {
                Text(fw.foreignRuleset.isEmpty ? "None" : fw.foreignRuleset)
                    .font(.mono(11)).foregroundStyle(Color.textSecondary)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .textSelection(.enabled)
            }
            .frame(maxHeight: 220)
            .padding(8)
            .background(Color.track, in: RoundedRectangle(cornerRadius: 8))
        }
        .font(.secondary)
    }

    private var diffSheet: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Changes to apply").font(.system(size: 15, weight: .semibold))
            ScrollView {
                VStack(alignment: .leading, spacing: 0) {
                    ForEach(Indexed.wrap(diff ?? [])) { l in
                        let (sign, tone): (String, Tone?) = switch l.value.kind {
                        case .added: ("+", .ok)
                        case .removed: ("−", .critical)
                        case .same: (" ", nil)
                        }
                        Text("\(sign) \(l.value.text)")
                            .font(.mono(11))
                            .foregroundStyle(tone?.text ?? Color.textSecondary)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .padding(.horizontal, 6)
                            .background(tone?.bg ?? .clear)
                    }
                }
            }
            .frame(minHeight: 200)
            HStack {
                Spacer()
                Button("Close") { diff = nil }
            }
        }
        .padding(20)
        .frame(minWidth: 640, minHeight: 360)
    }

    // MARK: actions

    private func resetDrafts() {
        managed = fw?.managed ?? true
        drafts = firewallRulesToArgs(rules: fw?.rules ?? []).map(RuleDraft.init)
    }

    private func preview() {
        guard let base = baseArgs else { return }
        do { diff = try firewallDiff(current: base, proposed: proposed) } catch { self.error = error.fleetMessage }
    }

    private func askApply(_ fw: FirewallRow) {
        let set = proposed
        let version = fw.version
        let modeChange = fw.managed != set.managed
        pending = PendingAction(
            title: "Apply firewall changes to \(server.name)?",
            message: (modeChange ? "The table switches to \(set.managed ? "Managed (default drop)" : "bans only"). " : "")
                + "The change reverts automatically unless Fleet can reconnect and confirm it within the window.",
            button: "Apply") { apply(set, version: version) }
    }

    private func apply(_ set: FirewallRulesetArgs, version: UInt64) {
        guard let api = core.api else { return }
        Task {
            do {
                let change = try await api.firewallApply(serverId: server.id, ruleset: set, expectedVersion: version)
                error = nil
                revert.confirm(api: api, serverId: server.id, change: change) { Task { await load() } }
            } catch {
                self.error = error.fleetMessage
            }
        }
    }

    private func retryConfirm() {
        guard let api = core.api, let c = revert.change else { return }
        revert.confirm(api: api, serverId: server.id, change: c) { Task { await load() } }
    }

    private func askUnban(_ addr: String) {
        pending = PendingAction(title: "Unban \(addr)?", message: "It can connect again right away.",
                                button: "Unban") {
            run { try await $0.banRemove(serverId: server.id, addr: addr) }
        }
    }

    private func askSaveExempt() {
        guard var c = banConfig else { return }
        c.exempt = exemptLines
        pending = PendingAction(title: "Save never-ban ranges?",
                                message: "Addresses in these ranges are never banned by intrusion blocking.",
                                button: "Save") {
            run { try await $0.bansConfigSet(serverId: server.id, config: c) }
        }
    }

    private func run(_ op: @escaping (FleetCore) async throws -> Void) {
        guard let api = core.api else { return }
        Task {
            do {
                try await op(api)
                error = nil
            } catch {
                self.error = error.fleetMessage
            }
            await load()
        }
    }

    private func load() async {
        guard let api = core.api else { return }
        loading = true
        defer { loading = false }
        do {
            fw = try await api.firewallGet(serverId: server.id)
            resetDrafts()
            error = nil
        } catch {
            self.error = error.fleetMessage
        }
        bans = try? await api.bansList(serverId: server.id)
        if let c = try? await api.bansConfigGet(serverId: server.id) {
            banConfig = c
            exemptText = c.exempt.joined(separator: "\n")
        }
        // A change applied earlier (another window, app restart) still waiting.
        if !revert.active, let changes = try? await api.changesList(serverId: server.id),
           let c = changes.first(where: { $0.kind == "firewall" }) {
            revert.confirm(api: api, serverId: server.id, change: c) { Task { await load() } }
        }
    }
}
