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
    /// Hit counters of the applied rules; nil on an agent without them.
    @State private var counters: FirewallCountersRow?
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
    @State private var security = SecurityModeModel()
    @State private var history: [FwHistoryRow] = []
    /// Docker's containers; nil when Docker isn't there (section hidden).
    @State private var containers: [ContainerRow]?
    /// Rules of the ruleset before the newest history entry (for "Added").
    @State private var previousRules: [FirewallRuleArgs] = []
    /// The next observed ruleset was applied from this Mac.
    @State private var appliedHere = false
    @State private var appliedTitle: String?
    /// What the change being confirmed did ("Added 9100/tcp from …").
    @State private var changeSummary: String?

    private var locked: Bool { !security.allowsChanges }
    private var lockReason: String { security.blockedReason ?? "" }

    private var baseArgs: FirewallRulesetArgs? {
        fw.map { FirewallRulesetArgs(managed: $0.managed, rules: firewallRulesToArgs(rules: $0.rules)) }
    }

    private var proposed: FirewallRulesetArgs {
        FirewallRulesetArgs(managed: managed, rules: managed ? drafts.map(\.args) : [])
    }

    /// Fleet's table doesn't exist on the server yet (`firewall.get` then
    /// reports bans-only, no rules, version 0). Nothing is enforced, bans
    /// included, until a first apply creates it.
    private var tableAbsent: Bool { fw?.version == 0 }

    private var dirty: Bool {
        guard let base = baseArgs else { return false }
        // Creating the table is a change even when the ruleset looks equal.
        return tableAbsent || base != proposed
    }

    private var problems: [String] { firewallCheck(ruleset: proposed, sshPort: server.port) }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                TabHeader(title: "Firewall", loading: loading, error: error, refresh: { Task { await load() } })
                SecurityModeNotice(model: security)
                AutoRevertBanner(model: revert, what: changeSummary ?? "Firewall rules changed",
                                 retry: retryConfirm, revertNow: revertNow)
                if let fw {
                    rulesCard(fw)
                    if containers != nil { containerCard }
                    historyCard(fw)
                    bansCard
                    foreign(fw)
                    cooperativeCard
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
        AdminSection(title: "Inbound rules") {
            HStack(spacing: 8) {
                Picker("Mode", selection: $managed) {
                    Text("Managed").tag(true)
                    Text("Bans only").tag(false)
                }
                .fleetSegmented().labelsHidden().frame(width: 200)
                .disabled(locked)
                .accessibilityIdentifier("firewall.mode")
                Button("Add rule", systemImage: "plus") { drafts.append(RuleDraft()) }
                    .disabled(!managed || locked)
                    .accessibilityIdentifier("firewall.addRule")
                Button("Revert edits") { resetDrafts() }.disabled(baseArgs == proposed)
                    .accessibilityIdentifier("firewall.revertEdits")
                Button("Preview diff") { preview() }.disabled(baseArgs == proposed)
                    .accessibilityIdentifier("firewall.previewDiff")
                Button(tableAbsent ? "Set up…" : "Apply…") { askApply(fw) }
                    .buttonStyle(.borderedProminent).tint(.accent)
                    .disabled(!dirty || !problems.isEmpty || revert.phase == .confirming || locked)
                    .help(lockReason)
                    .accessibilityIdentifier("firewall.apply")
            }
        } content: {
            if tableAbsent {
                Label("Not set up yet: Fleet's table doesn't exist on this server, so nothing is filtered or banned. "
                      + "Choose Bans only (keeps your existing firewall, adds intrusion bans) or Managed, then Set up.",
                      systemImage: "info.circle")
                    .font(.caption11).foregroundStyle(Color.textSecondary)
                    .accessibilityIdentifier("firewall.notSetUp")
            }
            Text(managed ? "table inet fleet · policy drop · IPv4 + IPv6" : "table inet fleet · bans only")
                .font(.caption11).foregroundStyle(Color.textMuted)
                .accessibilityIdentifier("firewall.tableSubtitle")
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
                .disabled(locked)
                HStack {
                    Text("—").frame(width: 24)
                    StatusPill(label: "Drop", tone: .critical)
                    Text("All other inbound traffic · \(fw.banned) addresses currently banned by intrusion blocking")
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
            Text("Drag to reorder. SSH (tcp/\(String(server.port))) must stay allowed; enrolled Macs keep SSH through the exempt set even with a source-restricted rule.")
                .font(.caption11).foregroundStyle(Color.textMuted)
        }
    }

    private var header: some View {
        HStack(spacing: 8) {
            Text("#").frame(width: 24, alignment: .leading)
            Text("Chain").frame(width: 90, alignment: .leading)
            Text("Action").frame(width: 90, alignment: .leading)
            Text("Proto").frame(width: 70, alignment: .leading)
            Text("Ports").frame(width: 130, alignment: .leading)
            Text("Source").frame(width: 150, alignment: .leading)
            Text("Rate / min").frame(width: 110, alignment: .leading)
            Text("Hits · since apply").frame(width: 100, alignment: .trailing)
                .help("Packets this rule matched since the table was last applied. nftables keeps no timestamps, so there is no 24 h window; every apply restarts the count.")
                .accessibilityIdentifier("firewall.hitsHeader")
            Text("Comment").frame(maxWidth: .infinity, alignment: .leading)
        }
        .font(.caption11).foregroundStyle(Color.textMuted).padding(.leading, 8)
    }

    /// "New" for an unsaved rule, "Added" for one the last applied change
    /// introduced (shortly after it was applied).
    private func rowTag(_ d: RuleDraft) -> String? {
        let a = d.args
        guard let base = baseArgs?.rules else { return nil }
        if !base.contains(a) { return "New" }
        let recent = history.count > 1
            && Date().timeIntervalSince1970 - Double(history[0].timeMs) / 1000 < 1800
        return recent && !previousRules.contains(a) ? "Added" : nil
    }

    /// Packet/byte hits of the applied rule this draft is (unsaved rules,
    /// and counters of another ruleset version, have none).
    private func hits(for d: RuleDraft) -> (text: String, help: String) {
        guard let fw, let counters, counters.version == fw.version,
              let index = baseArgs?.rules.firstIndex(of: d.args),
              let c = counters.rules.first(where: { Int($0.rule) == index })
        else { return ("–", "No counter: unsaved rule, or the table predates hit counters until it is applied again") }
        return (Self.compact(c.packets),
                "\(c.packets) packets, \(ByteCountFormatter.string(fromByteCount: Int64(clamping: c.bytes), countStyle: .binary)) since the table was last applied")
    }

    /// 0, 999, 1.2k, 3.4M, 5.6G.
    static func compact(_ n: UInt64) -> String {
        switch n {
        case ..<1_000: "\(n)"
        case ..<1_000_000: String(format: "%.1fk", Double(n) / 1e3)
        case ..<1_000_000_000: String(format: "%.1fM", Double(n) / 1e6)
        default: String(format: "%.1fG", Double(n) / 1e9)
        }
    }

    private func ruleRow(_ d: Binding<RuleDraft>) -> some View {
        let tag = rowTag(d.wrappedValue)
        let number = (drafts.firstIndex { $0.id == d.wrappedValue.id } ?? 0) + 1
        return HStack(spacing: 8) {
            Text("\(number)").foregroundStyle(Color.textMuted).frame(width: 24, alignment: .leading)
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
            let hit = hits(for: d.wrappedValue)
            Text(hit.text).foregroundStyle(Color.textSecondary)
                .frame(width: 100, alignment: .trailing)
                .help(hit.help)
                .accessibilityIdentifier("firewall.hits")
            TextField("Comment", text: d.comment)
            if let tag { StatusPill(label: tag, tone: .info).accessibilityIdentifier("firewall.ruleTag") }
            Button { drafts.removeAll { $0.id == d.wrappedValue.id } } label: {
                Image(systemName: "minus.circle")
            }
            .buttonStyle(.plain).help("Remove rule")
        }
        .font(.mono(11))
        .textFieldStyle(.roundedBorder)
        .listRowBackground(tag == nil ? Color.clear : Tone.info.bg)
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
                        Text(SecFormat.left(until: b.value.untilMs)).foregroundStyle(Color.textMuted)
                            .help("Until \(fmtDate(b.value.untilMs))")
                        Button("Unban") { askUnban(b.value.addr) }.controlSize(.small)
                            .disabled(locked)
                            .help(lockReason)
                    }
                    .font(.secondary)
                }
                if bans?.bans.isEmpty ?? true {
                    Text("None").font(.secondary).foregroundStyle(Color.textMuted)
                }
            }
            .fillingHeight()
            AdminSection(title: "Never ban") {
                Button("Save") { askSaveExempt() }
                    .disabled(banConfig == nil || exemptLines == banConfig?.exempt || locked)
                    .help(lockReason)
            } content: {
                TextEditor(text: $exemptText)
                    .font(.mono(11)).frame(height: 90)
                    .scrollContentBackground(.hidden)
                    .background(Color.track, in: RoundedRectangle(cornerRadius: 8))
                let learned = bans?.learnedExempt ?? []
                Text(learned.isEmpty ? "One CIDR per line."
                     : "One CIDR per line. Learned: \(learned.joined(separator: ", "))")
                    .font(.caption11).foregroundStyle(Color.textMuted)
                if let c = banConfig {
                    Text("Ban after \(c.threshold) failures in \(c.windowS) s")
                        .font(.caption11).foregroundStyle(Color.textMuted)
                }
            }
            .fillingHeight()
        }
        .fixedSize(horizontal: false, vertical: true)
    }

    // MARK: container ports

    enum Exposure: Equatable {
        case internalOnly, localOnly, published

        var label: String {
            switch self {
            case .internalOnly: "Internal"
            case .localOnly: "Local only"
            case .published: "Published"
            }
        }

        var tone: Tone {
            switch self {
            case .internalOnly: .neutral
            case .localOnly: .ok
            case .published: .warn
            }
        }
    }

    /// `127.0.0.1:8080→80/tcp` -> ("127.0.0.1", "8080 → 80/tcp"); a mapping
    /// with no host address (any) has host `nil`.
    static func portMapping(_ s: String) -> (host: String?, text: String) {
        let parts = s.components(separatedBy: "→")
        guard parts.count == 2 else { return (nil, s) }
        var left = parts[0]
        var host: String?
        if let i = left.lastIndex(of: ":") {
            host = String(left[..<i])
            left = String(left[left.index(after: i)...])
        }
        return (host, (host.map { "\($0):" } ?? "") + "\(left) → \(parts[1])")
    }

    static func exposure(_ ports: [String]) -> Exposure {
        if ports.isEmpty { return .internalOnly }
        let loopback: Set<String> = ["127.0.0.1", "::1"]
        return ports.allSatisfy { loopback.contains(portMapping($0).host ?? "") } ? .localOnly : .published
    }

    private var containerCard: some View {
        AdminSection(title: "Container ports") {
            Text("forward chain in table inet fleet").font(.caption11).foregroundStyle(Color.textMuted)
        } content: {
            ForEach(Indexed.wrap(containers ?? [])) { c in
                let e = Self.exposure(c.value.ports)
                HStack(spacing: 12) {
                    Text(c.value.name).font(.mono(11)).frame(width: 180, alignment: .leading)
                    Text(c.value.ports.isEmpty
                         ? "not published"
                         : c.value.ports.map { Self.portMapping($0).text }.joined(separator: ", "))
                        .foregroundStyle(Color.textSecondary).font(.mono(11))
                    Spacer()
                    StatusPill(label: e.label, tone: e.tone)
                }
                .font(.secondary)
                .accessibilityIdentifier("firewall.container.\(c.value.name)")
            }
            if containers?.isEmpty ?? true {
                Text("No running containers.").font(.secondary).foregroundStyle(Color.textMuted)
            }
            Text("Container traffic is filtered by Fleet's own forward chain (chain forward rules above), not by Docker's DOCKER-USER chain.")
                .font(.caption11).foregroundStyle(Color.textMuted)
        }
    }

    // MARK: ruleset history

    private func historyCard(_ fw: FirewallRow) -> some View {
        let unconfirmed: Bool = {
            switch revert.phase {
            case .confirming, .noConnection, .failed: true
            default: false
            }
        }()
        return AdminSection(title: "Ruleset history") {
            Text("kept on this Mac").font(.caption11).foregroundStyle(Color.textMuted)
        } content: {
            ForEach(Array(history.enumerated()), id: \.element.n) { i, h in
                HStack(spacing: 12) {
                    Text("v\(h.n)").font(.mono(11)).foregroundStyle(Color.textMuted)
                        .frame(width: 36, alignment: .leading)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(h.title).font(.base)
                        Text("\(SecFormat.whenText(h.timeMs)) · \(h.source)")
                            .font(.secondary).foregroundStyle(Color.textSecondary)
                    }
                    Spacer()
                    if i == 0 {
                        if unconfirmed { StatusPill(label: "Pending", tone: .info) }
                        else { StatusPill(label: "Current", tone: .ok) }
                    } else {
                        Button("Roll back") { askRollback(h, fw) }
                            .disabled(locked || revert.phase == .confirming)
                            .help(lockReason)
                            .accessibilityIdentifier("firewall.rollback.v\(h.n)")
                    }
                }
                .accessibilityIdentifier("firewall.history.v\(h.n)")
            }
            if history.isEmpty {
                Text("Rulesets Fleet sees on this server appear here.")
                    .font(.secondary).foregroundStyle(Color.textMuted)
            }
        }
    }

    private var cooperativeCard: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("Cooperative mode").font(.system(size: 13, weight: .semibold))
            Text("Fleet only manages its own table (inet fleet). Docker's rules and other tables are never flushed or edited.")
                .font(.secondary).foregroundStyle(Color.textSecondary)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .card()
        .accessibilityIdentifier("firewall.cooperative")
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
        let absent = fw.version == 0
        pending = PendingAction(
            title: absent ? "Set up Fleet's firewall table on \(server.name)?"
                : "Apply firewall changes to \(server.name)?",
            message: (absent
                      ? "Creates table inet fleet in \(set.managed ? "Managed (default drop)" : "bans-only") mode. "
                      : modeChange ? "The table switches to \(set.managed ? "Managed (default drop)" : "bans only"). " : "")
                + "The change reverts automatically unless Fleet can reconnect and confirm it within the window.",
            button: "Apply") { apply(set, version: version) }
    }

    private func apply(_ set: FirewallRulesetArgs, version: UInt64, title: String? = nil) {
        guard let api = core.api else { return }
        let summary = title ?? baseArgs.flatMap { try? firewallDescribeChange(current: $0, proposed: set) }
        Task {
            do {
                let change = try await api.firewallApply(serverId: server.id, ruleset: set, expectedVersion: version)
                error = nil
                appliedHere = true
                appliedTitle = title
                changeSummary = summary
                revert.confirm(api: api, serverId: server.id, change: change) { Task { await load() } }
                await load()
            } catch {
                self.error = error.fleetMessage
            }
        }
    }

    private func askRollback(_ h: FwHistoryRow, _ fw: FirewallRow) {
        guard let api = core.api, let base = baseArgs else { return }
        do {
            let target = try api.fwHistoryRuleset(serverId: server.id, n: h.n)
            let problems = firewallCheck(ruleset: target, sshPort: server.port)
            if let first = problems.first {
                error = "Can't roll back to v\(h.n): \(first)"
                return
            }
            let summary = (try? firewallDescribeChange(current: base, proposed: target)) ?? "Ruleset changes"
            pending = PendingAction(
                title: "Roll back \(server.name) to v\(h.n)?",
                message: "\(summary). The rollback is a normal change: it reverts automatically unless Fleet can reconnect and confirm it within the window.",
                button: "Roll back") { apply(target, version: fw.version, title: "Rolled back to v\(h.n)") }
        } catch {
            self.error = error.fleetMessage
        }
    }

    private func retryConfirm() {
        guard let api = core.api, let c = revert.change else { return }
        revert.confirm(api: api, serverId: server.id, change: c) { Task { await load() } }
    }

    private func revertNow() {
        guard let api = core.api else { return }
        revert.revertNow(api: api, serverId: server.id) { Task { await load() } }
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

    /// Remembers the ruleset the server reports (history is kept on this
    /// Mac) and refreshes the list and the "Added" baseline.
    private func observe(_ api: FleetCore, _ state: FirewallRow) {
        let first = ((try? api.fwHistoryList(serverId: server.id)) ?? []).isEmpty
        let args = FirewallRulesetArgs(managed: state.managed, rules: firewallRulesToArgs(rules: state.rules))
        _ = try? api.fwHistoryObserve(
            serverId: server.id, current: args, version: state.version,
            source: appliedHere ? "This Mac" : (first ? "Seen on first load" : "Outside this Mac"),
            title: appliedTitle)
        appliedHere = false
        appliedTitle = nil
        history = (try? api.fwHistoryList(serverId: server.id)) ?? []
        previousRules = history.count > 1
            ? ((try? api.fwHistoryRuleset(serverId: server.id, n: history[1].n))?.rules ?? [])
            : []
    }

    private func load() async {
        guard let api = core.api else { return }
        loading = true
        defer { loading = false }
        async let mode: Void = security.load(api: api, serverId: server.id)
        do {
            let state = try await api.firewallGet(serverId: server.id)
            fw = state
            resetDrafts()
            error = nil
            observe(api, state)
            counters = try? await api.firewallCounters(serverId: server.id)
        } catch {
            self.error = error.fleetMessage
        }
        containers = try? await api.dockerContainers(serverId: server.id, all: false)
        await mode
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
