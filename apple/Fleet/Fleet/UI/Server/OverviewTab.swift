import Charts
import SwiftUI

/// Derived chart series from raw metric names (design §4.3 catalog).
enum ChartMetric: String, CaseIterable, Identifiable {
    case cpu = "CPU"
    case memory = "Memory"
    case disk = "Disk /"
    case netRx = "Network in"
    case netTx = "Network out"
    /// Read plus write over all disks.
    case diskIO = "Disk I/O"
    /// In plus out over all interfaces except loopback.
    case network = "Network"
    var id: String { rawValue }

    /// The four cards of the Overview (ServerDetail.dc.html).
    static let overview: [ChartMetric] = [.cpu, .memory, .diskIO, .network]

    var isPercent: Bool { self == .cpu || self == .memory || self == .disk }

    /// Value from the latest raw values (name → value).
    func value(_ v: [String: Double]) -> Double? {
        switch self {
        case .cpu: return v["cpu.busy"]
        case .memory:
            guard let u = v["mem.used"], let t = v["mem.total"], t > 0 else { return nil }
            return u / t * 100
        case .disk: return v["disk.used:/"]
        case .netRx: return Self.sum(v, prefix: "net.rx:")
        case .netTx: return Self.sum(v, prefix: "net.tx:")
        case .diskIO:
            let r = Self.sum(v, prefix: "disk.read:"), w = Self.sum(v, prefix: "disk.write:")
            return r == nil && w == nil ? nil : (r ?? 0) + (w ?? 0)
        case .network:
            let r = Self.sum(v, prefix: "net.rx:", skipLoopback: true)
            let t = Self.sum(v, prefix: "net.tx:", skipLoopback: true)
            return r == nil && t == nil ? nil : (r ?? 0) + (t ?? 0)
        }
    }

    private static func sum(_ v: [String: Double], prefix: String, skipLoopback: Bool = false) -> Double? {
        let xs = v.filter { $0.key.hasPrefix(prefix) && !(skipLoopback && $0.key == prefix + "lo") }
            .map(\.value)
        return xs.isEmpty ? nil : xs.reduce(0, +)
    }

    func format(_ x: Double) -> String {
        if self == .network { return String(format: "%.1f Mbit/s", x * 8 / 1_000_000) }
        return isPercent ? "\(Int(x.rounded()))%" : Format.bytes(UInt64(max(0, x))) + "/s"
    }

    /// Big number of the card: memory shows bytes used, the chart plots percent.
    func headline(_ latest: [String: Double], chartValue: Double?) -> String? {
        if self == .memory {
            return latest["mem.used"].map { Format.bytes(UInt64(max(0, $0))) }
        }
        return chartValue.map { format($0) }
    }

    /// Caption next to the title ("8 cores · load 3.9").
    func caption(_ latest: [String: Double], cpuCount: UInt32?) -> String {
        func rate(_ x: Double?) -> String { Format.bytes(UInt64(max(0, x ?? 0))) + "/s" }
        switch self {
        case .cpu:
            var parts: [String] = []
            if let n = cpuCount { parts.append("\(n) cores") }
            if let l = latest["load.1"] { parts.append(String(format: "load %.1f", l)) }
            return parts.joined(separator: " · ")
        case .memory:
            guard let t = latest["mem.total"] else { return "" }
            var s = "of \(Format.bytes(UInt64(max(0, t))))"
            if let p = Self.memory.value(latest) { s += " · \(Int(p.rounded()))%" }
            return s
        case .diskIO:
            return "read \(rate(Self.sum(latest, prefix: "disk.read:"))) · write \(rate(Self.sum(latest, prefix: "disk.write:")))"
        case .network:
            func mbit(_ x: Double?) -> String { String(format: "%.1f", (x ?? 0) * 8 / 1_000_000) }
            return "in \(mbit(Self.sum(latest, prefix: "net.rx:", skipLoopback: true))) · out \(mbit(Self.sum(latest, prefix: "net.tx:", skipLoopback: true)))"
        default: return ""
        }
    }
}

struct MetricPoint: Identifiable {
    let date: Date
    let value: Double
    var id: Date { date }
}

/// History (`metrics.query`, minute rollups) plus the live 1 s stream.
@Observable
@MainActor
final class MetricsModel {
    private(set) var points: [ChartMetric: [MetricPoint]] = [:]
    private(set) var status: StreamStatus?
    private(set) var historyError: String?
    @ObservationIgnored private var names: [UInt16: String] = [:]
    @ObservationIgnored private var values: [String: Double] = [:]
    @ObservationIgnored private var handle: StreamHandle?
    /// Latest raw value per series (for captions).
    private(set) var latest: [String: Double] = [:]
    private(set) var loaded = false
    /// Window kept in memory.
    private(set) var window: TimeInterval = 24 * 3600
    /// Longest span a chart point covers; keeps 7 d charts to ~700 points.
    private var minGap: TimeInterval { max(1, window / 720) }

    func start(api: FleetCore, serverId: String, window: TimeInterval) async {
        stop()
        self.window = window
        points = [:]
        values = [:]
        latest = [:]
        loaded = false
        await loadHistory(api: api, serverId: serverId)
        loaded = true
        do {
            handle = try api.subscribeMetrics(serverId: serverId, oneSecond: true,
                                              sink: MetricsRelay(model: self))
        } catch {
            status = .ended(error: error.fleetMessage)
        }
    }

    func stop() {
        handle?.cancel()
        handle = nil
    }

    private func loadHistory(api: FleetCore, serverId: String) async {
        let now = UInt64(Date().timeIntervalSince1970 * 1000)
        let since = now - UInt64(window * 1000)
        do {
            let h = try await api.metricsQuery(serverId: serverId, sinceMs: since, untilMs: nil,
                                               minuteResolution: true, series: [])
            historyError = nil
            let byId = Dictionary(h.catalog.map { ($0.id, $0.name) }, uniquingKeysWith: { a, _ in a })
            let avg = Dictionary(h.series.map { (byId[$0.id] ?? "", $0.avg) }, uniquingKeysWith: { a, _ in a })
            let n = avg.values.map(\.count).max() ?? 0
            var out: [ChartMetric: [MetricPoint]] = [:]
            // Average buckets of `stride` minute rollups (7 d = 10 080 points).
            let stride = max(1, n / 720)
            var i = 0
            while i < n {
                var last: [String: Double] = [:]
                var sums: [ChartMetric: (Double, Int)] = [:]
                for k in i..<min(n, i + stride) {
                    var v: [String: Double] = [:]
                    for (name, xs) in avg where k < xs.count && xs[k].isFinite {
                        v[name] = Double(xs[k])
                    }
                    last = v
                    for m in ChartMetric.overview {
                        if let x = m.value(v) { sums[m, default: (0, 0)] = (sums[m, default: (0, 0)].0 + x, sums[m, default: (0, 0)].1 + 1) }
                    }
                }
                let date = Date(timeIntervalSince1970: Double(h.startMs + UInt64(i) * UInt64(h.stepMs)) / 1000)
                for (m, s) in sums where s.1 > 0 {
                    out[m, default: []].append(MetricPoint(date: date, value: s.0 / Double(s.1)))
                }
                if !last.isEmpty { values.merge(last) { _, new in new } }
                i += stride
            }
            latest = values
            points = out
        } catch {
            historyError = error.fleetMessage
        }
    }

    fileprivate func catalog(_ series: [MetricSeriesRow]) {
        names = Dictionary(series.map { ($0.id, $0.name) }, uniquingKeysWith: { a, _ in a })
    }

    fileprivate func sample(_ s: MetricsSampleRow) {
        for v in s.values {
            if let n = names[v.id], v.value.isFinite { values[n] = Double(v.value) }
        }
        let date = Date(timeIntervalSince1970: Double(s.timeMs) / 1000)
        let cutoff = date.addingTimeInterval(-window)
        latest = values
        for m in ChartMetric.overview {
            guard let x = m.value(values) else { continue }
            var arr = points[m, default: []]
            if let l = arr.last, date.timeIntervalSince(l.date) < minGap {
                arr[arr.count - 1] = MetricPoint(date: l.date, value: x)
                points[m] = arr
                continue
            }
            arr.append(MetricPoint(date: date, value: x))
            if let first = arr.first, first.date < cutoff {
                arr.removeAll { $0.date < cutoff }
            }
            points[m] = arr
        }
    }

    fileprivate func setStatus(_ s: StreamStatus) { status = s }
}

private final class MetricsRelay: MetricsSink {
    private let model: MetricsModel
    init(model: MetricsModel) { self.model = model }
    func onCatalog(series: [MetricSeriesRow]) {
        Task { @MainActor [model] in model.catalog(series) }
    }
    func onSample(sample: MetricsSampleRow) {
        Task { @MainActor [model] in model.sample(sample) }
    }
    func onStatus(status: StreamStatus) {
        Task { @MainActor [model] in model.setStatus(status) }
    }
}

/// Overview: resource charts, system and agent facts, top processes.
/// Every string shown came from the server (untrusted, display only).
struct OverviewTab: View {
    @Environment(CoreBridge.self) private var core
    let server: ServerRow
    let ctx: ServerContext
    /// Switches the server tab ("View all", hardening score link).
    var openTab: (ServerTab) -> Void = { _ in }
    @State private var metrics = MetricsModel()
    @State private var range: Double = 86400
    @State private var processes: [ProcessRow] = []
    @State private var processesLoaded = false
    @State private var containers: [ContainerRow]?
    @State private var containersError: String?
    @State private var profile: ServerProfileRow?
    @State private var score: UInt8?
    @State private var scoreError: String?
    @State private var error: String?
    @State private var confirmUninstall = false
    @State private var uninstalling = false
    @State private var securityMode: SecurityModeStatus = .unknown
    @State private var enablingManaged = false

    private var info: SystemInfoRow? { ctx.info }
    private var health: AgentHealthRow? { ctx.health }

    var body: some View {
        ScrollView {
            HStack(alignment: .top, spacing: 20) {
                VStack(alignment: .leading, spacing: 16) {
                    HStack(spacing: 12) {
                        Text("Resources").font(.system(size: 14, weight: .semibold))
                        streamPill
                        Spacer()
                        rangePicker
                    }
                    if let e = error ?? ctx.factsError ?? metrics.historyError {
                        Text(e).font(.base).foregroundStyle(Tone.warn.text)
                    }
                    LazyVGrid(columns: [GridItem(.adaptive(minimum: 240), spacing: 16)], spacing: 16) {
                        ForEach(ChartMetric.overview) { m in chart(m) }
                    }
                    section("Top processes", caption: "By CPU · live") { processTable }
                    HStack(alignment: .top, spacing: 16) {
                        section("System") { systemRows }
                        section("Agent") { agentRows }
                    }
                }
                .frame(maxWidth: .infinity, alignment: .topLeading)
                VStack(alignment: .leading, spacing: 16) {
                    timelineCard
                    containersCard
                    profileCard
                }
                .frame(width: 340)
            }
            .padding(.horizontal, 28)
            .padding(.top, 20)
            .padding(.bottom, 24)
        }
        .task(id: server.id) {
            guard let api = core.api else { return }
            await load()
            await metrics.start(api: api, serverId: server.id, window: range)
            // Top processes every 5 s while shown.
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(5))
                await loadProcesses()
            }
        }
        .task(id: server.id) { await loadCards() }
        .onChange(of: range) {
            guard let api = core.api else { return }
            Task { await metrics.start(api: api, serverId: server.id, window: range) }
        }
        .onChange(of: core.eventTick) {
            if core.lastEventServer == server.id { Task { await loadContainers() } }
        }
        .onDisappear { metrics.stop() }
    }

    /// 1 h / 24 h / 7 d on a `track` well.
    private var rangePicker: some View {
        HStack(spacing: 2) {
            ForEach([("1 h", 3600.0, "1h"), ("24 h", 86400.0, "24h"), ("7 d", 604_800.0, "7d")], id: \.2) { label, value, id in
                Button(label) { range = value }
                    .buttonStyle(.plain)
                    .font(.secondary.weight(.medium))
                    .foregroundStyle(range == value ? Color.text : Color.textSecondary)
                    .padding(.horizontal, 10).frame(height: 24)
                    .background(range == value ? Color.control : .clear, in: RoundedRectangle(cornerRadius: 6))
                    .accessibilityAddTraits(range == value ? .isSelected : [])
                    .accessibilityIdentifier("overview.range.\(id)")
            }
        }
        .padding(3)
        .background(Color.track, in: RoundedRectangle(cornerRadius: 9))
    }

    // MARK: right column

    private var timelineCard: some View {
        let items = Array(ctx.today.prefix(8))
        return VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("Timeline · today").font(.system(size: 13, weight: .semibold)).foregroundStyle(Color.text)
                Spacer()
                Button("View all") { openTab(.timeline) }
                    .buttonStyle(.plain).font(.secondary).foregroundStyle(Color.accentText)
                    .accessibilityIdentifier("overview.timeline.viewAll")
            }
            if items.isEmpty {
                if ctx.timelineLoaded {
                    Text("Nothing today.").font(.secondary).foregroundStyle(Color.textMuted)
                } else {
                    ProgressView().controlSize(.small)
                }
            } else {
                CompactTimelineRows(items: items)
            }
        }
        .frame(maxWidth: .infinity, alignment: .topLeading)
        .card()
        .accessibilityIdentifier("overview.timeline")
    }

    private var containersCard: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("Containers").font(.system(size: 13, weight: .semibold)).foregroundStyle(Color.text)
                Spacer()
                if let c = containers, !c.isEmpty {
                    let projects = Set(c.compactMap(\.composeProject)).sorted()
                    Text(projects.isEmpty ? "\(c.count) running" : "Compose · \(projects.joined(separator: ", "))")
                        .font(.secondary).foregroundStyle(Color.textMuted).lineLimit(1)
                }
                Button("View all") { openTab(.docker) }
                    .buttonStyle(.plain).font(.secondary).foregroundStyle(Color.accentText)
                    .accessibilityIdentifier("overview.containers.viewAll")
            }
            if let c = containers {
                if c.isEmpty {
                    Text("No running containers.").font(.secondary).foregroundStyle(Color.textMuted)
                }
                ForEach(c.prefix(6), id: \.id) { ct in
                    HStack(spacing: 10) {
                        Circle().fill(containerTone(ct).dot).frame(width: 6, height: 6)
                        VStack(alignment: .leading, spacing: 1) {
                            Text(ct.name).font(.base).foregroundStyle(Color.text).lineLimit(1)
                            Text(ct.image).font(.mono(11)).foregroundStyle(Color.textSecondary).lineLimit(1)
                        }
                        Spacer(minLength: 0)
                        Text(ct.status).font(.caption11).foregroundStyle(Color.textSecondary).lineLimit(1)
                    }
                    .padding(.vertical, 4)
                    .accessibilityElement(children: .combine)
                    .accessibilityIdentifier("overview.containers.row")
                }
            } else if let e = containersError {
                Text(e).font(.secondary).foregroundStyle(Color.textMuted).lineLimit(2)
            } else {
                ProgressView().controlSize(.small)
            }
        }
        .frame(maxWidth: .infinity, alignment: .topLeading)
        .card()
        .accessibilityIdentifier("overview.containers")
    }

    private func containerTone(_ c: ContainerRow) -> Tone {
        switch c.state {
        case "running": .ok
        case "restarting", "dead": .warn
        default: .neutral
        }
    }

    private var profileCard: some View {
        HStack(alignment: .center, spacing: 12) {
            VStack(alignment: .leading, spacing: 8) {
                Text("Profile").font(.system(size: 13, weight: .semibold)).foregroundStyle(Color.text)
                HStack(spacing: 6) {
                    ForEach(profileChips, id: \.self) { chip in
                        Text(chip).font(.secondary).foregroundStyle(Color.textSecondary)
                            .padding(.horizontal, 8).frame(height: 22)
                            .background(Color.selected, in: RoundedRectangle(cornerRadius: 6))
                    }
                }
                .accessibilityIdentifier("overview.profile.chips")
            }
            Spacer(minLength: 0)
            Button { openTab(.security) } label: {
                VStack(alignment: .trailing, spacing: 2) {
                    if let score {
                        Text("\(score)").font(.system(size: 24, weight: .semibold)).monospacedDigit()
                            .foregroundStyle(Color.text)
                    } else if scoreError != nil {
                        Text("n/a").font(.system(size: 24, weight: .semibold)).foregroundStyle(Color.textMuted)
                    } else {
                        ProgressView().controlSize(.small)
                    }
                    Text("Hardening score").font(.caption11).foregroundStyle(Color.textSecondary)
                }
            }
            .buttonStyle(.plain)
            .help(scoreError ?? "Open the Security tab")
            .accessibilityIdentifier("overview.profile.score")
        }
        .frame(maxWidth: .infinity, alignment: .topLeading)
        .card()
        .accessibilityIdentifier("overview.profile")
    }

    private var profileChips: [String] {
        guard let profile else { return ["Not provisioned from this Mac"] }
        var out = [profile.level == .strict ? "Strict" : "Baseline"]
        for r in profile.roles {
            switch r {
            case .docker: out.append("Docker")
            case .web: out.append("Web")
            case .game: out.append("Game server")
            }
        }
        return out
    }

    private func loadCards() async {
        profile = try? core.api?.serverProfile(serverId: server.id)
        await loadContainers()
        guard let api = core.api else { return }
        do {
            score = try await api.auditRun(serverId: server.id, level: nil).score
            scoreError = nil
        } catch {
            scoreError = error.fleetMessage
        }
    }

    private func loadContainers() async {
        guard let api = core.api else { return }
        do {
            containers = try await api.dockerContainers(serverId: server.id, all: false)
            containersError = nil
        } catch {
            if containers == nil { containersError = "Docker unavailable: \(error.fleetMessage)" }
        }
    }

    @ViewBuilder private var streamPill: some View {
        switch metrics.status {
        case .live: StatusPill(label: "Live", tone: .ok)
        case .reconnecting: StatusPill(label: "Reconnecting", tone: .warn)
        case .ended(let e?): StatusPill(label: "Stream ended", tone: .critical).help(e)
        case .ended(nil), .none: EmptyView()
        }
    }

    private func chart(_ m: ChartMetric) -> some View {
        let cutoff = Date().addingTimeInterval(-range)
        let pts = (metrics.points[m] ?? []).filter { $0.date >= cutoff }
        return VStack(alignment: .leading, spacing: 8) {
            HStack(alignment: .firstTextBaseline, spacing: 10) {
                Text(m.rawValue).font(.secondary).foregroundStyle(Color.textSecondary)
                Spacer()
                Text(m.caption(metrics.latest, cpuCount: info?.cpuCount))
                    .font(.secondary).foregroundStyle(Color.textMuted).lineLimit(1)
            }
            Group {
                if let h = m.headline(metrics.latest, chartValue: pts.last?.value) {
                    Text(h)
                } else if metrics.loaded {
                    Text("No data").foregroundStyle(Color.textMuted)
                } else {
                    ProgressView().controlSize(.small)
                }
            }
            .font(.system(size: 24, weight: .semibold)).monospacedDigit()
            .foregroundStyle(Color.text)
            Chart(pts) { p in
                AreaMark(x: .value("Time", p.date), y: .value(m.rawValue, p.value))
                    .foregroundStyle(Color.accent.opacity(0.09))
                LineMark(x: .value("Time", p.date), y: .value(m.rawValue, p.value))
                    .foregroundStyle(Color.accent)
                    .lineStyle(StrokeStyle(lineWidth: 1.5))
            }
            .chartYScale(domain: m.isPercent ? 0...100 : 0...max(1, pts.map(\.value).max() ?? 1))
            .chartXAxis { AxisMarks(values: .automatic(desiredCount: 4)) }
            .chartYAxis { AxisMarks(position: .leading, values: .automatic(desiredCount: 3)) }
            .frame(height: 72)
        }
        .card()
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier("overview.metric.\(m.rawValue)")
    }

    private var processTable: some View {
        VStack(spacing: 0) {
            HStack {
                Text("PID").frame(width: 60, alignment: .leading)
                Text("Process").frame(maxWidth: .infinity, alignment: .leading)
                Text("User").frame(width: 80, alignment: .leading)
                Text("CPU").frame(width: 50, alignment: .trailing)
                Text("Memory").frame(width: 70, alignment: .trailing)
            }
            .font(.caption11).foregroundStyle(Color.textMuted).padding(.bottom, 6)
            if processes.isEmpty {
                if processesLoaded {
                    Text("No processes reported.").foregroundStyle(Color.textMuted)
                        .frame(maxWidth: .infinity, alignment: .leading)
                } else {
                    ProgressView().controlSize(.small).frame(maxWidth: .infinity, alignment: .leading)
                }
            }
            ForEach(processes, id: \.pid) { p in
                HStack {
                    Text("\(p.pid)").font(.mono(11)).frame(width: 60, alignment: .leading)
                    Text(p.cmdline.isEmpty ? p.name : p.cmdline).lineLimit(1).help(p.cmdline)
                        .frame(maxWidth: .infinity, alignment: .leading)
                    Text(p.user).lineLimit(1).frame(width: 80, alignment: .leading)
                    Text(String(format: "%.1f%%", p.cpuPercent)).monospacedDigit()
                        .frame(width: 50, alignment: .trailing)
                    Text(Format.bytes(p.rssBytes)).monospacedDigit().frame(width: 70, alignment: .trailing)
                }
                .font(.base).foregroundStyle(Color.text).frame(height: 26)
                .contentShape(Rectangle())
                .processActions(serverId: server.id, process: p) { e in
                    error = e
                    Task { await loadProcesses() }
                }
                Divider().overlay(Color.divider)
            }
        }
    }

    @ViewBuilder private var systemRows: some View {
        if let info {
            row("Hostname", info.hostname)
            row("OS", "\(info.osId) \(info.osVersion)")
            row("Kernel", info.kernel, mono: true)
            row("CPUs", "\(info.cpuCount) · \(info.arch)")
            row("Memory", Format.bytes(info.memTotalBytes))
            row("Uptime", Format.uptime(info.uptimeS))
        } else {
            unavailable
        }
    }

    @ViewBuilder private var agentRows: some View {
        if let health {
            row("Version", health.agentVersion, mono: true)
            row("Memory", "gate \(Format.bytes(health.gateRssBytes)) · exec \(Format.bytes(health.execRssBytes))")
            row("Roster", "epoch \(health.rosterEpoch) · v\(health.rosterVersion)")
            row("Policy", "v\(health.policyVersion) · audit \(health.auditSeq)")
            HStack {
                Text("Security").foregroundStyle(Color.textSecondary)
                Spacer()
                StatusPill(label: securityModeLabel, tone: securityModeTone)
            }
            .font(.base)
            if securityMode == .agentOnly {
                VStack(alignment: .leading, spacing: 6) {
                    Text("Fleet doesn't manage bans, authorized_keys or the firewall on this server.")
                        .font(.secondary).foregroundStyle(Color.textSecondary)
                    Button("Enable Fleet security management…") { enableManaged() }
                        .disabled(enablingManaged)
                }
            }
            if health.recoveryPending {
                StatusPill(label: "Recovery pending", tone: .critical)
            }
            Button("Uninstall agent…", role: .destructive) { confirmUninstall = true }
                .disabled(uninstalling)
                .confirmationDialog("Uninstall the agent from \(server.name)?",
                                    isPresented: $confirmUninstall) {
                    Button("Uninstall, keep audit database", role: .destructive) { uninstall() }
                } message: {
                    Text("SSH keys move back to ~/.ssh/authorized_keys and are confirmed over a new "
                         + "connection first. The Fleet firewall table is kept.")
                }
        } else {
            unavailable
        }
    }

    @ViewBuilder private var unavailable: some View {
        if ctx.factsError != nil {
            Text("Unavailable").foregroundStyle(Color.textMuted)
        } else {
            ProgressView().controlSize(.small)
        }
    }

    private func uninstall() {
        guard let api = core.api else { return }
        uninstalling = true
        Task {
            defer { uninstalling = false }
            do {
                try await api.uninstallAgent(serverId: server.id, keepAudit: true, removeFirewall: false)
            } catch { self.error = error.fleetMessage }
        }
    }

    private var securityModeLabel: String {
        switch securityMode {
        case .managed: "Managed by Fleet"
        case .agentOnly: "Agent only"
        case .unknown: "Unknown"
        }
    }

    private var securityModeTone: Tone {
        switch securityMode {
        case .managed: .ok
        case .agentOnly: .warn
        case .unknown: .warn
        }
    }

    private func load() async {
        error = nil
        // System info and agent health come from the shared server context.
        if let api = core.api {
            securityMode = (try? await api.securityMode(serverId: server.id)) ?? .unknown
        }
        await loadProcesses()
    }

    /// Pushes `security = "managed"` (Touch ID): a normal `policy.update`
    /// that turns the ban engine and `authorized_keys` sync back on right
    /// away, without touching firewall or sshd state (design §5.4).
    private func enableManaged() {
        guard let api = core.api else { return }
        enablingManaged = true
        Task {
            defer { enablingManaged = false }
            do {
                try await api.setSecurityMode(serverId: server.id, mode: .managed)
                securityMode = .managed
            } catch { self.error = error.fleetMessage }
        }
    }

    private func loadProcesses() async {
        guard let api = core.api else { return }
        if let l = try? await api.processesList(serverId: server.id, sort: .cpu, limit: 10) {
            processes = l.processes
        }
        processesLoaded = true
    }

    private func section(_ title: String, caption: String? = nil,
                         @ViewBuilder _ content: () -> some View) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text(title).font(.system(size: 13, weight: .semibold)).foregroundStyle(Color.text)
                Spacer()
                if let caption { Text(caption).font(.secondary).foregroundStyle(Color.textMuted) }
            }
            content()
        }
        .frame(maxWidth: .infinity, alignment: .topLeading)
        .card()
    }

    private func row(_ label: String, _ value: String, mono: Bool = false) -> some View {
        HStack {
            Text(label).foregroundStyle(Color.textSecondary)
            Spacer()
            Text(value)
                .font(mono ? .mono(12) : .base)
                .foregroundStyle(Color.text)
                .lineLimit(1).truncationMode(.middle)
                .textSelection(.enabled)
        }
        .font(.base)
    }
}
