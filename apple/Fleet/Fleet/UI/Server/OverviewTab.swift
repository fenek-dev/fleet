import Charts
import SwiftUI

/// Derived chart series from raw metric names (design §4.3 catalog).
enum ChartMetric: String, CaseIterable, Identifiable {
    case cpu = "CPU"
    case memory = "Memory"
    case disk = "Disk /"
    case netRx = "Network in"
    case netTx = "Network out"
    var id: String { rawValue }

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
        }
    }

    private static func sum(_ v: [String: Double], prefix: String) -> Double? {
        let xs = v.filter { $0.key.hasPrefix(prefix) }.map(\.value)
        return xs.isEmpty ? nil : xs.reduce(0, +)
    }

    func format(_ x: Double) -> String {
        isPercent ? "\(Int(x.rounded()))%" : Format.bytes(UInt64(max(0, x))) + "/s"
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
    /// Window kept in memory.
    var window: TimeInterval = 24 * 3600

    func start(api: FleetCore, serverId: String) async {
        stop()
        points = [:]
        values = [:]
        await loadHistory(api: api, serverId: serverId)
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
            for i in 0..<n {
                var v: [String: Double] = [:]
                for (name, xs) in avg where i < xs.count && xs[i].isFinite {
                    v[name] = Double(xs[i])
                }
                let date = Date(timeIntervalSince1970: Double(h.startMs + UInt64(i) * UInt64(h.stepMs)) / 1000)
                for m in ChartMetric.allCases {
                    if let x = m.value(v) { out[m, default: []].append(MetricPoint(date: date, value: x)) }
                }
            }
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
        for m in ChartMetric.allCases {
            guard let x = m.value(values) else { continue }
            var arr = points[m, default: []]
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
    @State private var metrics = MetricsModel()
    @State private var range: Double = 3600
    @State private var info: SystemInfoRow?
    @State private var health: AgentHealthRow?
    @State private var processes: [ProcessRow] = []
    @State private var error: String?
    @State private var confirmUninstall = false
    @State private var uninstalling = false
    @State private var securityMode: SecurityModeStatus = .unknown
    @State private var enablingManaged = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                HStack {
                    Text("Resources").font(.system(size: 15, weight: .semibold))
                    streamPill
                    Spacer()
                    Picker("Range", selection: $range) {
                        Text("1 h").tag(3600.0)
                        Text("24 h").tag(86400.0)
                    }
                    .pickerStyle(.segmented).labelsHidden().frame(width: 140)
                }
                if let e = error ?? metrics.historyError {
                    Text(e).font(.base).foregroundStyle(Tone.warn.text)
                }
                LazyVGrid(columns: [GridItem(.flexible(), spacing: 16), GridItem(.flexible(), spacing: 16)],
                          spacing: 16) {
                    ForEach(ChartMetric.allCases) { m in chart(m) }
                }
                HStack(alignment: .top, spacing: 16) {
                    section("Top processes") { processTable }
                    VStack(spacing: 16) {
                        section("System") { systemRows }
                        section("Agent") { agentRows }
                    }
                }
            }
            .padding(24)
        }
        .task(id: server.id) {
            guard let api = core.api else { return }
            await load()
            await metrics.start(api: api, serverId: server.id)
            // Top processes every 5 s while shown.
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(5))
                await loadProcesses()
            }
        }
        .onDisappear { metrics.stop() }
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
            HStack(alignment: .firstTextBaseline) {
                Text(m.rawValue).font(.secondary).foregroundStyle(Color.textSecondary)
                Spacer()
                Text(pts.last.map { m.format($0.value) } ?? "–")
                    .font(.system(size: 17, weight: .semibold)).monospacedDigit()
                    .foregroundStyle(Color.text)
            }
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
            .frame(height: 110)
        }
        .card()
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
                Text("No data").foregroundStyle(Color.textMuted).frame(maxWidth: .infinity, alignment: .leading)
            }
            ForEach(processes, id: \.pid) { p in
                HStack {
                    Text("\(p.pid)").font(.mono(11)).frame(width: 60, alignment: .leading)
                    Text(p.name).lineLimit(1).help(p.cmdline).frame(maxWidth: .infinity, alignment: .leading)
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
            Text("No data").foregroundStyle(Color.textMuted)
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
            Text("No data").foregroundStyle(Color.textMuted)
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
        // agent.health works on monitor sessions; the rest needs unlock.
        do { health = try await core.agentHealth(server.id) } catch { self.error = error.fleetMessage }
        do { info = try await core.systemInfo(server.id) } catch { self.error = error.fleetMessage }
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
    }

    private func section(_ title: String, @ViewBuilder _ content: () -> some View) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(title).font(.system(size: 13, weight: .semibold)).foregroundStyle(Color.text)
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
