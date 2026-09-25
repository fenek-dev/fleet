import SwiftUI

extension VulnSeverity {
    var label: String {
        switch self {
        case .unknown: "unrated"
        case .negligible: "negligible"
        case .low: "low"
        case .medium: "medium"
        case .high: "high"
        case .critical: "critical"
        }
    }

    var tone: Tone {
        switch self {
        case .critical, .high: .critical
        case .medium: .warn
        case .low: .info
        case .negligible, .unknown: .neutral
        }
    }
}

enum IntelFormat {
    static func ago(_ ms: UInt64?) -> String {
        guard let ms else { return "never" }
        let d = Date(timeIntervalSince1970: TimeInterval(ms) / 1000)
        return d.formatted(.relative(presentation: .named))
    }

    static func time(_ ms: UInt64) -> String {
        Date(timeIntervalSince1970: TimeInterval(ms) / 1000)
            .formatted(date: .abbreviated, time: .shortened)
    }

    static func feedName(_ key: String) -> String {
        switch key {
        case "debian-tracker": "Debian Security Tracker"
        case "ubuntu-usn": "Ubuntu Security Notices"
        default: key
        }
    }
}

/// One line per feed: last update or last error.
struct FeedStatusLine: View {
    @Environment(IntelStore.self) private var intel

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            ForEach(intel.status?.feeds ?? [], id: \.key) { f in
                HStack(spacing: 6) {
                    Text(IntelFormat.feedName(f.key))
                    if let e = f.lastError {
                        Text("failed: \(e)").foregroundStyle(Tone.warn.text).lineLimit(1)
                    } else {
                        Text("checked \(IntelFormat.ago(f.fetchedMs)) · \(f.rows) entries")
                    }
                }
            }
            if intel.status?.updating == true {
                Text("Updating vulnerability data…")
            }
        }
        .font(.caption11)
        .foregroundStyle(Color.textMuted)
    }
}

private struct FindingRow: View {
    let f: VulnFindingRow

    var body: some View {
        HStack(spacing: 10) {
            StatusPill(label: f.severity.label, tone: f.severity.tone)
                .frame(width: 90, alignment: .leading)
            VStack(alignment: .leading, spacing: 1) {
                Text(f.id).font(.mono(11)).textSelection(.enabled)
                if !f.aliases.isEmpty {
                    Text(aliases).font(.caption11).foregroundStyle(Color.textMuted).lineLimit(1)
                }
            }
            .frame(width: 190, alignment: .leading)
            Text(f.package).frame(width: 170, alignment: .leading).lineLimit(1)
            Text(f.installed).font(.mono(11)).foregroundStyle(Color.textSecondary).lineLimit(1)
            Image(systemName: "arrow.right").foregroundStyle(Color.textMuted)
            if let fixed = f.fixed {
                Text(fixed).font(.mono(11)).foregroundStyle(Tone.ok.text).lineLimit(1)
            } else {
                Text("no fix yet").foregroundStyle(Color.textMuted)
            }
            Spacer()
        }
        .font(.secondary)
    }

    private var aliases: String {
        let shown = f.aliases.prefix(3).joined(separator: ", ")
        return f.aliases.count > 3 ? "\(shown) +\(f.aliases.count - 3)" : shown
    }
}

/// Security tab: installed packages matched against the feeds.
struct VulnerabilitiesSection: View {
    @Environment(CoreBridge.self) private var core
    @Environment(IntelStore.self) private var intel
    let server: ServerRow
    @State private var loading = false
    @State private var error: String?
    @State private var showUnfixed = false

    private static let shownMax = 300

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Text("Vulnerabilities").font(.system(size: 13, weight: .semibold))
                if loading { ProgressView().controlSize(.small) }
                Spacer()
                Toggle("Include unfixed", isOn: $showUnfixed).toggleStyle(.checkbox)
                Button("Scan") { Task { await scan() } }
                    .disabled(loading || server.state != .ready)
            }
            if let error {
                Text(error).font(.secondary).foregroundStyle(Tone.warn.text)
            }
            if let r = intel.reports[server.id] {
                report(r)
            } else if !loading {
                Text("Not scanned yet.").font(.secondary).foregroundStyle(Color.textMuted)
            }
            FeedStatusLine()
        }
        .frame(maxWidth: .infinity, alignment: .topLeading)
        .card()
        .task(id: server.id) {
            if intel.reports[server.id] == nil, server.state == .ready { await scan() }
        }
    }

    @ViewBuilder private func report(_ r: VulnReportRow) -> some View {
        if r.distro == nil {
            Text("Not a supported release (\(r.os)). Matching covers Debian 12+ and Ubuntu 22.04+.")
                .font(.secondary).foregroundStyle(Color.textMuted)
        } else if r.noData {
            Text("No vulnerability data for \(r.distro ?? "") yet. It downloads daily while Fleet runs.")
                .font(.secondary).foregroundStyle(Color.textMuted)
        } else {
            HStack(spacing: 16) {
                stat("\(r.vulnerablePackages)", "packages with fixes available",
                     tone: r.vulnerablePackages > 0 ? .warn : .ok)
                stat("\(r.unfixedPackages)", "packages with unfixed issues", tone: .neutral)
                stat("\(r.packagesScanned)", "packages checked", tone: .neutral)
                Spacer()
                Text("\(r.distro ?? "") \(r.release ?? "") · scanned \(IntelFormat.ago(r.scannedMs))")
                    .font(.caption11).foregroundStyle(Color.textMuted)
            }
            let shown = r.findings.filter { showUnfixed || $0.fixed != nil }
            ForEach(Indexed.wrap(Array(shown.prefix(Self.shownMax)))) { f in FindingRow(f: f.value) }
            if shown.count > Self.shownMax {
                Text("\(shown.count - Self.shownMax) more not shown.")
                    .font(.caption11).foregroundStyle(Color.textMuted)
            }
            if shown.isEmpty {
                Text("No known vulnerabilities with available fixes.")
                    .font(.secondary).foregroundStyle(Tone.ok.text)
            }
            if r.distro == "debian" {
                Text("Debian matches by package name; binaries named differently from their source package (for example libssl3) are not matched yet.")
                    .font(.caption11).foregroundStyle(Color.textMuted)
            }
        }
    }

    private func stat(_ value: String, _ label: String, tone: Tone) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 6) {
            Text(value).font(.system(size: 20, weight: .semibold)).monospacedDigit()
                .foregroundStyle(tone.text)
            Text(label).font(.secondary).foregroundStyle(Color.textSecondary)
        }
    }

    private func scan() async {
        guard let api = core.api else { return }
        loading = true
        defer { loading = false }
        error = nil
        do { try await intel.scan(api, serverId: server.id) } catch { self.error = error.fleetMessage }
        intel.refreshStatus()
    }
}

/// Fleet-wide vulnerabilities: per-server counts and the most widespread
/// advisories.
struct FleetVulnerabilitiesView: View {
    @Environment(CoreBridge.self) private var core
    @Environment(IntelStore.self) private var intel
    @Binding var selection: NavItem?

    private struct Spread: Identifiable {
        let id: String
        let severity: VulnSeverity
        let fixed: Bool
        var servers: Set<String>
        var packages: Set<String>
    }

    private var rows: [VulnReportRow] {
        intel.reports.values.sorted {
            ($0.vulnerablePackages, $1.serverId) > ($1.vulnerablePackages, $0.serverId)
        }
    }

    private var spread: [Spread] {
        var by: [String: Spread] = [:]
        for r in intel.reports.values {
            for f in r.findings where f.fixed != nil {
                by[f.id, default: Spread(id: f.id, severity: f.severity, fixed: true,
                                         servers: [], packages: [])].servers.insert(r.serverId)
                by[f.id]?.packages.insert(f.package)
            }
        }
        return by.values.sorted {
            ($0.servers.count, $0.severity.rank) > ($1.servers.count, $1.severity.rank)
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    if let e = intel.lastError {
                        Text(e).font(.base).foregroundStyle(Tone.warn.text)
                    }
                    FeedStatusLine()
                    serversCard
                    advisoriesCard
                }
                .padding(24)
            }
        }
        .background(Color.window)
        .task {
            // Poll feed status while an update runs.
            while !Task.isCancelled {
                intel.refreshStatus()
                try? await Task.sleep(for: .seconds(intel.status?.updating == true ? 3 : 30))
            }
        }
    }

    private var header: some View {
        HStack(spacing: 12) {
            VStack(alignment: .leading, spacing: 2) {
                Text("Vulnerabilities").font(.toolbarTitle).foregroundStyle(Color.text)
                Text("Debian Security Tracker and Ubuntu Security Notices, matched on this Mac")
                    .font(.secondary).foregroundStyle(Color.textMuted)
            }
            if intel.scanning { ProgressView().controlSize(.small) }
            Spacer()
            Button("Update data", systemImage: "arrow.down.circle") {
                Task { await intel.updateFeeds() }
            }
            .disabled(intel.status?.updating == true)
            Button("Scan fleet", systemImage: "shield.lefthalf.filled") {
                Task { if let api = core.api { await intel.scanFleet(api) } }
            }
            .buttonStyle(.borderedProminent).tint(.accent)
            .disabled(intel.scanning)
        }
        .padding(.horizontal, 24)
        .frame(height: 60)
        .background(Color.header)
    }

    private var serversCard: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Servers").font(.system(size: 13, weight: .semibold))
            if rows.isEmpty {
                Text("No scans yet. Scan the fleet to match installed packages.")
                    .font(.secondary).foregroundStyle(Color.textMuted)
            }
            ForEach(rows, id: \.serverId) { r in
                Button { selection = .server(r.serverId) } label: {
                    HStack(spacing: 12) {
                        Text(name(r.serverId)).frame(width: 180, alignment: .leading)
                        Text(r.distro.map { "\($0) \(r.release ?? "")" } ?? r.os)
                            .foregroundStyle(Color.textSecondary).frame(width: 150, alignment: .leading)
                        Text("\(r.vulnerablePackages) vulnerable").monospacedDigit()
                            .foregroundStyle(r.vulnerablePackages > 0 ? Tone.warn.text : Tone.ok.text)
                            .frame(width: 110, alignment: .leading)
                        Text("\(r.unfixedPackages) unfixed").monospacedDigit()
                            .foregroundStyle(Color.textMuted).frame(width: 90, alignment: .leading)
                        if let h = r.highest { StatusPill(label: h.label, tone: h.tone) }
                        Spacer()
                        Text(IntelFormat.ago(r.scannedMs)).foregroundStyle(Color.textMuted)
                    }
                    .font(.secondary)
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
            }
        }
        .frame(maxWidth: .infinity, alignment: .topLeading)
        .card()
    }

    private var advisoriesCard: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Most widespread fixable advisories").font(.system(size: 13, weight: .semibold))
            let top = Array(spread.prefix(100))
            if top.isEmpty {
                Text("None.").font(.secondary).foregroundStyle(Color.textMuted)
            }
            ForEach(top) { s in
                HStack(spacing: 12) {
                    StatusPill(label: s.severity.label, tone: s.severity.tone)
                        .frame(width: 90, alignment: .leading)
                    Text(s.id).font(.mono(11)).frame(width: 190, alignment: .leading)
                        .textSelection(.enabled)
                    Text(s.packages.sorted().prefix(3).joined(separator: ", "))
                        .lineLimit(1).frame(width: 220, alignment: .leading)
                    Spacer()
                    Text("\(s.servers.count) server\(s.servers.count == 1 ? "" : "s")")
                        .monospacedDigit().foregroundStyle(Color.textSecondary)
                }
                .font(.secondary)
            }
        }
        .frame(maxWidth: .infinity, alignment: .topLeading)
        .card()
    }

    private func name(_ id: String) -> String {
        core.servers.first { $0.id == id }?.name ?? id
    }
}

extension VulnSeverity {
    var rank: Int {
        switch self {
        case .unknown: 0
        case .negligible: 1
        case .low: 2
        case .medium: 3
        case .high: 4
        case .critical: 5
        }
    }
}
