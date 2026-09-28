import SwiftUI

extension TimelineItemRow: Identifiable {}

extension TimelineCategory {
    var symbol: String {
        switch self {
        case .alert: "bell"
        case .login: "person.badge.key"
        case .service: "gearshape.2"
        case .package: "shippingbox"
        case .config: "doc.text"
        case .security: "lock.shield"
        case .network: "network"
        case .container: "cube"
        case .health: "heart.text.square"
        case .fleet: "person.3"
        case .change: "arrow.uturn.backward"
        case .action: "hammer"
        case .other: "circle"
        }
    }
}

/// Filter chips over the timeline.
enum TimelineFilter: String, CaseIterable, Identifiable {
    case all = "All"
    case alerts = "Alerts"
    case logins = "Logins"
    case packages = "Packages"
    case services = "Services"
    case config = "Config"
    case security = "Security"
    case actions = "Actions"
    case ai = "AI"
    var id: String { rawValue }

    func matches(_ i: TimelineItemRow) -> Bool {
        switch self {
        case .all: true
        case .alerts: i.category == .alert || i.category == .health
        case .logins: i.category == .login
        case .packages: i.category == .package
        case .services: i.category == .service || i.category == .container
        case .config: i.category == .config || i.category == .change
        case .security: [.security, .network, .fleet].contains(i.category)
        case .actions: i.category == .action
        case .ai: i.ai
        }
    }
}

/// The list shared by the server tab and the fleet view.
struct TimelineList: View {
    let items: [TimelineItemRow]
    let showServer: Bool
    var openServer: ((String) -> Void)?

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            ForEach(items) { i in
                HStack(alignment: .firstTextBaseline, spacing: 10) {
                    Text(IntelFormat.time(i.timeMs))
                        .font(.caption11).monospacedDigit()
                        .foregroundStyle(Color.textMuted)
                        .frame(width: 130, alignment: .leading)
                    Image(systemName: i.category.symbol)
                        .foregroundStyle(tone(i).text)
                        .frame(width: 18)
                    VStack(alignment: .leading, spacing: 1) {
                        HStack(spacing: 6) {
                            Text(i.title).foregroundStyle(Color.text).lineLimit(1)
                            if i.ai { StatusPill(label: "AI", tone: .info) }
                        }
                        let sub = [i.detail, i.actor.map { "by \($0)" } ?? ""]
                            .filter { !$0.isEmpty }.joined(separator: " · ")
                        if !sub.isEmpty {
                            Text(sub).font(.secondary).foregroundStyle(Color.textSecondary).lineLimit(2)
                        }
                    }
                    Spacer()
                    if showServer {
                        Button(i.serverName) { openServer?(i.serverId) }
                            .buttonStyle(.plain)
                            .font(.secondary)
                            .foregroundStyle(Color.accentText)
                    }
                }
                .font(.base)
                .padding(.vertical, 6)
                Divider().overlay(Color.divider)
            }
        }
    }

    private func tone(_ i: TimelineItemRow) -> Tone {
        if i.ai { return .info }
        switch i.severity {
        case .critical: return .critical
        case .warning: return .warn
        case .info, .none: return .neutral
        }
    }
}

/// Compact list for the Overview's "Timeline · today" card: time, tone
/// dot, title and one detail line.
struct CompactTimelineRows: View {
    let items: [TimelineItemRow]

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            ForEach(items) { i in
                HStack(alignment: .top, spacing: 10) {
                    Text(Date(timeIntervalSince1970: TimeInterval(i.timeMs) / 1000)
                        .formatted(date: .omitted, time: .shortened))
                        .font(.mono(11)).foregroundStyle(Color.textMuted)
                        .frame(width: 58, alignment: .leading)
                    Circle().fill(tone(i).dot).frame(width: 6, height: 6).padding(.top, 5)
                    VStack(alignment: .leading, spacing: 1) {
                        Text(i.title).font(.base).foregroundStyle(Color.text).lineLimit(1)
                        if !i.detail.isEmpty {
                            Text(i.detail).font(.caption11).foregroundStyle(Color.textSecondary).lineLimit(1)
                        }
                    }
                    Spacer(minLength: 0)
                }
                .padding(.vertical, 6)
                .accessibilityElement(children: .combine)
                .accessibilityIdentifier("overview.timeline.row")
            }
        }
    }

    private func tone(_ i: TimelineItemRow) -> Tone {
        if i.ai { return .info }
        switch i.severity {
        case .critical: return .critical
        case .warning: return .warn
        case .info, .none: return .neutral
        }
    }
}

private struct TimelineChrome<Content: View>: View {
    let row: TimelineRow?
    @Binding var filter: TimelineFilter
    @ViewBuilder var content: (_ items: [TimelineItemRow]) -> Content

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Picker("Show", selection: $filter) {
                ForEach(TimelineFilter.allCases) { Text($0.rawValue).tag($0) }
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .frame(maxWidth: 640)
            if let row {
                ForEach(row.failures, id: \.self) { f in
                    Text(f).font(.secondary).foregroundStyle(Tone.warn.text)
                }
                if row.rejectedEvents > 0 {
                    Text("\(row.rejectedEvents) events failed signature checks and are not shown.")
                        .font(.secondary).foregroundStyle(Tone.critical.text)
                }
                let items = row.items.filter(filter.matches)
                if items.isEmpty {
                    Text("Nothing in the last 7 days.").font(.secondary).foregroundStyle(Color.textMuted)
                } else {
                    content(items)
                }
            }
        }
    }
}

/// Server detail: Timeline tab.
struct TimelineTab: View {
    @Environment(CoreBridge.self) private var core
    @Environment(IntelStore.self) private var intel
    let server: ServerRow
    @State private var row: TimelineRow?
    @State private var filter: TimelineFilter = .all
    @State private var loading = false
    @State private var error: String?

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                TabHeader(title: "Timeline", loading: loading, error: error,
                          refresh: { Task { await load() } })
                TimelineChrome(row: row, filter: $filter) { items in
                    TimelineList(items: items, showServer: false).card()
                }
            }
            .padding(24)
        }
        .task(id: server.id) { await load() }
        // A live event for this server: catch up (incremental).
        .onChange(of: core.eventTick) {
            if core.lastEventServer == server.id, !loading { Task { await load() } }
        }
    }

    private func load() async {
        guard let api = core.api else { return }
        loading = true
        defer { loading = false }
        do {
            row = try await api.timelineServer(timeline: intel.timeline, serverId: server.id, limit: 1000)
            error = nil
        } catch {
            self.error = error.fleetMessage
        }
    }
}

/// Sidebar: fleet-wide timeline.
struct FleetTimelineView: View {
    @Environment(CoreBridge.self) private var core
    @Environment(IntelStore.self) private var intel
    @Binding var selection: NavItem?
    @State private var row: TimelineRow?
    @State private var filter: TimelineFilter = .all
    @State private var loading = false
    @State private var error: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Timeline").font(.toolbarTitle).foregroundStyle(Color.text)
                    Text("Events and operations across the fleet, newest first")
                        .font(.secondary).foregroundStyle(Color.textMuted)
                }
                if loading { ProgressView().controlSize(.small) }
                Spacer()
                Button("Refresh", systemImage: "arrow.clockwise") { Task { await load() } }
                    .disabled(loading)
            }
            .padding(.horizontal, 24)
            .frame(height: 60)
            .background(Color.header)
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    if let error { Text(error).font(.base).foregroundStyle(Tone.warn.text) }
                    TimelineChrome(row: row, filter: $filter) { items in
                        TimelineList(items: items, showServer: true) { selection = .server($0) }.card()
                    }
                }
                .padding(24)
            }
        }
        .background(Color.window)
        .task { await load() }
    }

    private func load() async {
        guard let api = core.api else { return }
        loading = true
        defer { loading = false }
        do {
            row = try await api.timelineFleet(timeline: intel.timeline, limit: 2000)
            error = nil
        } catch {
            self.error = error.fleetMessage
        }
    }
}
