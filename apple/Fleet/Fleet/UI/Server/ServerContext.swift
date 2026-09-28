import SwiftUI

/// Facts shared by the server header and the Overview tab: system info,
/// agent health and today's timeline. Loaded once per server. Every string
/// came from the server (untrusted, display only).
@Observable
@MainActor
final class ServerContext {
    private(set) var info: SystemInfoRow?
    private(set) var health: AgentHealthRow?
    private(set) var timeline: [TimelineItemRow] = []
    private(set) var timelineLoaded = false
    private(set) var factsError: String?

    func loadFacts(core: CoreBridge, serverId: String) async {
        factsError = nil
        // agent.health works on monitor sessions; the rest needs unlock.
        do { health = try await core.agentHealth(serverId) } catch { factsError = error.fleetMessage }
        do { info = try await core.systemInfo(serverId) } catch { factsError = error.fleetMessage }
    }

    func loadTimeline(core: CoreBridge, intel: IntelStore, serverId: String) async {
        guard let api = core.api else { return }
        if let row = try? await api.timelineServer(timeline: intel.timeline, serverId: serverId, limit: 200) {
            timeline = row.items
        }
        timelineLoaded = true
    }

    /// Items since local midnight, newest first.
    var today: [TimelineItemRow] {
        let start = UInt64(max(0, Calendar.current.startOfDay(for: Date()).timeIntervalSince1970 * 1000))
        return timeline.filter { $0.timeMs >= start }
    }

    /// The newest warning or critical item of the last 24 h.
    var healthNote: TimelineItemRow? {
        let since = UInt64(max(0, Date().addingTimeInterval(-86400).timeIntervalSince1970 * 1000))
        return timeline.first { $0.timeMs >= since && ($0.severity == .warning || $0.severity == .critical) }
    }
}

extension ServerContext {
    /// Header facts line: `host · OS · N vCPU · X GB · up 12 d · agent 0.9.2`.
    static func facts(_ s: ServerRow, info: SystemInfoRow?, health: AgentHealthRow?) -> String {
        var parts = [s.host]
        if let info {
            let os = "\(info.osId) \(info.osVersion)".trimmingCharacters(in: .whitespaces)
            if !os.isEmpty { parts.append(os) }
            parts.append("\(info.cpuCount) vCPU")
            parts.append(Format.bytes(info.memTotalBytes))
        }
        if let up = info?.uptimeS ?? s.uptimeS { parts.append("up \(Format.uptime(up))") }
        if let v = health?.agentVersion ?? s.agentVersion { parts.append("agent \(v)") }
        return parts.joined(separator: " · ")
    }
}
