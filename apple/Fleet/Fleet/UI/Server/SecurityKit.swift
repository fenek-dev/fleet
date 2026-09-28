import SwiftUI

/// Shared pieces of the Security and Firewall tabs: switching tabs from a
/// link, the Agent-only notice, the score ring and short time formats.

extension Notification.Name {
    /// `userInfo`: `serverId: String`, `tab: String` (`ServerTab.rawValue`).
    static let fleetSelectServerTab = Notification.Name("fleet.selectServerTab")
}

/// Asks the open server detail view to show another tab ("Firewall",
/// "All bans", "View diff" links).
func openServerTab(_ tab: ServerTab, serverId: String) {
    NotificationCenter.default.post(name: .fleetSelectServerTab, object: nil,
                                    userInfo: ["serverId": serverId, "tab": tab.rawValue])
}

// MARK: - Security mode

/// Whether Fleet may change this server's security (policy `security`).
/// Agent-only refuses firewall, authorized_keys, profile and ban changes at
/// the agent; the app disables those controls and says why.
@Observable
@MainActor
final class SecurityModeModel {
    private(set) var mode: SecurityModeStatus = .unknown
    private(set) var loaded = false

    func load(api: FleetCore, serverId: String) async {
        mode = (try? await api.securityMode(serverId: serverId)) ?? .unknown
        loaded = true
    }

    /// Nil when changes are allowed.
    var blockedReason: String? {
        switch mode {
        case .managed: nil
        case .agentOnly:
            "Agent only: Fleet doesn't manage this server's security, so firewall, ban and hardening changes are off. Switch it to Managed from the server's Overview tab."
        case .unknown:
            loaded
                ? "This server's security mode is unknown (refresh the connection). Changes stay off until it is confirmed Managed."
                : nil
        }
    }

    var allowsChanges: Bool { mode == .managed }
}

/// Explains why security controls are off.
struct SecurityModeNotice: View {
    let model: SecurityModeModel

    var body: some View {
        if let reason = model.blockedReason {
            HStack(alignment: .top, spacing: 10) {
                Image(systemName: "lock.shield").foregroundStyle(Tone.warn.text)
                Text(reason).font(.secondary).foregroundStyle(Tone.warn.text)
                Spacer(minLength: 0)
            }
            .padding(12)
            .background(Tone.warn.bg, in: RoundedRectangle(cornerRadius: 12))
            .accessibilityIdentifier("security.modeNotice")
        }
    }
}

// MARK: - Score ring

/// Hardening score as a ring with "92 of 100" in the middle.
struct ScoreRing: View {
    let score: UInt8?
    var size: CGFloat = 76

    private var tone: Tone {
        guard let s = score else { return .neutral }
        return s >= 85 ? .ok : s >= 60 ? .warn : .critical
    }

    var body: some View {
        ZStack {
            Circle().stroke(Color.track, lineWidth: 7)
            Circle()
                .trim(from: 0, to: CGFloat(min(score ?? 0, 100)) / 100)
                .stroke(tone.dot, style: StrokeStyle(lineWidth: 7, lineCap: .round))
                .rotationEffect(.degrees(-90))
            VStack(spacing: 0) {
                Text(score.map { "\($0)" } ?? "–").font(.system(size: size * 0.32, weight: .semibold))
                    .monospacedDigit()
                Text("of 100").font(.system(size: 10)).foregroundStyle(Color.textMuted)
            }
        }
        .frame(width: size, height: size)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(score.map { "Hardening score \($0) of 100" } ?? "No hardening score")
        .accessibilityIdentifier("security.scoreRing")
    }
}

// MARK: - Time formats

enum SecFormat {
    /// `14:08` today, `Sep 24` earlier.
    static func clockOrDay(_ ms: UInt64) -> String {
        let d = Date(timeIntervalSince1970: TimeInterval(ms) / 1000)
        if Calendar.current.isDateInToday(d) { return d.formatted(date: .omitted, time: .shortened) }
        return d.formatted(.dateTime.month(.abbreviated).day())
    }

    /// Time left until `ms`: `48 min`, `23 h`, `2 d`.
    static func left(until ms: UInt64, now: Date = Date()) -> String {
        let s = Int(Double(ms) / 1000 - now.timeIntervalSince1970)
        if s <= 0 { return "expiring" }
        if s < 3600 { return "\(max(1, s / 60)) min" }
        if s < 86400 { return "\(s / 3600) h" }
        return "\(s / 86400) d"
    }

    /// `Just now`, `12 min ago`, `Sep 20`.
    static func whenText(_ ms: UInt64, now: Date = Date()) -> String {
        let s = Int(now.timeIntervalSince1970 - Double(ms) / 1000)
        if s < 60 { return "Just now" }
        if s < 3600 { return "\(s / 60) min ago" }
        return clockOrDay(ms)
    }
}
