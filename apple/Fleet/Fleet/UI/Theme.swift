import SwiftUI

/// Tokens from docs/ui-design.md (dark theme only).
extension Color {
    init(hex: UInt32) {
        self.init(
            .sRGB,
            red: Double((hex >> 16) & 0xff) / 255,
            green: Double((hex >> 8) & 0xff) / 255,
            blue: Double(hex & 0xff) / 255)
    }

    static let window = Color(hex: 0x121315)
    static let sidebar = Color(hex: 0x141518)
    static let header = Color(hex: 0x151619)
    static let card = Color(hex: 0x1a1b1e)
    static let cardSubtle = Color(hex: 0x1f2024)
    static let control = Color(hex: 0x25262b)
    static let track = Color(hex: 0x0f1012)
    static let selected = Color(hex: 0x26272c)
    static let border = Color(hex: 0x2a2b30)
    static let borderControl = Color(hex: 0x34363c)
    static let divider = Color(hex: 0x232429)
    static let text = Color(hex: 0xededee)
    static let textSecondary = Color(hex: 0xa3a7ae)
    static let textMuted = Color(hex: 0x8d9199)
    static let accent = Color(hex: 0x2563eb)
    static let accentText = Color(hex: 0x87a9f4)
}

/// Status palette: background, text, dot.
struct Tone: Equatable {
    let bg: Color
    let text: Color
    let dot: Color

    static let ok = Tone(bg: Color(hex: 0x15291d), text: Color(hex: 0x6fd49a), dot: Color(hex: 0x3fb772))
    static let warn = Tone(bg: Color(hex: 0x33230f), text: Color(hex: 0xf0a257), dot: Color(hex: 0xe8832a))
    static let critical = Tone(bg: Color(hex: 0x3a1a17), text: Color(hex: 0xff8a7d), dot: Color(hex: 0xef5a4a))
    static let info = Tone(bg: Color(hex: 0x182338), text: Color(hex: 0x8fb3ff), dot: Color(hex: 0x8fb3ff))
    static let neutral = Tone(bg: Color.selected, text: Color.textSecondary, dot: Color.textMuted)
}

/// Geist is not bundled yet; system fonts at the spec's sizes.
extension Font {
    static let base = Font.system(size: 13)
    static let secondary = Font.system(size: 12)
    static let caption11 = Font.system(size: 11)
    static let toolbarTitle = Font.system(size: 17, weight: .semibold)
    static let serverTitle = Font.system(size: 22, weight: .semibold)
    static let sectionTitle = Font.system(size: 20, weight: .semibold)
    static func mono(_ size: CGFloat = 12) -> Font { .system(size: size, design: .monospaced) }
}

extension View {
    /// A 12 px card on `card` with a `border` stroke.
    func card(padding: CGFloat = 16) -> some View {
        self.padding(padding)
            .background(Color.card, in: RoundedRectangle(cornerRadius: 12))
            .overlay(RoundedRectangle(cornerRadius: 12).stroke(Color.border))
    }
}

/// Status is always a dot plus a label; color is never the only signal.
struct StatusPill: View {
    let label: String
    let tone: Tone

    var body: some View {
        HStack(spacing: 6) {
            Circle().fill(tone.dot).frame(width: 6, height: 6)
            Text(label).font(.secondary).foregroundStyle(tone.text)
        }
        .padding(.horizontal, 8)
        .frame(height: 22)
        .background(tone.bg, in: Capsule())
        .accessibilityElement(children: .combine)
    }
}

extension ConnState {
    var label: String {
        switch self {
        case .disconnected: "Not connected"
        case .connecting: "Connecting"
        case .authenticating: "Authenticating"
        case .ready: "Healthy"
        case .degraded: "Retrying"
        case .offline: "Offline"
        }
    }

    var tone: Tone {
        switch self {
        case .ready: .ok
        case .connecting, .authenticating: .info
        case .degraded: .warn
        case .offline: .critical
        case .disconnected: .neutral
        }
    }

    /// Sort order for the health column: worst first.
    var rank: Int {
        switch self {
        case .offline: 0
        case .degraded: 1
        case .disconnected: 2
        case .connecting: 3
        case .authenticating: 4
        case .ready: 5
        }
    }
}

enum Format {
    static func percent(_ v: Float?) -> String {
        guard let v else { return "–" }
        return "\(Int(v.rounded()))%"
    }

    static func uptime(_ s: UInt64?) -> String {
        guard let s else { return "–" }
        let d = s / 86_400, h = (s % 86_400) / 3600, m = (s % 3600) / 60
        if d > 0 { return "\(d) d" }
        if h > 0 { return "\(h) h" }
        return "\(m) min"
    }

    static func bytes(_ b: UInt64) -> String {
        ByteCountFormatter.string(fromByteCount: Int64(clamping: b), countStyle: .memory)
    }

    static func lastSeen(_ ms: UInt64?) -> String {
        guard let ms else { return "–" }
        let date = Date(timeIntervalSince1970: TimeInterval(ms) / 1000)
        return date.formatted(.relative(presentation: .named))
    }
}
