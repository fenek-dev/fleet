import AppKit
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
    /// The operator's accent (Settings → Appearance); default #2563eb.
    static var accent: Color { Color(hex: Appearance.accentHex) }
    /// Accent mixed 45% toward white (#87a9f4 for the default).
    static var accentText: Color { Color(hex: Appearance.tint(Appearance.accentHex, 0.45)) }

    // Terminal (ui-design.md §Tokens "terminal").
    static let terminalBg = Color(hex: 0x0d0e10)
    static let terminalBar = Color(hex: 0x16171a)
    static let terminalPrompt = Color(hex: 0x8ab4f8)
}

/// Accent choices of Settings → Appearance (Settings.dc.html `accent`).
enum Appearance {
    static let accentKey = "appearance.accent"
    static let defaultAccent: UInt32 = 0x2563eb
    static let accents: [(name: String, hex: UInt32)] = [
        ("Blue", 0x2563eb), ("Teal", 0x0f766e), ("Violet", 0x7c3aed), ("Orange", 0xc2410c),
    ]

    static var accentHex: UInt32 {
        let v = UserDefaults.standard.integer(forKey: accentKey)
        return accents.contains { Int($0.hex) == v } ? UInt32(v) : defaultAccent
    }

    /// `hex` mixed `t` of the way toward white.
    static func tint(_ hex: UInt32, _ t: Double) -> UInt32 {
        func mix(_ v: UInt32) -> UInt32 { UInt32((Double(v) + (255 - Double(v)) * t).rounded()) }
        return mix((hex >> 16) & 0xff) << 16 | mix((hex >> 8) & 0xff) << 8 | mix(hex & 0xff)
    }
}

/// Fixed metrics from ui-design.md §Layout.
enum Metrics {
    static let toolbarHeight: CGFloat = 60
    static let tableRowHeight: CGFloat = 42
    static let tableHeaderHeight: CGFloat = 36
    static let sidebarWidth: CGFloat = 240
}

/// Status palette: background, text, dot.
struct Tone: Equatable {
    let bg: Color
    let text: Color
    let dot: Color

    static let ok = Tone(bg: Color(hex: 0x15291d), text: Color(hex: 0x6fd49a), dot: Color(hex: 0x3fb772))
    static let warn = Tone(bg: Color(hex: 0x33230f), text: Color(hex: 0xf0a257), dot: Color(hex: 0xe8832a))
    static let critical = Tone(bg: Color(hex: 0x3a1a17), text: Color(hex: 0xff8a7d), dot: Color(hex: 0xef5a4a))
    /// The spec defines no dot for info; it takes the text color.
    static let info = Tone(bg: Color(hex: 0x182338), text: Color(hex: 0x8fb3ff), dot: Color(hex: 0x8fb3ff))
    /// Not in the spec: needed for states with no signal (not connected).
    static let neutral = Tone(bg: Color.selected, text: Color.textSecondary, dot: Color.textMuted)
}

/// Geist / Geist Mono when installed on the Mac, system fonts otherwise.
/// The fonts are not bundled: no copy was obtainable offline with a pinned
/// hash (SIL OFL 1.1 would allow bundling them).
enum Typeface {
    static let hasGeist = NSFont(name: "Geist-Regular", size: 13) != nil
        || NSFont(name: "Geist", size: 13) != nil
    static let hasGeistMono = NSFont(name: "GeistMono-Regular", size: 12) != nil
        || NSFont(name: "Geist Mono", size: 12) != nil

    static func ui(_ size: CGFloat, _ weight: Font.Weight = .regular) -> Font {
        hasGeist ? .custom("Geist", size: size).weight(weight) : .system(size: size, weight: weight)
    }

    static func mono(_ size: CGFloat, _ weight: Font.Weight = .regular) -> Font {
        hasGeistMono ? .custom("Geist Mono", size: size).weight(weight)
            : .system(size: size, weight: weight, design: .monospaced)
    }
}

extension Font {
    static var base: Font { Typeface.ui(13) }
    static var secondary: Font { Typeface.ui(12) }
    static var caption11: Font { Typeface.ui(11) }
    static var toolbarTitle: Font { Typeface.ui(17, .semibold) }
    static var serverTitle: Font { Typeface.ui(22, .semibold) }
    static var sectionTitle: Font { Typeface.ui(20, .semibold) }
    static func mono(_ size: CGFloat = 12) -> Font { Typeface.mono(size) }
}

private struct FleetLockedKey: EnvironmentKey {
    static let defaultValue = false
}

extension EnvironmentValues {
    /// The app is locked: only the monitor key is usable (read-only).
    /// Screens with write actions disable them when this is true.
    var fleetLocked: Bool {
        get { self[FleetLockedKey.self] }
        set { self[FleetLockedKey.self] = newValue }
    }
}

/// The 60 px toolbar shared by top-level screens (ui-design.md §Layout):
/// 17 px title, optional trailing controls, bottom border.
struct ScreenHeader<Trailing: View>: View {
    let title: String
    var subtitle: String?
    @ViewBuilder var trailing: () -> Trailing

    init(_ title: String, subtitle: String? = nil,
         @ViewBuilder trailing: @escaping () -> Trailing = { EmptyView() }) {
        self.title = title
        self.subtitle = subtitle
        self.trailing = trailing
    }

    var body: some View {
        HStack(spacing: 16) {
            Text(title).font(.toolbarTitle).foregroundStyle(Color.text)
                .accessibilityAddTraits(.isHeader)
            if let subtitle {
                Text(subtitle).font(.secondary).foregroundStyle(Color.textMuted)
            }
            Spacer(minLength: 0)
            trailing()
        }
        .padding(.horizontal, 24)
        .frame(height: Metrics.toolbarHeight)
        .background(Color.header)
        .overlay(alignment: .bottom) { Rectangle().fill(Color.border).frame(height: 1) }
    }
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
        // ByteCountFormatter spells zero out ("Zero KB").
        if b == 0 { return "0 KB" }
        return ByteCountFormatter.string(fromByteCount: Int64(clamping: b), countStyle: .memory)
    }

    static func lastSeen(_ ms: UInt64?) -> String {
        guard let ms else { return "–" }
        let date = Date(timeIntervalSince1970: TimeInterval(ms) / 1000)
        return date.formatted(.relative(presentation: .named))
    }
}
