import SwiftUI

/// Buttons of the design: 32 px, 8 px radius. Primary is accent with white
/// text; secondary is `control` with a control border.
struct FleetButtonStyle: ButtonStyle {
    enum Kind { case primary, secondary, destructive }
    var kind: Kind = .secondary
    @Environment(\.isEnabled) private var enabled

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(Typeface.ui(13, .medium))
            .foregroundStyle(kind == .primary ? Color.white : kind == .destructive ? Tone.critical.text : Color(hex: 0xd4d6da))
            .padding(.horizontal, 14)
            .frame(height: 32)
            .background(kind == .primary ? Color.accent : Color.control, in: RoundedRectangle(cornerRadius: 8))
            .overlay(RoundedRectangle(cornerRadius: 8)
                .stroke(kind == .primary ? Color.accent : Color.borderControl))
            .opacity(enabled ? (configuration.isPressed ? 0.8 : 1) : 0.45)
            .contentShape(RoundedRectangle(cornerRadius: 8))
    }
}

extension ButtonStyle where Self == FleetButtonStyle {
    static var fleetPrimary: FleetButtonStyle { .init(kind: .primary) }
    static var fleetSecondary: FleetButtonStyle { .init(kind: .secondary) }
    static var fleetDestructive: FleetButtonStyle { .init(kind: .destructive) }
}

extension View {
    /// Form that blends with the window: no grouped box, leading edge flush
    /// with the surrounding headers.
    func fleetForm() -> some View {
        formStyle(.columns).scrollContentBackground(.hidden)
    }
}

/// A Settings section page: 20 px title, description, optional trailing
/// action, then the scrolling content (28/32 px padding, 20 px gaps).
struct SettingsPage<Content: View, Trailing: View>: View {
    let title: String
    let subtitle: String
    @ViewBuilder var trailing: () -> Trailing
    @ViewBuilder var content: () -> Content

    init(_ title: String, subtitle: String,
         @ViewBuilder trailing: @escaping () -> Trailing,
         @ViewBuilder content: @escaping () -> Content) {
        self.title = title
        self.subtitle = subtitle
        self.trailing = trailing
        self.content = content
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                HStack(alignment: .top, spacing: 16) {
                    VStack(alignment: .leading, spacing: 4) {
                        Text(title).font(.sectionTitle).foregroundStyle(Color.text)
                            .accessibilityAddTraits(.isHeader)
                        Text(subtitle).font(.base).foregroundStyle(Color.textSecondary)
                    }
                    Spacer(minLength: 0)
                    trailing()
                }
                content()
            }
            .padding(.horizontal, 32)
            .padding(.vertical, 28)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }
}

extension SettingsPage where Trailing == EmptyView {
    init(_ title: String, subtitle: String, @ViewBuilder content: @escaping () -> Content) {
        self.init(title, subtitle: subtitle, trailing: { EmptyView() }, content: content)
    }
}

/// A 12 px bordered card on `card`.
struct SettingsCard<Content: View>: View {
    var padding: CGFloat = 16
    @ViewBuilder var content: () -> Content

    var body: some View {
        content()
            .padding(padding)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Color.card, in: RoundedRectangle(cornerRadius: 12))
            .overlay(RoundedRectangle(cornerRadius: 12).stroke(Color.border))
    }
}

/// Summary card with icon, title, optional status pill and body.
struct SectionCard<Body: View>: View {
    let icon: String
    let title: String
    var pill: (String, Tone)?
    @ViewBuilder var content: () -> Body

    var body: some View {
        SettingsCard {
            VStack(alignment: .leading, spacing: 10) {
                HStack(spacing: 10) {
                    Image(systemName: icon).foregroundStyle(Color.accentText)
                    Text(title).font(Typeface.ui(14, .semibold)).foregroundStyle(Color.text)
                    Spacer(minLength: 0)
                    if let pill { StatusPill(label: pill.0, tone: pill.1) }
                }
                content()
            }
        }
    }
}

/// Small rounded chip (tags, "This Mac", "Full admin").
struct Chip: View {
    let text: String
    var tone: Tone?

    var body: some View {
        Text(text)
            .font(.secondary)
            .foregroundStyle(tone?.text ?? Color(hex: 0xc3c6cb))
            .padding(.horizontal, 8)
            .frame(height: 22)
            .background(tone?.bg ?? Color.selected, in: RoundedRectangle(cornerRadius: 6))
    }
}

// `FlowLayout` (wrapping chips) lives in BulkRunSheet.swift.
