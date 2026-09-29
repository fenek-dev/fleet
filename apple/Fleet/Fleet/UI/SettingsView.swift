import SwiftUI

/// Sections of the Settings screen, in the order of Settings.dc.html.
enum SettingsSection: String, CaseIterable, Identifiable {
    case devices, recovery, ai, sync, releases, alertRules, profiles, appearance, general

    var id: String { rawValue }

    var title: String {
        switch self {
        case .devices: "Devices"
        case .recovery: "Recovery"
        case .ai: "AI agents"
        case .sync: "Sync"
        case .releases: "Agent releases"
        case .alertRules: "Alert rules"
        case .profiles: "Profiles"
        case .appearance: "Appearance"
        case .general: "General"
        }
    }

    static let storageKey = "settings.section"
}

/// Settings as an in-window screen (ui-design.md §Screens 8): 60 px
/// header, a 200 px section list on the left, the section on the right.
struct SettingsView: View {
    @Binding var selection: NavItem?
    @AppStorage(SettingsSection.storageKey) private var raw = SettingsSection.devices.rawValue

    private var section: SettingsSection { SettingsSection(rawValue: raw) ?? .devices }

    var body: some View {
        VStack(spacing: 0) {
            ScreenHeader("Settings")
            HStack(spacing: 0) {
                sectionList
                Divider().overlay(Color.divider)
                page
                    .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
            }
        }
        .background(Color.window)
        .navigationTitle("Settings")
    }

    private var sectionList: some View {
        VStack(alignment: .leading, spacing: 2) {
            ForEach(SettingsSection.allCases) { s in
                let on = s == section
                Button { raw = s.rawValue } label: {
                    Text(s.title)
                        .font(.base.weight(on ? .medium : .regular))
                        .foregroundStyle(on ? Color.text : Color(hex: 0xc3c6cb))
                        .padding(.horizontal, 12)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .frame(height: 32)
                        .background(on ? Color.selected : .clear, in: RoundedRectangle(cornerRadius: 7))
                        .contentShape(RoundedRectangle(cornerRadius: 7))
                }
                .buttonStyle(.plain)
                .accessibilityAddTraits(on ? .isSelected : [])
                .accessibilityIdentifier("settings.nav.\(s.rawValue)")
            }
            Spacer()
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 20)
        .frame(width: 200)
    }

    @ViewBuilder private var page: some View {
        switch section {
        case .devices:
            DevicesSettings(goTo: { raw = $0.rawValue }).accessibilityIdentifier("settings.devices")
        case .recovery:
            RecoverySettings().accessibilityIdentifier("settings.recovery")
        case .ai:
            AISettings().accessibilityIdentifier("settings.ai")
        case .sync:
            SyncSettings().accessibilityIdentifier("settings.sync")
        case .releases:
            VStack(alignment: .leading, spacing: 0) {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Agent releases").font(.sectionTitle).foregroundStyle(Color.text)
                        .accessibilityAddTraits(.isHeader)
                    Text("Import, sign and roll out agent builds. Every Mac verifies the signed manifest.")
                        .font(.base).foregroundStyle(Color.textSecondary)
                }
                .padding(.horizontal, 32)
                .padding(.top, 28)
                .padding(.bottom, 8)
                AgentReleasesSettings()
            }
            .accessibilityIdentifier("settings.agentReleases")
        case .alertRules:
            SettingsPage("Alert rules",
                         subtitle: "Rules run on each agent. Alerts appear in this app only.") {
                AlertRulesSettings()
            }
            .accessibilityIdentifier("settings.alertRules")
        case .profiles:
            ProfilesSettings(provision: { selection = .provision })
                .accessibilityIdentifier("settings.profiles")
        case .appearance:
            AppearanceSettings().accessibilityIdentifier("settings.appearance")
        case .general:
            GeneralSettings().accessibilityIdentifier("settings.general")
        }
    }
}
