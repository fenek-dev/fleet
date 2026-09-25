import SwiftUI

/// Settings (design §7.5): Devices, Recovery, AI, Sync, General.
struct SettingsView: View {
    var body: some View {
        TabView {
            Tab("General", systemImage: "gearshape") { GeneralSettings() }
            Tab("Devices", systemImage: "laptopcomputer") { DevicesSettings() }
            Tab("Recovery", systemImage: "key") { RecoverySettings() }
            Tab("AI", systemImage: "sparkles") {
                SettingsPlaceholder(
                    title: "AI agents",
                    detail: "Approved MCP clients and the pause switch.")
            }
            Tab("Sync", systemImage: "icloud") { SyncSettings() }
        }
        .frame(width: 640, height: 520)
        .preferredColorScheme(.dark)
    }
}

private struct GeneralSettings: View {
    @Environment(AppLock.self) private var lock

    private static let options: [(String, Int)] = [
        ("5 minutes", 5), ("15 minutes", 15), ("1 hour", 60), ("8 hours", 480),
    ]

    var body: some View {
        Form {
            Picker("Lock after idle", selection: Binding(
                get: { Int(lock.idleLimit.components.seconds / 60) },
                set: { lock.setIdleLimit(.seconds($0 * 60)) }
            )) {
                ForEach(Self.options, id: \.1) { Text($0.0).tag($0.1) }
            }
            LabeledContent("Core version", value: coreVersion())
        }
        .formStyle(.grouped)
    }
}

private struct SettingsPlaceholder: View {
    let title: String
    let detail: String

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(title).font(.sectionTitle)
            Text(detail).foregroundStyle(Color.textSecondary)
            Text("Not built yet.").font(.secondary).foregroundStyle(Color.textMuted)
            Spacer()
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(24)
    }
}
