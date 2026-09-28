import SwiftUI

/// Settings → Profiles (design §9): the built-in provisioning profiles and
/// role add-ons the agent ships, with the modules each one applies.
struct ProfilesSettings: View {
    var provision: () -> Void = {}
    @State private var expanded: Set<String> = []
    private let catalog = builtinProfiles()

    var body: some View {
        SettingsPage("Profiles",
                     subtitle: "Baseline and Strict, plus role add-ons. They ship inside the agent and are reviewed with each agent release.") {
            Button("Provision a server") { provision() }
                .buttonStyle(.fleetPrimary)
                .accessibilityIdentifier("profiles.provision")
        } content: {
            group("Levels", catalog.filter { $0.kind == "level" })
            group("Role add-ons", catalog.filter { $0.kind == "role" })
            Text("Custom profiles extend Baseline or Strict: they can skip modules or declare exceptions, never weaken the fixed settings. Choose them in Provisioning.")
                .font(.caption11).foregroundStyle(Color.textMuted)
        }
    }

    private func group(_ title: String, _ rows: [ProfileCatalogRow]) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(title).font(Typeface.ui(14, .semibold)).foregroundStyle(Color.text)
            ForEach(rows, id: \.id) { card($0) }
        }
    }

    private func card(_ p: ProfileCatalogRow) -> some View {
        let open = expanded.contains(p.id)
        return SettingsCard {
            VStack(alignment: .leading, spacing: 10) {
                HStack(spacing: 10) {
                    Text(p.name).font(.base.weight(.semibold)).foregroundStyle(Color.text)
                    Chip(text: p.kind == "level" ? "Profile" : "Role")
                    if let e = p.extends { Chip(text: "extends \(e)") }
                    Spacer()
                    Text("\(p.modules.count) module\(p.modules.count == 1 ? "" : "s")\(p.extends == nil ? "" : " added")")
                        .font(.secondary).foregroundStyle(Color.textMuted)
                    Button(open ? "Hide modules" : "Show modules") {
                        if open { expanded.remove(p.id) } else { expanded.insert(p.id) }
                    }
                    .buttonStyle(.fleetSecondary)
                    .accessibilityIdentifier("profiles.toggle.\(p.id)")
                }
                Text(p.summary).font(.base).foregroundStyle(Color.textSecondary)
                if open {
                    Divider().overlay(Color.divider)
                    ForEach(p.modules, id: \.id) { m in
                        HStack {
                            Text(m.title).foregroundStyle(Color.text)
                            Spacer()
                            Text(m.id).font(.mono(11)).foregroundStyle(Color.textMuted)
                        }
                        .font(.secondary)
                    }
                    if !p.packages.isEmpty {
                        detail("Packages", p.packages.joined(separator: ", "))
                    }
                    if !p.trackedPaths.isEmpty {
                        detail("Tracked files", p.trackedPaths.joined(separator: ", "))
                    }
                    if p.firewallRules > 0 {
                        detail("Firewall", "\(p.firewallRules) rule\(p.firewallRules == 1 ? "" : "s") in Fleet's own table")
                    }
                }
            }
        }
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier("profiles.card.\(p.id)")
    }

    private func detail(_ label: String, _ value: String) -> some View {
        HStack(alignment: .top) {
            Text(label).foregroundStyle(Color.textMuted).frame(width: 100, alignment: .leading)
            Text(value).font(.mono(11)).foregroundStyle(Color.textSecondary).textSelection(.enabled)
        }
        .font(.secondary)
    }
}

/// Settings → Appearance: accent color. The app is dark only.
struct AppearanceSettings: View {
    @AppStorage(Appearance.accentKey) private var accent = Int(Appearance.defaultAccent)

    var body: some View {
        SettingsPage("Appearance", subtitle: "Fleet is dark only. Pick the accent for buttons and highlights.") {
            SectionCard(icon: "paintpalette", title: "Accent color") {
                HStack(spacing: 14) {
                    ForEach(Appearance.accents, id: \.hex) { a in
                        let on = Int(Appearance.accentHex) == Int(a.hex)
                        Button { accent = Int(a.hex) } label: {
                            VStack(spacing: 6) {
                                Circle().fill(Color(hex: a.hex)).frame(width: 28, height: 28)
                                    .overlay(Circle().stroke(Color.text, lineWidth: on ? 2 : 0).padding(-3))
                                Text(a.name).font(.secondary)
                                    .foregroundStyle(on ? Color.text : Color.textSecondary)
                            }
                        }
                        .buttonStyle(.plain)
                        .accessibilityLabel("\(a.name) accent")
                        .accessibilityAddTraits(on ? .isSelected : [])
                        .accessibilityIdentifier("appearance.accent.\(a.name.lowercased())")
                    }
                }
                HStack(spacing: 10) {
                    Text("Preview").font(.secondary).foregroundStyle(Color.textMuted)
                    Text("Primary button").font(Typeface.ui(13, .medium)).foregroundStyle(.white)
                        .padding(.horizontal, 14).frame(height: 32)
                        .background(Color.accent, in: RoundedRectangle(cornerRadius: 8))
                    Text("Link text").foregroundStyle(Color.accentText)
                }
                .padding(.top, 4)
            }
            SectionCard(icon: "textformat", title: "Type") {
                Text(Typeface.hasGeist
                     ? "Geist and Geist Mono are installed and in use."
                     : "Geist is not installed, so the system font and SF Mono are used. Install Geist and Geist Mono (SIL Open Font License) and restart Fleet to use them.")
                    .font(.base).foregroundStyle(Color.textSecondary)
                    .accessibilityIdentifier("appearance.fontStatus")
            }
        }
    }
}

/// Settings → General: app lock and versions.
struct GeneralSettings: View {
    @Environment(AppLock.self) private var lock

    private static let options: [(String, Int)] = [
        ("5 minutes", 5), ("15 minutes", 15), ("1 hour", 60), ("8 hours", 480),
    ]

    var body: some View {
        SettingsPage("General", subtitle: "App lock and version.") {
            SectionCard(icon: "lock", title: "Lock") {
                Picker("Lock after idle", selection: Binding(
                    get: { Int(lock.idleLimit.components.seconds / 60) },
                    set: { lock.setIdleLimit(.seconds($0 * 60)) }
                )) {
                    ForEach(Self.options, id: \.1) { Text($0.0).tag($0.1) }
                }
                .frame(maxWidth: 320)
                .accessibilityIdentifier("settings.general.idleLock")
                Text("While locked only the monitor key works: telemetry and events, nothing that changes a server.")
                    .font(.secondary).foregroundStyle(Color.textMuted)
            }
            SectionCard(icon: "info.circle", title: "About") {
                LabeledContent("Core version", value: coreVersion())
            }
        }
    }
}
