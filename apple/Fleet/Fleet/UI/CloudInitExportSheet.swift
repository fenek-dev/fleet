import AppKit
import SwiftUI

/// Recent cloud-init exports (id, label): not secret, only a convenience
/// for the wizard's "pin host key" field. The pins themselves live in
/// the core's MAC'd cache.
enum CloudInitExports {
    struct Entry: Codable, Hashable {
        let id: String
        let label: String
    }

    private static let key = "fleet.cloudInitExports"

    static var recent: [Entry] {
        guard let data = UserDefaults.standard.data(forKey: key) else { return [] }
        return (try? JSONDecoder().decode([Entry].self, from: data)) ?? []
    }

    static func remember(_ e: Entry) {
        let list = [e] + recent.filter { $0.id != e.id }
        if let data = try? JSONEncoder().encode(Array(list.prefix(10))) {
            UserDefaults.standard.set(data, forKey: key)
        }
    }
}

/// cloud-init export (design §9.7): the admin user with every enrolled
/// Mac's SSH key and a host key generated and pinned on this Mac. The file
/// holds the host private key, so it's only written where the operator
/// saves it (0600) and never kept by the app.
struct CloudInitExportSheet: View {
    @Environment(CoreBridge.self) private var core
    @Environment(\.dismiss) private var dismiss
    @State var adminUser: String
    @State private var hostname = ""
    @State private var result: CloudInitExportRow?
    @State private var saved: URL?
    @State private var error: String?

    init(adminUser: String) {
        _adminUser = State(initialValue: adminUser.isEmpty ? "ops" : adminUser)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Export as cloud-init").font(.sectionTitle)
            Text("Paste the file into your provider's user-data. The server boots with the admin user, this fleet's Mac keys and an SSH host key generated here, so the first connection trusts nothing on first use. Root and password login are off from the start; Fleet applies the full profile on first connection.")
                .font(.base).foregroundStyle(Color.textSecondary)
            Form {
                TextField("Admin user", text: $adminUser)
                TextField("Hostname", text: $hostname, prompt: Text("web-05 (optional)"))
            }
            .formStyle(.grouped)
            .disabled(result != nil)
            if let r = result {
                VStack(alignment: .leading, spacing: 6) {
                    LabeledContent("Host key", value: r.fingerprint)
                        .font(.mono(12)).textSelection(.enabled)
                    LabeledContent("Export id", value: r.exportId)
                        .font(.mono(12)).textSelection(.enabled)
                    Text("In the wizard, choose \"Created from a Fleet cloud-init file\" with this id to pin the host key.")
                        .font(.secondary).foregroundStyle(Color.textMuted)
                    if let saved {
                        Text("Saved to \(saved.path)").font(.secondary).foregroundStyle(Tone.ok.text)
                    }
                }
                .card(padding: 12)
            }
            if let error {
                Text(error).font(.base).foregroundStyle(Tone.critical.text)
            }
            HStack {
                Button(result == nil ? "Cancel" : "Done") { dismiss() }
                Spacer()
                if result == nil {
                    Button("Generate") { generate() }
                        .buttonStyle(.borderedProminent).tint(.accent)
                        .disabled(adminUser.isEmpty)
                } else {
                    Button("Save…") { save() }
                        .buttonStyle(.borderedProminent).tint(.accent)
                }
            }
        }
        .padding(24)
        .frame(width: 560)
    }

    private func generate() {
        guard let api = core.api else { return }
        error = nil
        do {
            let host = hostname.trimmingCharacters(in: .whitespaces)
            let r = try api.exportCloudInit(adminUser: adminUser.trimmingCharacters(in: .whitespaces),
                                            hostname: host.isEmpty ? nil : host)
            result = r
            CloudInitExports.remember(.init(id: r.exportId, label: host.isEmpty ? adminUser : host))
            save()
        } catch {
            self.error = error.fleetMessage
        }
    }

    private func save() {
        guard let r = result else { return }
        let panel = NSSavePanel()
        panel.nameFieldStringValue = "\(hostname.isEmpty ? "fleet" : hostname)-cloud-init.yaml"
        panel.message = "The file contains the server's SSH host private key."
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            try Data(r.yaml.utf8).write(to: url, options: .atomic)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
            saved = url
        } catch {
            self.error = "Couldn't save: \(error.localizedDescription)"
        }
    }
}
