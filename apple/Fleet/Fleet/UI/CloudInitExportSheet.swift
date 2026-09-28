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
        guard let data = AppPaths.defaults.data(forKey: key) else { return [] }
        return (try? JSONDecoder().decode([Entry].self, from: data)) ?? []
    }

    static func remember(_ e: Entry) {
        let list = [e] + recent.filter { $0.id != e.id }
        if let data = try? JSONEncoder().encode(Array(list.prefix(10))) {
            AppPaths.defaults.set(data, forKey: key)
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
                        if let provider = CloudInitFile.syncedLocation(saved) {
                            Text(CloudInitFile.syncedWarning(provider))
                                .font(.secondary).foregroundStyle(Tone.warn.text)
                        }
                    }
                }
                .card(padding: 12)
                Text(CloudInitFile.afterBootNotice)
                    .font(.secondary).foregroundStyle(Tone.warn.text)
                    .fixedSize(horizontal: false, vertical: true)
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
        if let provider = CloudInitFile.syncedLocation(url) {
            let alert = NSAlert()
            alert.alertStyle = .warning
            alert.messageText = "This folder syncs to \(provider)"
            alert.informativeText = CloudInitFile.syncedWarning(provider)
            alert.addButton(withTitle: "Choose Another Folder")
            alert.addButton(withTitle: "Save Anyway")
            if alert.runModal() == .alertFirstButtonReturn {
                save()
                return
            }
        }
        do {
            try CloudInitFile.writePrivate(Data(r.yaml.utf8), to: url)
            saved = url
        } catch {
            self.error = "Couldn't save: \(error.localizedDescription)"
        }
    }
}

/// Writing the export and the warnings around it. The file holds the
/// server's SSH host private key.
enum CloudInitFile {
    static let afterBootNotice = """
        After the server's first boot: the host private key stays in your provider's stored user-data \
        (instance metadata) and on the server in /var/lib/cloud/instance/user-data.txt*. Delete or \
        replace the user-data in the provider's console, run \
        `sudo rm -f /var/lib/cloud/instance/user-data.txt*` on the server, and delete this file. \
        Rotating the host key afterwards is recommended.
        """

    static func syncedWarning(_ provider: String) -> String {
        "\(provider) uploads this file, including the server's SSH host private key, to its servers and to your other devices. Save it to a local folder instead, or delete it as soon as the server has booted."
    }

    /// The sync provider whose folder holds `url`, if any.
    static func syncedLocation(_ url: URL) -> String? {
        let dir = url.deletingLastPathComponent().resolvingSymlinksInPath()
        let path = dir.path
        let lib = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library").resolvingSymlinksInPath().path
        if path.hasPrefix(lib + "/Mobile Documents") { return "iCloud Drive" }
        let providers: [(String, String)] = [
            ("Dropbox", "Dropbox"), ("GoogleDrive", "Google Drive"), ("Google Drive", "Google Drive"),
            ("OneDrive", "OneDrive"), ("iCloud Drive", "iCloud Drive"),
        ]
        for component in dir.pathComponents {
            for (needle, name) in providers where component == needle || component.hasPrefix(needle + "-") {
                return name
            }
        }
        if path.hasPrefix(lib + "/CloudStorage") { return "a cloud storage provider" }
        // Desktop & Documents in iCloud, and any other ubiquitous folder.
        if (try? dir.resourceValues(forKeys: [.isUbiquitousItemKey]))?.isUbiquitousItem == true {
            return "iCloud Drive"
        }
        return nil
    }

    /// Writes `data` to `url` as a 0600 file from the start: a temporary
    /// sibling created with `O_CREAT | O_EXCL` and mode 0600, then renamed
    /// over `url`. No window where the key sits in a world-readable file.
    static func writePrivate(_ data: Data, to url: URL) throws {
        let tmp = url.deletingLastPathComponent()
            .appendingPathComponent(".\(url.lastPathComponent).\(UUID().uuidString).tmp")
        let fd = tmp.path.withCString {
            open($0, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, mode_t(0o600))
        }
        guard fd >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
        let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        do {
            try handle.write(contentsOf: data)
            try handle.synchronize()
            try handle.close()
            guard rename(tmp.path, url.path) == 0 else {
                throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
            }
        } catch {
            try? handle.close()
            unlink(tmp.path)
            throw error
        }
    }
}
