import AppKit
import SwiftUI
import UniformTypeIdentifiers

/// Add a server and install the agent (design §10.1):
/// details → host key confirmation (first use) → agent install → done.
/// With `existing`, starts at the host key / install step for a server
/// that is already in the list.
struct AddServerSheet: View {
    @Environment(CoreBridge.self) private var core
    @Environment(\.dismiss) private var dismiss
    var existing: ServerRow?

    private enum Step { case details, probing, hostKey, install, installing, done }

    @State private var step: Step = .details
    @State private var serverId: String?
    @State private var name = ""
    @State private var host = ""
    @State private var port = "22"
    @State private var user = "root"
    @State private var jump = ""
    @State private var groupId: String?
    @State private var tags = ""
    @State private var prompt: HostKeyPrompt?
    @State private var artifact: URL?
    @State private var adminUser = ""
    @State private var securityMode: SecurityModeArg = .managed
    @State private var run = InstallRun()
    @State private var health: AgentHealthRow?
    @State private var error: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text(title).font(.sectionTitle)
                .accessibilityIdentifier("addServer.title")
            switch step {
            case .details: details
            case .probing: busy("Connecting with this Mac's SSH key…")
            case .hostKey: hostKeyStep
            case .install: installStep
            case .installing: installingStep
            case .done: doneStep
            }
            if let error {
                Text(error).font(.base).foregroundStyle(Tone.critical.text)
                    .textSelection(.enabled)
                    .accessibilityIdentifier("addServer.error")
            }
        }
        .padding(24)
        .frame(width: 540)
        .onAppear(perform: resume)
    }

    private var title: String {
        switch step {
        case .details: "Add server"
        case .probing, .hostKey: "Confirm host key"
        case .install, .installing: "Install agent"
        case .done: "Agent installed"
        }
    }

    // MARK: details

    private var details: some View {
        VStack(alignment: .leading, spacing: 12) {
            Form {
                TextField("Name", text: $name, prompt: Text("web-04"))
                    .accessibilityIdentifier("addServer.name")
                TextField("Host", text: $host, prompt: Text("203.0.113.14"))
                    .accessibilityIdentifier("addServer.host")
                TextField("Port", text: $port)
                    .accessibilityIdentifier("addServer.port")
                TextField("User", text: $user)
                    .accessibilityIdentifier("addServer.user")
                TextField("Jump hosts", text: $jump, prompt: Text("user@bastion:22 (optional)"))
                    .accessibilityIdentifier("addServer.jump")
                Picker("Group", selection: $groupId) {
                    Text("None").tag(String?.none)
                    ForEach(core.groups, id: \.id) { Text($0.name).tag(Optional($0.id)) }
                }
                .accessibilityIdentifier("addServer.group")
                TextField("Tags", text: $tags, prompt: Text("web, eu-central"))
                    .accessibilityIdentifier("addServer.tags")
            }
            .formStyle(.grouped)
            sshKeyBox
            HStack {
                Button("Cancel") { dismiss() }
                    .accessibilityIdentifier("addServer.cancel")
                Spacer()
                Button("Add only") { add(connect: false) }
                    .accessibilityIdentifier("addServer.addOnly")
                Button("Add and connect") { add(connect: true) }
                    .accessibilityIdentifier("addServer.addConnect")
                    .buttonStyle(.borderedProminent).tint(.accent)
                    .keyboardShortcut(.defaultAction)
            }
        }
    }

    /// The Mac's SSH public key: the operator authorizes it on the server.
    private var sshKeyBox: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("Authorize this Mac's SSH key for the user first:")
                .font(.secondary).foregroundStyle(Color.textSecondary)
            HStack(alignment: .top) {
                Text(core.sshPublicKey() ?? "Unlock Fleet to read the SSH key.")
                    .font(.mono(11)).foregroundStyle(Color.text)
                    .lineLimit(3).truncationMode(.middle)
                    .textSelection(.enabled)
                    .accessibilityIdentifier("addServer.sshKey")
                Spacer()
                Button("Copy", systemImage: "doc.on.doc") {
                    guard let k = core.sshPublicKey() else { return }
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(k, forType: .string)
                }
                .labelStyle(.iconOnly)
                .help("Copy for ~/.ssh/authorized_keys")
            }
        }
        .card(padding: 12)
    }

    // MARK: host key

    private var hostKeyStep: some View {
        VStack(alignment: .leading, spacing: 12) {
            if let prompt {
                Text("Compare this fingerprint with the one from your provider's console or `ssh-keygen -lf /etc/ssh/ssh_host_*_key.pub` on the server.")
                    .font(.base).foregroundStyle(Color.textSecondary)
                VStack(alignment: .leading, spacing: 4) {
                    Text(prompt.algorithm).font(.secondary).foregroundStyle(Color.textMuted)
                    Text(prompt.fingerprint).font(.mono(13)).foregroundStyle(Color.text)
                        .textSelection(.enabled)
                        .accessibilityIdentifier("addServer.fingerprint")
                }
                .card(padding: 12)
                ForEach(prompt.jumps, id: \.self) { j in
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Jump host \(j.host):\(j.port) · \(j.algorithm)")
                            .font(.secondary).foregroundStyle(Color.textMuted)
                        Text(j.fingerprint).font(.mono(13)).foregroundStyle(Color.text)
                            .textSelection(.enabled)
                    }
                    .card(padding: 12)
                }
                if prompt.viaJumpUnpinned {
                    StatusPill(label: "Jump host keys above are new too and will be pinned", tone: .warn)
                }
            }
            HStack {
                Button("Reject") { reject() }
                    .accessibilityIdentifier("addServer.reject")
                Spacer()
                Button("Trust and continue") { trust() }
                    .accessibilityIdentifier("addServer.trust")
                    .buttonStyle(.borderedProminent).tint(.accent)
            }
        }
    }

    // MARK: install

    private var installStep: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Choose the agent package (`fleet-agent_*.deb`) or a `fleet-agent` binary. The user needs passwordless sudo (or be root).")
                .font(.base).foregroundStyle(Color.textSecondary)
            HStack {
                Text(artifact?.lastPathComponent ?? "No file chosen")
                    .font(.mono(12))
                    .foregroundStyle(artifact == nil ? Color.textMuted : Color.text)
                    .accessibilityIdentifier("addServer.artifactName")
                Spacer()
                Button("Choose…") { chooseArtifact() }
                    .accessibilityIdentifier("addServer.chooseArtifact")
            }
            .card(padding: 12)
            Form {
                TextField("Admin user", text: $adminUser, prompt: Text(user))
                    .accessibilityIdentifier("addServer.adminUser")
                Picker("Security", selection: $securityMode) {
                    Text("Managed by Fleet").tag(SecurityModeArg.managed)
                    Text("Agent only (don't change security)").tag(SecurityModeArg.agentOnly)
                }
                .accessibilityIdentifier("addServer.security")
            }
            .formStyle(.grouped)
            securityModeHint
            HStack {
                Button("Later") { dismiss() }
                    .accessibilityIdentifier("addServer.later")
                Spacer()
                Button("Install") { install() }
                    .accessibilityIdentifier("addServer.install")
                    .buttonStyle(.borderedProminent).tint(.accent)
                    .disabled(artifact == nil)
            }
        }
    }

    private var securityModeHint: some View {
        Text(securityMode == .managed
             ? "Fleet manages bans and keeps this server's authorized_keys file in sync with the roster."
             : "Fleet won't touch bans, authorized_keys or the firewall on this server. Switch to Managed later from the server's Overview tab.")
            .font(.secondary).foregroundStyle(Color.textSecondary)
    }

    private static let steps: [(InstallStep, String)] = [
        (.connecting, "Connect"),
        (.uploading, "Upload"),
        (.verifying, "Verify upload"),
        (.installing, "Install"),
        (.starting, "Start services"),
        (.cleaningUp, "Clean up"),
        (.pinning, "Pin agent keys"),
        (.waitingForAgent, "Connect to agent"),
        (.checkingHealth, "Signed health check"),
    ]

    private var installingStep: some View {
        let progress = run.progress
        let current = run.current
        return VStack(alignment: .leading, spacing: 8) {
            ForEach(Self.steps.indices, id: \.self) { i in
                let (s, label) = Self.steps[i]
                HStack(spacing: 10) {
                    Group {
                        if current == s && error == nil {
                            ProgressView().controlSize(.small)
                        } else if progress[s] != nil {
                            Image(systemName: current == s ? "xmark.circle" : "checkmark.circle.fill")
                                .foregroundStyle(current == s ? Tone.critical.text : Tone.ok.text)
                        } else {
                            Image(systemName: "circle").foregroundStyle(Color.textMuted)
                        }
                    }
                    .frame(width: 18)
                    Text(label).foregroundStyle(progress[s] != nil ? Color.text : Color.textMuted)
                        .accessibilityIdentifier("addServer.step.\(label)")
                    if s == .uploading, let p = progress[s], p.totalBytes > 0 {
                        Spacer()
                        Text("\(Format.bytes(p.doneBytes)) / \(Format.bytes(p.totalBytes))")
                            .font(.mono(11)).foregroundStyle(Color.textMuted)
                    }
                }
            }
            if error != nil {
                HStack {
                    Button("Close") { dismiss() }
                        .accessibilityIdentifier("addServer.close")
                    Spacer()
                    Button("Try again") { error = nil; step = .install }
                        .accessibilityIdentifier("addServer.retry")
                }
            }
        }
    }

    private var doneStep: some View {
        VStack(alignment: .leading, spacing: 12) {
            if let health {
                LabeledContent("Agent", value: health.agentVersion)
                LabeledContent("Roster", value: "epoch \(health.rosterEpoch) · v\(health.rosterVersion)")
                LabeledContent("Policy", value: "v\(health.policyVersion)")
            }
            Text("The server is connected over a verified agent session.")
                .foregroundStyle(Color.textSecondary)
            HStack {
                Spacer()
                Button("Done") { dismiss() }
                    .accessibilityIdentifier("addServer.done")
                    .buttonStyle(.borderedProminent).tint(.accent)
                    .keyboardShortcut(.defaultAction)
            }
        }
    }

    private func busy(_ text: String) -> some View {
        HStack(spacing: 10) {
            ProgressView().controlSize(.small)
            Text(text).foregroundStyle(Color.textSecondary)
        }
    }

    // MARK: actions

    private func resume() {
        guard let s = existing, serverId == nil else { return }
        serverId = s.id
        user = s.user
        if s.hostKeyPinned {
            step = .install
        } else {
            probe()
        }
    }

    private func add(connect: Bool) {
        error = nil
        guard let p = UInt16(port) else {
            error = "Port must be 1–65535."
            return
        }
        let tagList = tags.split(separator: ",")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
        do {
            let row = try core.addServer(NewServer(
                name: name, host: host, port: p, user: user, groupId: groupId,
                tags: tagList, proxyJump: jump.isEmpty ? nil : jump))
            serverId = row?.id
            if connect { probe() } else { dismiss() }
        } catch {
            self.error = error.fleetMessage
        }
    }

    private func probe() {
        guard let api = core.api, let id = serverId else { return }
        step = .probing
        error = nil
        Task {
            do {
                prompt = try await api.probeHostKey(serverId: id)
                step = .hostKey
            } catch {
                self.error = error.fleetMessage
                step = .hostKey
            }
        }
    }

    private func trust() {
        guard let api = core.api, let id = serverId, let prompt else { return }
        do {
            // Binds the pin to exactly the fingerprints shown above.
            try api.acceptHostKey(serverId: id, fingerprint: prompt.fingerprint,
                                  jumpFingerprints: prompt.jumps.map(\.fingerprint))
            core.reload()
            error = nil
            step = .install
        } catch {
            self.error = error.fleetMessage
        }
    }

    private func reject() {
        if let id = serverId { try? core.api?.rejectHostKey(serverId: id) }
        dismiss()
    }

    private func chooseArtifact() {
        if let preset = TestHooks.agentArtifact {
            artifact = preset
            return
        }
        let panel = NSOpenPanel()
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = false
        panel.message = "Choose the fleet-agent package or binary"
        if panel.runModal() == .OK { artifact = panel.url }
    }

    private func install() {
        guard let api = core.api, let id = serverId, let artifact else { return }
        error = nil
        let run = InstallRun()
        self.run = run
        step = .installing
        let relay = InstallRelay { p in
            Task { @MainActor in run.update(p) }
        }
        let admin = adminUser.trimmingCharacters(in: .whitespaces)
        Task {
            do {
                health = try await api.installAgent(
                    serverId: id, adminUser: admin.isEmpty ? nil : admin,
                    artifactPath: artifact.path, securityMode: securityMode, listener: relay)
                core.reload()
                step = .done
            } catch {
                self.error = error.fleetMessage
            }
        }
    }
}

@Observable
@MainActor
private final class InstallRun {
    private(set) var progress: [InstallStep: InstallProgress] = [:]
    private(set) var current: InstallStep?

    func update(_ p: InstallProgress) {
        progress[p.step] = p
        current = p.step
    }
}

/// Install progress from the core thread to the main actor.
private final class InstallRelay: InstallListener {
    private let handler: @Sendable (InstallProgress) -> Void
    init(_ handler: @escaping @Sendable (InstallProgress) -> Void) { self.handler = handler }
    func onProgress(progress: InstallProgress) { handler(progress) }
}
