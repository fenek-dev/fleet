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

    private enum Step { case details, probing, hostKey, install, existingAgent, installing, done }

    /// What preflight found when the server already has a Fleet agent
    /// (nothing was changed yet).
    private struct ExistingInfo {
        var execActive: Bool
        var stateKnown: Bool
        var keysKnown: Bool
        /// This Mac opened a verified session: it is in the agent's roster.
        var sameFleet: Bool
        var sshSwitched: Bool
    }
    @State private var existingInfo: ExistingInfo?
    /// The one-time password, kept (wipeable) while the operator decides
    /// what to do with an existing agent, so it needn't be typed twice.
    @State private var heldSecret: SecretBytes?
    @State private var adopting = false

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
    /// One-time server password (design §10.1): used only to add this Mac's
    /// key and to answer `sudo` during the install. Never stored; cleared
    /// from the field the moment the install starts.
    @State private var password = ""
    @State private var usePassword = false
    /// The server refused this Mac's key at the probe: the password adds it.
    @State private var keyRefused = false
    /// This run adds the key first (shows that step).
    @State private var addingKey = false

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text(title).font(.sectionTitle)
                .accessibilityIdentifier("addServer.title")
            switch step {
            case .details: details
            case .probing: busy("Connecting with this Mac's SSH key…")
            case .hostKey: hostKeyStep
            case .install: installStep
            case .existingAgent: existingAgentStep
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
        .onDisappear { heldSecret?.wipe(); heldSecret = nil }
    }

    private var title: String {
        switch step {
        case .details: "Add server"
        case .probing, .hostKey: "Confirm host key"
        case .install, .installing: "Install agent"
        case .existingAgent: "Existing agent found"
        case .done: adopting ? "Agent adopted" : "Agent installed"
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
                if keyRefused {
                    Text("The server doesn't accept this Mac's SSH key yet. Nothing was sent to it besides the host key exchange. After you trust the fingerprint, you can enter the user's password once to add the key.")
                        .font(.secondary).foregroundStyle(Color.textSecondary)
                        .accessibilityIdentifier("addServer.keyRefusedHint")
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
            Text(Self.bundledAgentDir != nil
                 ? "Fleet installs its bundled agent, matched to the server's architecture (Debian 12+ / Ubuntu 22.04+). The user needs passwordless sudo (or be root), or the password below."
                 : "Choose the agent package (`fleet-agent_*.deb`) or a `fleet-agent` binary. The user needs passwordless sudo (or be root), or the password below.")
                .font(.base).foregroundStyle(Color.textSecondary)
            HStack {
                Text(artifact?.lastPathComponent
                     ?? (Self.bundledAgentDir != nil ? "Bundled agent (.deb)" : "No file chosen"))
                    .font(.mono(12))
                    .foregroundStyle(canInstall ? Color.text : Color.textMuted)
                    .accessibilityIdentifier("addServer.artifactName")
                Spacer()
                if artifact != nil, Self.bundledAgentDir != nil, TestHooks.agentArtifact == nil {
                    Button("Use bundled") { artifact = nil }
                        .accessibilityIdentifier("addServer.useBundled")
                }
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
            passwordBox
            HStack {
                Button("Later") { dismiss() }
                    .accessibilityIdentifier("addServer.later")
                Spacer()
                Button("Install") { install() }
                    .accessibilityIdentifier("addServer.install")
                    .buttonStyle(.borderedProminent).tint(.accent)
                    .disabled(!canInstall || (keyRefused && password.isEmpty))
            }
        }
    }

    /// One-time password: adds this Mac's key when the server refused it,
    /// and answers `sudo`. Not stored.
    @ViewBuilder
    private var passwordBox: some View {
        if usePassword {
            VStack(alignment: .leading, spacing: 6) {
                SecureField("Password for \(user)", text: $password)
                    .textContentType(.password)
                    .accessibilityIdentifier("addServer.password")
                Text("Used once to add this Mac's key and for sudo during install. Not stored.")
                    .font(.secondary).foregroundStyle(Color.textSecondary)
                if !keyRefused {
                    Button("Don't use a password") { usePassword = false; password = "" }
                        .buttonStyle(.link)
                        .accessibilityIdentifier("addServer.noPassword")
                }
            }
            .card(padding: 12)
        } else {
            Button("Set up with password…") { usePassword = true }
                .buttonStyle(.link)
                .accessibilityIdentifier("addServer.usePassword")
        }
    }

    /// `Contents/Resources/agent` when this build embeds agent packages
    /// (scripts/bundle-agent.sh).
    private static let bundledAgentDir: URL? = {
        guard let dir = Bundle.main.resourceURL?.appendingPathComponent("agent", isDirectory: true),
              let names = try? FileManager.default.contentsOfDirectory(atPath: dir.path),
              names.contains(where: { $0.hasSuffix(".deb") })
        else { return nil }
        return dir
    }()

    private var canInstall: Bool { artifact != nil || Self.bundledAgentDir != nil }

    private var securityModeHint: some View {
        Text(securityMode == .managed
             ? "Fleet manages bans and keeps this server's authorized_keys file in sync with the roster."
             : "Fleet won't touch bans, authorized_keys or the firewall on this server. Switch to Managed later from the server's Overview tab.")
            .font(.secondary).foregroundStyle(Color.textSecondary)
    }

    /// An agent is already on the server (nothing was changed): adopt it
    /// when this Mac is in its roster, otherwise replace it (explicitly).
    @ViewBuilder
    private var existingAgentStep: some View {
        let info = existingInfo
        VStack(alignment: .leading, spacing: 12) {
            if info?.sameFleet == true {
                Text("This server already has a Fleet agent from this fleet, and it accepts this Mac. Fleet can use it as it is: nothing is uploaded, restarted or changed.")
                    .font(.base).foregroundStyle(Color.textSecondary)
                    .accessibilityIdentifier("addServer.existing.same")
            } else {
                Text("This server already has a Fleet agent from another fleet. Replace it?")
                    .font(.base).foregroundStyle(Color.text)
                    .accessibilityIdentifier("addServer.existing.other")
                Text("The old agent is stopped and its history is archived on the server in /var/lib/fleet-audit (not deleted). This fleet's roster and policy are installed in its place; Macs of the old fleet lose access to this server.")
                    .font(.secondary).foregroundStyle(Color.textSecondary)
                if info?.sshSwitched == true {
                    Text("The old fleet moved this server's SSH keys to /etc/fleet/authorized_keys. This Mac's key stays valid: the keys already there are kept, and the new roster adds this fleet's Macs.")
                        .font(.secondary).foregroundStyle(Color.textSecondary)
                }
            }
            Text(existingFacts(info)).font(.mono(11)).foregroundStyle(Color.textMuted)
                .accessibilityIdentifier("addServer.existing.facts")
            HStack {
                Button("Cancel") { heldSecret?.wipe(); heldSecret = nil; dismiss() }
                    .accessibilityIdentifier("addServer.existing.cancel")
                Spacer()
                if info?.sameFleet == true {
                    Button("Reinstall anyway") { install(existing: .reinstall) }
                        .accessibilityIdentifier("addServer.existing.reinstall")
                    Button("Use existing agent") { install(existing: .adopt) }
                        .accessibilityIdentifier("addServer.existing.adopt")
                        .buttonStyle(.borderedProminent).tint(.accent)
                } else {
                    Button("Replace agent") { install(existing: .replace) }
                        .accessibilityIdentifier("addServer.existing.replace")
                        .buttonStyle(.borderedProminent).tint(Tone.critical.text)
                }
            }
        }
    }

    private func existingFacts(_ i: ExistingInfo?) -> String {
        guard let i else { return "" }
        return [
            i.execActive ? "agent running" : "agent not running",
            i.stateKnown ? "state present" : "no state",
            i.keysKnown ? "keys readable" : "keys unreadable",
        ].joined(separator: " · ")
    }

    private static let adoptSteps: [(InstallStep, String)] = [
        (.connecting, "Connect"),
        (.pinning, "Pin agent keys"),
        (.waitingForAgent, "Connect to agent"),
        (.checkingHealth, "Signed health check"),
    ]

    private var steps: [(InstallStep, String)] {
        if adopting { return Self.adoptSteps }
        return (addingKey ? [(InstallStep.addingKey, "Add SSH key")] : []) + Self.steps
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
        // "Clean up" runs after a failed step and is reported last; the
        // failed step is the last real one before it.
        let failed = run.working
        return VStack(alignment: .leading, spacing: 8) {
            let steps = steps
            ForEach(steps.indices, id: \.self) { i in
                let (s, label) = steps[i]
                let isFailed = error != nil && failed == s
                HStack(spacing: 10) {
                    Group {
                        if current == s && error == nil {
                            ProgressView().controlSize(.small)
                        } else if isFailed {
                            Image(systemName: "xmark.circle")
                                .foregroundStyle(Tone.critical.text)
                        } else if progress[s] != nil {
                            Image(systemName: "checkmark.circle.fill")
                                .foregroundStyle(Tone.ok.text)
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
            if let a = run.artifact {
                VStack(alignment: .leading, spacing: 2) {
                    Text("\(a.bundled ? "Bundled" : "Chosen") package for \(a.arch): \(a.name)")
                        .font(.secondary).foregroundStyle(Color.textSecondary)
                    Text("BLAKE3 \(a.blake3)")
                        .font(.mono(11)).foregroundStyle(Color.textMuted)
                        .textSelection(.enabled)
                        .accessibilityIdentifier("addServer.artifactHash")
                }
                .card(padding: 10)
            }
            if error != nil {
                HStack {
                    Button("Close") { dismiss() }
                        .accessibilityIdentifier("addServer.close")
                    Spacer()
                    if !run.installed {
                        Button("Try again") { error = nil; step = .install }
                            .accessibilityIdentifier("addServer.retry")
                    }
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
        if let p = TestHooks.serverPassword {
            password = p
            usePassword = true
        }
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
        keyRefused = false
        Task {
            do {
                prompt = try await api.probeHostKey(serverId: id)
                step = .hostKey
            } catch FleetError.SshKeyRefused {
                // Key not authorized yet: read the host key without
                // authenticating, so the operator confirms the fingerprint
                // before any password is sent.
                do {
                    prompt = try await api.probeHostKeyOnly(serverId: id)
                    keyRefused = true
                    usePassword = true
                } catch {
                    self.error = error.fleetMessage
                }
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

    private func install(existing action: ExistingAgentAction = .ask) {
        guard let api = core.api, let id = serverId, canInstall else { return }
        // Priority: the test hook, a file chosen with "Choose…", the bundle.
        let file = TestHooks.agentArtifact ?? artifact
        error = nil
        let run = InstallRun()
        self.run = run
        step = .installing
        let relay = InstallRelay({ p in
            Task { @MainActor in run.update(p) }
        }, artifact: { a in
            Task { @MainActor in run.setArtifact(a) }
        })
        let admin = adminUser.trimmingCharacters(in: .whitespaces)
        // The password moves out of the view state into a wipeable buffer;
        // nothing else holds it once the install call returns.
        // A choice after "existing agent found" reuses the held password.
        let secret = heldSecret
            ?? (usePassword && !password.isEmpty ? SecretBytes(password) : nil)
        heldSecret = nil
        password = ""
        let addKey = keyRefused && secret != nil
        addingKey = addKey
        adopting = action == .adopt
        Task {
            var keep = false
            defer { if !keep { secret?.wipe() } }
            do {
                health = try await api.installAgent(
                    serverId: id, adminUser: admin.isEmpty ? nil : admin,
                    artifactPath: file?.path, bundledDir: Self.bundledAgentDir?.path,
                    bundledPins: BundledArtifacts.agentPins,
                    securityMode: securityMode, password: secret?.data, addKey: addKey,
                    existing: action, listener: relay)
                core.reload()
                step = .done
            } catch FleetError.ExistingAgent(_, let execActive, _, let stateKnown, let keysKnown,
                                             let sameFleet, let sshSwitched) {
                // Nothing was changed: ask what to do. The password stays
                // (wipeable) until the choice is made or the sheet closes.
                existingInfo = ExistingInfo(
                    execActive: execActive, stateKnown: stateKnown, keysKnown: keysKnown,
                    sameFleet: sameFleet, sshSwitched: sshSwitched)
                adopting = false
                heldSecret = secret
                keep = true
                error = nil
                step = .existingAgent
            } catch {
                switch error as? FleetError {
                case .PasswordRefused, .SudoPasswordRequired, .SudoPasswordRefused:
                    usePassword = true
                default: break
                }
                if action == .adopt {
                    // The agent didn't accept this Mac: back to the choices,
                    // where only Replace is left.
                    existingInfo?.sameFleet = false
                    adopting = false
                    heldSecret = secret
                    keep = true
                    self.error = error.fleetMessage
                    step = .existingAgent
                } else {
                    self.error = error.fleetMessage
                }
            }
        }
    }
}

/// The one-time password as bytes that are zeroed after use. A Swift
/// `String` can't be wiped, so the field's text is copied here and the
/// field is cleared at once.
private final class SecretBytes: @unchecked Sendable {
    private(set) var data: Data

    init(_ text: String) { data = Data(text.utf8) }

    func wipe() {
        data.withUnsafeMutableBytes { raw in
            if let base = raw.baseAddress { memset_s(base, raw.count, 0, raw.count) }
        }
        data = Data()
    }
}

@Observable
@MainActor
private final class InstallRun {
    private(set) var progress: [InstallStep: InstallProgress] = [:]
    private(set) var current: InstallStep?
    private(set) var artifact: InstallArtifact?

    func setArtifact(_ a: InstallArtifact) { artifact = a }

    /// Last step that is real work (not the best-effort clean-up).
    private(set) var working: InstallStep?
    /// The agent is installed and its keys are pinned; a later failure
    /// must not re-run the install.
    var installed: Bool { progress[.pinning] != nil }

    func update(_ p: InstallProgress) {
        progress[p.step] = p
        current = p.step
        if p.step != .cleaningUp { working = p.step }
    }
}

/// Install progress from the core thread to the main actor.
private final class InstallRelay: InstallListener {
    private let handler: @Sendable (InstallProgress) -> Void
    private let artifactHandler: @Sendable (InstallArtifact) -> Void
    init(_ handler: @escaping @Sendable (InstallProgress) -> Void,
         artifact: @escaping @Sendable (InstallArtifact) -> Void) {
        self.handler = handler
        self.artifactHandler = artifact
    }
    func onProgress(progress: InstallProgress) { handler(progress) }
    func onArtifact(artifact: InstallArtifact) { artifactHandler(artifact) }
}
