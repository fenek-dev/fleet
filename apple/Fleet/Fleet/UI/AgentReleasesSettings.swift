import AppKit
import SwiftUI

/// Settings → Agent releases (design §5.7, §10.2): import a build, compare
/// its hash with an independent reproducible build, sign the release
/// manifest with the root key (Touch ID), roll it out through the canary
/// sequence (1 server, 10%, the rest).
struct AgentReleasesSettings: View {
    @Environment(CoreBridge.self) private var core
    @State private var releases: [AgentReleaseRow] = []
    @State private var artifact: URL?
    @State private var hash: String?
    @State private var version = ""
    @State private var target = "x86_64"
    @State private var attested = ""
    @State private var busy = false
    @State private var error: String?
    @State private var progress = BulkProgress()
    @State private var rollbackServer: String?
    @State private var confirmRollback = false
    @State private var rollbackNote: String?

    private var attestationMatches: Bool {
        guard let hash else { return false }
        let first = attested.split(whereSeparator: \.isWhitespace).first.map(String.init) ?? ""
        return first.lowercased() == hash
    }

    var body: some View {
        Form {
            Section("Import a build") {
                HStack {
                    Text(artifact?.lastPathComponent ?? "No file chosen")
                        .foregroundStyle(artifact == nil ? Color.textMuted : Color.primary)
                    Spacer()
                    Button("Choose…") { choose() }.disabled(busy)
                        .accessibilityIdentifier("releases.choose")
                }
                if let hash {
                    LabeledContent("BLAKE3 of the binary") {
                        Text(hash).font(.mono(11)).textSelection(.enabled)
                    }
                }
                TextField("Version (major.minor.patch)", text: $version)
                    .accessibilityIdentifier("releases.version")
                Picker("Architecture", selection: $target) {
                    Text("x86_64 (amd64)").tag("x86_64")
                    Text("aarch64 (arm64)").tag("aarch64")
                }
                TextField("Independent build's BLAKE3 (b3sum output)", text: $attested)
                    .accessibilityIdentifier("releases.attested")
                    .font(.mono(11))
                Text("Rebuild the same source on a second machine or CI (pinned toolchain, "
                     + "--locked) and paste its hash. The app signs only when both builds agree.")
                    .font(.secondary).foregroundStyle(Color.textMuted)
                if hash != nil && !attested.isEmpty && !attestationMatches {
                    Text("The hashes differ: this build is not reproducible or not the same source.")
                        .foregroundStyle(Tone.critical.text)
                }
                Button("Sign release…") { sign() }
                    .accessibilityIdentifier("releases.sign")
                    .disabled(busy || !attestationMatches || version.isEmpty)
            }
            Section("Signed releases") {
                if releases.isEmpty {
                    Text("None yet.").foregroundStyle(Color.textMuted)
                }
                ForEach(releases, id: \.blake3) { r in
                    HStack {
                        VStack(alignment: .leading, spacing: 2) {
                            Text("v\(r.version) (\(r.target))")
                            Text(r.blake3.prefix(16) + "…  " + (r.artifactPath as NSString).lastPathComponent)
                                .font(.secondary).foregroundStyle(Color.textMuted)
                        }
                        Spacer()
                        Button("Roll out to all servers…") { rollout(r) }
                            .accessibilityIdentifier("releases.rollout")
                            .disabled(busy || progress.isRunning || core.servers.isEmpty)
                    }
                }
            }
            Section("Roll back an agent") {
                Text("Swaps the previous agent build back in on one server and restarts it. "
                     + "Needs Touch ID. Refused while an update is still awaiting confirmation.")
                    .font(.secondary).foregroundStyle(Color.textMuted)
                Picker("Server", selection: $rollbackServer) {
                    Text("Choose…").tag(String?.none)
                    ForEach(core.servers.filter(\.agentPinned), id: \.id) {
                        Text($0.name).tag(Optional($0.id))
                    }
                }
                .accessibilityIdentifier("releases.rollbackServer")
                HStack {
                    Button("Roll back…") { confirmRollback = true }
                        .disabled(busy || rollbackServer == nil)
                        .accessibilityIdentifier("releases.rollback")
                    if let rollbackNote {
                        Text(rollbackNote).font(.secondary).foregroundStyle(Tone.ok.text)
                            .accessibilityIdentifier("releases.rollbackDone")
                    }
                }
            }
            if progress.total > 0 {
                Section("Rollout") {
                    if let c = progress.canaryPassed {
                        Text("Phase passed after \(c)").font(.secondary)
                    }
                    ForEach(progress.rows) { row in
                        LabeledContent(row.id, value: row.status.map { "\($0)" } ?? "queued")
                    }
                    if let s = progress.summary {
                        Text("\(s.succeeded) updated, \(s.failed) failed, \(s.skipped) skipped"
                             + (s.stop.map { " — stopped: \($0)" } ?? ""))
                    }
                    if progress.isRunning {
                        Button("Stop") { progress.cancel() }
                    }
                }
            }
            if let error {
                Text(error).foregroundStyle(Tone.critical.text)
            }
        }
        .formStyle(.grouped)
        .task(id: core.fleetRevision) { load() }
        .confirmationDialog(
            "Roll back the agent on \(rollbackName)?", isPresented: $confirmRollback,
            titleVisibility: .visible
        ) {
            Button("Roll back (Touch ID)", role: .destructive) { rollback() }
                .accessibilityIdentifier("releases.confirmRollback")
        } message: {
            Text("The previous build replaces the running one and the agent restarts; "
                 + "the connection drops briefly.")
        }
    }

    private var rollbackName: String {
        core.servers.first { $0.id == rollbackServer }?.name ?? "this server"
    }

    private func rollback() {
        guard let api = core.api, let id = rollbackServer else { return }
        busy = true
        error = nil
        rollbackNote = nil
        let name = rollbackName
        Task {
            defer { busy = false }
            do {
                try await api.rollbackAgent(serverId: id)
                rollbackNote = "Rolled back \(name); it restarts now."
            } catch { self.error = error.fleetMessage }
        }
    }

    private func load() {
        guard let api = core.api else { return }
        do { releases = try api.listAgentReleases() } catch { self.error = error.fleetMessage }
    }

    private func choose() {
        let panel = NSOpenPanel()
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = false
        panel.message = "Choose the fleet-agent binary or .deb (scripts/build-deb.sh)"
        guard panel.runModal() == .OK, let url = panel.url, let api = core.api else { return }
        artifact = url
        hash = nil
        busy = true
        Task {
            defer { busy = false }
            do { hash = try await api.agentArtifactHash(artifactPath: url.path) } catch {
                self.error = error.fleetMessage
            }
        }
    }

    private func sign() {
        guard let api = core.api, let artifact else { return }
        busy = true
        error = nil
        Task {
            defer { busy = false }
            do {
                _ = try await api.importAgentRelease(
                    artifactPath: artifact.path, version: version, target: target,
                    attestedBlake3: attested)
                load()
            } catch { self.error = error.fleetMessage }
        }
    }

    private func rollout(_ r: AgentReleaseRow) {
        guard let api = core.api else { return }
        let ids = core.servers.map(\.id)
        progress.reset(targets: ids)
        error = nil
        do {
            progress.handle = try api.rolloutAgentRelease(
                version: r.version, target: r.target, targets: ids, listener: progress.listener())
        } catch { self.error = error.fleetMessage }
    }
}
