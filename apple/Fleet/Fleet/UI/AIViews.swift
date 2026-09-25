import SwiftUI

/// Settings → AI (design §8): pause switch, paired MCP clients, setup.
struct AISettings: View {
    @Environment(AIModel.self) private var ai

    var body: some View {
        Form {
            Section {
                Toggle("Pause all AI agents", isOn: Binding(
                    get: { ai.paused }, set: { ai.setPaused($0) }))
                Text("While paused, every MCP call is rejected at once.")
                    .font(.caption11).foregroundStyle(Color.textMuted)
            }
            Section("Paired clients") {
                if ai.clients.isEmpty {
                    Text("None yet. A client is paired the first time it connects, with Touch ID.")
                        .foregroundStyle(Color.textMuted)
                }
                ForEach(ai.clients, id: \.key) { c in
                    HStack {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(c.clientName).foregroundStyle(Color.text)
                            Text("via \(c.parentSigningId)\(c.parentTeam.isEmpty ? " (unsigned)" : " · \(c.parentTeam)")")
                                .font(.caption11).foregroundStyle(Color.textMuted)
                        }
                        Spacer()
                        Text(Date(timeIntervalSince1970: Double(c.pairedMs) / 1000)
                            .formatted(date: .abbreviated, time: .omitted))
                            .font(.caption11).foregroundStyle(Color.textMuted)
                        Button("Revoke", role: .destructive) { ai.revoke(c) }
                            .controlSize(.small)
                    }
                }
            }
            Section("Setup") {
                Text("Add to your MCP client: command `\(fleetctlPath)` with argument `mcp`.")
                    .font(.secondary).textSelection(.enabled)
                if let p = ai.socketPath {
                    LabeledContent("Socket", value: p).font(.caption11)
                }
                if let e = ai.socketError {
                    Text(e).foregroundStyle(Tone.critical.text)
                }
                Text("Elevated operations and bulk actions on more than 5 servers wait for your Touch ID. Tools for keys, roster, policy and recovery don't exist.")
                    .font(.caption11).foregroundStyle(Color.textMuted)
            }
        }
        .formStyle(.grouped)
        .onAppear { ai.reloadClients() }
    }

    private var fleetctlPath: String {
        Bundle.main.bundleURL.appendingPathComponent("Contents/MacOS/fleetctl").path
    }
}

/// Operator prompt for AI pairing and AI-initiated elevated/bulk actions.
struct AIPromptSheet: View {
    @Environment(AIModel.self) private var ai
    @Environment(CoreBridge.self) private var core
    let prompt: McpPromptRow
    @State private var busy = false

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            switch prompt.kind {
            case .pairing(let name, let team, let parent):
                Label("New AI client", systemImage: "sparkles").font(.toolbarTitle)
                Text("\(name) wants to use Fleet through fleetctl.")
                LabeledContent("Launched by", value: parent)
                LabeledContent("Team", value: team.isEmpty ? "unsigned" : team)
                Text("Once paired it can call every operation the server policies allow. Elevated and wide actions still need your Touch ID each time. You can revoke it in Settings → AI.")
                    .font(.secondary).foregroundStyle(Color.textSecondary)
            case .approval(let client, let tool, let op, let details, let servers, let elevated):
                Label(elevated ? "AI requests an elevated operation" : "AI requests a bulk action",
                      systemImage: elevated ? "exclamationmark.shield" : "square.stack.3d.up")
                    .font(.toolbarTitle)
                    .foregroundStyle(elevated ? Tone.warn.text : Color.text)
                LabeledContent("Client", value: client)
                LabeledContent("Tool", value: tool)
                LabeledContent("Operation", value: op)
                LabeledContent("Servers", value: "\(servers.count)")
                ScrollView {
                    VStack(alignment: .leading, spacing: 6) {
                        Text(servers.map(name).joined(separator: ", "))
                            .font(.secondary)
                        Text(details)
                            .font(.system(size: 11, design: .monospaced))
                            .foregroundStyle(Color.textSecondary)
                            .textSelection(.enabled)
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
                .frame(maxHeight: 180)
                Text(elevated
                     ? "Approving asks the root key's Touch ID once for all \(servers.count) servers."
                     : "Approving asks for Touch ID. The first server runs alone as a canary.")
                    .font(.caption11).foregroundStyle(Color.textMuted)
            }
            HStack {
                Button("Pause AI") { ai.setPaused(true) }
                Spacer()
                Button("Deny", role: .cancel) { answer(false) }
                    .keyboardShortcut(.cancelAction)
                Button("Approve") { answer(true) }
                    .buttonStyle(.borderedProminent)
            }
            .disabled(busy)
        }
        .padding(20)
        .frame(width: 480)
    }

    private func name(_ id: String) -> String { core.servers.first { $0.id == id }?.name ?? id }

    private func answer(_ ok: Bool) {
        busy = true
        Task {
            await ai.answer(prompt, approve: ok)
            busy = false
        }
    }
}

extension McpPromptRow: Identifiable {}
