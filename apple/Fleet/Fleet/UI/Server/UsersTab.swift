import SwiftUI

extension UnixUserRow: Identifiable { public var id: String { name } }

/// Groups that grant root-equivalent access (the protocol's own list).
private let privilegedGroupSet = Set(privilegedGroups())

struct NewUserSheet: View {
    @Environment(\.dismiss) private var dismiss
    let create: (String, [String], LoginShellArg, String) -> Void
    @State private var name = ""
    @State private var groups = ""
    @State private var shell: LoginShellArg = .bash
    @State private var comment = ""

    private var groupList: [String] {
        groups.split(whereSeparator: { $0 == "," || $0 == " " }).map(String.init)
    }

    var body: some View {
        Form {
            TextField("Login name", text: $name)
            TextField("Groups (comma-separated)", text: $groups)
            Picker("Shell", selection: $shell) {
                Text("bash").tag(LoginShellArg.bash)
                Text("sh").tag(LoginShellArg.sh)
                Text("no login").tag(LoginShellArg.nologin)
            }
            TextField("Full name / comment", text: $comment)
            if groupList.contains(where: privilegedGroupSet.contains) {
                Text("Privileged groups: creating this user requires Touch ID approval (root key).")
                    .font(.caption11).foregroundStyle(Tone.warn.text)
            }
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }
                Button("Create…") { create(name, groupList, shell, comment); dismiss() }
                    .buttonStyle(.borderedProminent).tint(.accent).disabled(name.isEmpty)
            }
        }
        .padding(20)
        .frame(width: 420)
    }
}

/// Users, groups and SSH keys (design §2.5, §5.9). The extra section of
/// `/etc/fleet/authorized_keys/<user>` is auto-reverted like the firewall.
struct UsersTab: View {
    @Environment(CoreBridge.self) private var core
    let server: ServerRow
    @State private var data: UnixUsersRow?
    @State private var showSystem = false
    @State private var selection: String?
    @State private var keys: AuthorizedKeysRow?
    @State private var keysText = ""
    @State private var groupsText = ""
    @State private var creating = false
    @State private var loading = false
    @State private var error: String?
    @State private var pending: PendingAction?
    @State private var revert = AutoRevertModel()

    private var users: [UnixUserRow] {
        (data?.users ?? []).filter { showSystem || !$0.system }
    }

    private var selected: UnixUserRow? { users.first { $0.name == selection } }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            TabHeader(title: "Users", loading: loading, error: error, refresh: { Task { await load() } }) {
                Toggle("System accounts", isOn: $showSystem)
                Button("New user…", systemImage: "person.badge.plus") { creating = true }
            }
            AutoRevertBanner(model: revert, what: "SSH keys changed", retry: retryConfirm,
                             revertNow: revertNow)
            HSplitView {
                VStack(spacing: 12) {
                    Table(users, selection: $selection) {
                        TableColumn("User") { u in Text(u.name) }
                        TableColumn("UID") { u in Text("\(u.uid)") }.width(60)
                        TableColumn("Groups") { u in Text(u.groups.joined(separator: ", ")).lineLimit(1) }
                        TableColumn("Shell") { u in Text(u.shell).font(.mono(11)) }.width(130)
                        TableColumn("Last login") { u in Text(fmtDate(u.lastLoginMs)) }.width(140)
                        TableColumn("") { u in
                            HStack(spacing: 4) {
                                if u.locked { StatusPill(label: "locked", tone: .warn) }
                                if u.privileged { StatusPill(label: "admin", tone: .info) }
                            }
                        }
                        .width(140)
                    }
                    .tableCard()
                    Table(Indexed.wrap(data?.groups ?? [])) {
                        TableColumn("Group") { g in Text(g.value.name) }
                        TableColumn("GID") { g in Text("\(g.value.gid)") }.width(60)
                        TableColumn("Members") { g in Text(g.value.members.joined(separator: ", ")).lineLimit(1) }
                    }
                    .tableCard()
                    .frame(maxHeight: 200)
                }
                .frame(minWidth: 520)
                detail.frame(minWidth: 360)
            }
        }
        .padding(24)
        .task(id: server.id) { await load() }
        .onChange(of: selection) { _, _ in Task { await loadUser() } }
        .confirmAction($pending)
        .sheet(isPresented: $creating) {
            NewUserSheet { name, groups, shell, comment in
                pending = PendingAction(title: "Create user \(name) on \(server.name)?",
                                        message: groups.isEmpty ? "" : "Groups: \(groups.joined(separator: ", "))",
                                        button: "Create",
                                        elevated: groups.contains(where: privilegedGroupSet.contains)) {
                    run { try await $0.usersCreate(serverId: server.id, name: name, groups: groups,
                                                   shell: shell, comment: comment) }
                }
            }
        }
    }

    @ViewBuilder private var detail: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 10) {
                if let u = selected {
                    Text(u.name).font(.system(size: 15, weight: .semibold))
                    Text("\(u.home) · uid \(u.uid)").font(.caption11).foregroundStyle(Color.textMuted)
                    HStack {
                        Button(u.locked ? "Unlock" : "Lock") { askLock(u) }
                        Button("Delete…") { askDelete(u) }
                    }
                    .controlSize(.small)
                    Divider()
                    Text("Groups").font(.system(size: 13, weight: .semibold))
                    HStack {
                        TextField("sudo, www-data", text: $groupsText).textFieldStyle(.roundedBorder)
                        Button("Save") { askGroups(u) }
                            .disabled(groupsText == u.groups.joined(separator: ", "))
                    }
                    Divider()
                    keysSection(u)
                } else {
                    Text("Select a user").foregroundStyle(Color.textMuted)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .card()
    }

    @ViewBuilder private func keysSection(_ u: UnixUserRow) -> some View {
        Text("SSH keys").font(.system(size: 13, weight: .semibold))
        if let k = keys, k.user == u.name {
            if !k.rosterLines.isEmpty {
                Text("Fleet Macs (managed by the roster)").font(.caption11).foregroundStyle(Color.textMuted)
                ForEach(k.rosterLines, id: \.self) { l in
                    Text(l).font(.mono(10)).lineLimit(1).truncationMode(.middle).foregroundStyle(Color.textSecondary)
                }
            }
            Text("Other keys (one per line)").font(.caption11).foregroundStyle(Color.textMuted)
            TextEditor(text: $keysText)
                .font(.mono(11)).frame(height: 120)
                .scrollContentBackground(.hidden)
                .background(Color.track, in: RoundedRectangle(cornerRadius: 8))
            Button("Save keys…") { askKeys(u, k) }
                .disabled(keysLines == k.extra || revert.phase == .confirming)
        } else {
            Text("No key file loaded.").font(.secondary).foregroundStyle(Color.textMuted)
        }
    }

    private var keysLines: [String] {
        keysText.split(whereSeparator: \.isNewline).map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
    }

    // MARK: actions

    private func askLock(_ u: UnixUserRow) {
        let lock = !u.locked
        pending = PendingAction(title: "\(lock ? "Lock" : "Unlock") \(u.name) on \(server.name)?",
                                message: lock ? "Password and key logins stop working for this account." : "",
                                button: lock ? "Lock" : "Unlock", destructive: lock) {
            run { try await $0.usersLock(serverId: server.id, name: u.name, locked: lock) }
        }
    }

    private func askDelete(_ u: UnixUserRow) {
        pending = PendingAction(title: "Delete \(u.name) on \(server.name)?",
                                message: "The account is removed; its home directory \(u.home) is kept.",
                                button: "Delete", destructive: true) {
            run { try await $0.usersDelete(serverId: server.id, name: u.name, removeHome: false) }
        }
    }

    private func askGroups(_ u: UnixUserRow) {
        let groups = groupsText.split(whereSeparator: { $0 == "," || $0 == " " }).map(String.init)
        pending = PendingAction(title: "Set \(u.name)'s groups?", message: groups.joined(separator: ", "),
                                button: "Save", elevated: groups.contains(where: privilegedGroupSet.contains)) {
            run { try await $0.usersGroupsSet(serverId: server.id, name: u.name, groups: groups) }
        }
    }

    private func askKeys(_ u: UnixUserRow, _ k: AuthorizedKeysRow) {
        let lines = keysLines
        pending = PendingAction(
            title: "Replace \(u.name)'s other SSH keys?",
            message: "\(lines.count) keys. Fleet Macs keep access through the roster section. The change reverts automatically unless Fleet can reconnect and confirm it.",
            button: "Save", elevated: true) {
                guard let api = core.api else { return }
                Task {
                    do {
                        let change = try await api.authorizedKeysSet(serverId: server.id, userName: u.name,
                                                                     keys: lines, expectedVersion: k.version)
                        error = nil
                        revert.confirm(api: api, serverId: server.id, change: change) { Task { await loadUser() } }
                    } catch {
                        self.error = error.fleetMessage
                    }
                }
            }
    }

    private func retryConfirm() {
        guard let api = core.api, let c = revert.change else { return }
        revert.confirm(api: api, serverId: server.id, change: c) { Task { await loadUser() } }
    }

    private func revertNow() {
        guard let api = core.api else { return }
        revert.revertNow(api: api, serverId: server.id) { Task { await loadUser() } }
    }

    private func run(_ op: @escaping (FleetCore) async throws -> Void) {
        guard let api = core.api else { return }
        Task {
            do {
                try await op(api)
                error = nil
            } catch {
                self.error = error.fleetMessage
            }
            await load()
        }
    }

    private func loadUser() async {
        guard let api = core.api, let u = selected else { keys = nil; return }
        groupsText = u.groups.joined(separator: ", ")
        do {
            let k = try await api.authorizedKeysGet(serverId: server.id, userName: u.name)
            keys = k
            keysText = k.extra.joined(separator: "\n")
        } catch {
            keys = nil
        }
    }

    private func load() async {
        guard let api = core.api else { return }
        loading = true
        defer { loading = false }
        do {
            data = try await api.usersList(serverId: server.id)
            error = nil
        } catch {
            self.error = error.fleetMessage
        }
        await loadUser()
    }
}
