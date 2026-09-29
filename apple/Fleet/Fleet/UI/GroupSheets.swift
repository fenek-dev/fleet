import SwiftUI

extension ServerRow: Identifiable {}

/// Create a group, or rename one (design §2.1: groups, tags and search).
struct GroupNameSheet: View {
    @Environment(CoreBridge.self) private var core
    @Environment(\.dismiss) private var dismiss
    /// Nil: create.
    var group: GroupRow?
    @State private var name = ""
    @State private var error: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text(group == nil ? "New group" : "Rename group").font(.sectionTitle)
            TextField("Name (Production, Staging, …)", text: $name)
                .textFieldStyle(.roundedBorder)
                .accessibilityIdentifier("group.name")
                .onSubmit(save)
            if let error {
                Text(error).font(.secondary).foregroundStyle(Tone.critical.text)
            }
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                    .accessibilityIdentifier("group.cancel")
                Button(group == nil ? "Create" : "Rename", action: save)
                    .buttonStyle(.fleetPrimary)
                    .disabled(name.trimmingCharacters(in: .whitespaces).isEmpty)
                    .keyboardShortcut(.defaultAction)
                    .accessibilityIdentifier("group.save")
            }
        }
        .padding(24)
        .frame(width: 380)
        .onAppear { name = group?.name ?? "" }
    }

    private func save() {
        guard !name.trimmingCharacters(in: .whitespaces).isEmpty else { return }
        do {
            if let group {
                try core.renameGroup(group.id, name)
            } else {
                try core.addGroup(name)
            }
            dismiss()
        } catch { self.error = error.fleetMessage }
    }
}

/// Group and tags of a server that is already in the fleet.
struct EditServerSheet: View {
    @Environment(CoreBridge.self) private var core
    @Environment(\.dismiss) private var dismiss
    let server: ServerRow
    @State private var groupId: String?
    @State private var tags = ""
    @State private var error: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Edit \(server.name)").font(.sectionTitle)
            Picker("Group", selection: $groupId) {
                Text("None").tag(String?.none)
                ForEach(core.groups, id: \.id) { Text($0.name).tag(Optional($0.id)) }
            }
            .accessibilityIdentifier("editServer.group")
            TextField("Tags (comma separated: web, eu)", text: $tags)
                .textFieldStyle(.roundedBorder)
                .accessibilityIdentifier("editServer.tags")
            Text("Tags use lowercase letters, digits and dashes.")
                .font(.secondary).foregroundStyle(Color.textMuted)
            if let error {
                Text(error).font(.secondary).foregroundStyle(Tone.critical.text)
            }
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button("Save", action: save)
                    .buttonStyle(.fleetPrimary)
                    .keyboardShortcut(.defaultAction)
                    .accessibilityIdentifier("editServer.save")
            }
        }
        .padding(24)
        .frame(width: 420)
        .onAppear {
            groupId = server.groupId
            tags = server.tags.joined(separator: ", ")
        }
    }

    private func save() {
        let list = tags.split(whereSeparator: { $0 == "," || $0.isWhitespace })
            .map { String($0).lowercased() }
        do {
            try core.setPlacement(server.id, groupId: groupId, tags: list)
            dismiss()
        } catch { self.error = error.fleetMessage }
    }
}
