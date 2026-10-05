import SwiftUI

struct CronDraft: Identifiable, Equatable {
    let id = UUID()
    var schedule = "0 3 * * *"
    var command = ""
    var comment = ""
}

/// Editor for one user's crontab (`cron.set` at the version listed).
struct CrontabEditor: View {
    @Environment(CoreBridge.self) private var core
    @Environment(\.dismiss) private var dismiss
    let server: ServerRow
    let tab: CronTabRow
    let done: () -> Void
    @State private var drafts: [CronDraft] = []
    @State private var error: String?
    @State private var busy = false
    @State private var pending: PendingAction?

    private var user: String { tab.user ?? "" }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Crontab · \(user)").font(.system(size: 15, weight: .semibold))
            Text("Schedule: five fields or @daily/@hourly/@reboot…. The command runs through the user's shell.")
                .font(.caption11).foregroundStyle(Color.textMuted)
            List {
                ForEach($drafts) { $d in
                    HStack {
                        TextField("m h dom mon dow", text: $d.schedule).frame(width: 140)
                        TextField("Command", text: $d.command)
                        TextField("Comment", text: $d.comment).frame(width: 160)
                        Button { drafts.removeAll { $0.id == d.id } } label: { Image(systemName: "minus.circle") }
                            .buttonStyle(.plain)
                    }
                    .font(.mono(11))
                    .textFieldStyle(.roundedBorder)
                }
                .onMove { drafts.move(fromOffsets: $0, toOffset: $1) }
            }
            .frame(minHeight: 220)
            Button("Add entry", systemImage: "plus") { drafts.append(CronDraft()) }
            if let error { Text(error).foregroundStyle(Tone.critical.text).font(.secondary) }
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }.buttonStyle(.fleetSecondary)
                Button("Save…") { askSave() }.buttonStyle(.fleetPrimary).disabled(busy)
            }
        }
        .padding(20)
        .frame(minWidth: 760, minHeight: 420)
        .onAppear {
            drafts = tab.entries.map { CronDraft(schedule: $0.schedule, command: $0.command, comment: $0.comment ?? "") }
        }
        .confirmAction($pending)
    }

    private func askSave() {
        let entries = drafts.map { CronEntryArgs(schedule: $0.schedule, command: $0.command, comment: $0.comment) }
        pending = PendingAction(
            title: "Replace \(user)'s crontab on \(server.name)?",
            message: "\(entries.count) entries. Commands run as \(user).",
            button: "Save",
            elevated: user == "root") {
                guard let api = core.api else { return }
                busy = true
                Task {
                    defer { busy = false }
                    do {
                        try await api.cronSet(serverId: server.id, userName: user, entries: entries,
                                              expectedVersion: tab.version)
                        done()
                        dismiss()
                    } catch {
                        self.error = error.fleetMessage
                    }
                }
            }
    }
}

/// Cron jobs and systemd timers (design §2.5).
struct CronTab: View {
    @Environment(CoreBridge.self) private var core
    let server: ServerRow
    @State private var tabs: [CronTabRow] = []
    @State private var timers: [TimerRow] = []
    @State private var openUser = ""
    @State private var editing: CronTabRow?
    @State private var loading = false
    @State private var error: String?

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                TabHeader(title: "Cron", loading: loading, error: error, refresh: { Task { await load() } }) {
                    TextField("User", text: $openUser).frame(width: 120).focusEffectDisabled(false)
                    Button("Edit user crontab…") { Task { await open(openUser) } }.disabled(openUser.isEmpty)
                }
                ForEach(Indexed.wrap(tabs)) { t in tabCard(t.value) }
                if tabs.isEmpty && !loading { Text("No crontabs.").foregroundStyle(Color.textMuted) }
                AdminSection(title: "systemd timers") {
                    Table(Indexed.wrap(timers)) {
                        TableColumn("Timer") { t in Text(t.value.unit).lineLimit(1) }
                        TableColumn("Activates") { t in Text(t.value.activates).lineLimit(1) }
                        TableColumn("Schedule") { t in Text(t.value.schedule).font(.mono(11)).lineLimit(1) }
                        TableColumn("Next") { t in Text(fmtDate(t.value.nextMs)) }.width(150)
                        TableColumn("Last") { t in Text(fmtDate(t.value.lastMs)) }.width(150)
                    }
                    // Sized to the rows (header + ~28 pt each) so no empty striped area shows below them.
                    .frame(height: timers.isEmpty ? 120 : CGFloat(timers.count) * 28 + 36)
                    .scrollContentBackground(.hidden)
                    .alternatingRowBackgrounds(.disabled)
                    .tableEmptyState(timers.isEmpty && !loading, "No systemd timers", systemImage: "timer")
                }
            }
            .padding(24)
        }
        .task(id: server.id) { await load() }
        .sheet(item: Binding(get: { editing.map { Indexed(id: 0, value: $0) } },
                             set: { editing = $0?.value })) { t in
            CrontabEditor(server: server, tab: t.value) { Task { await load() } }
        }
    }

    private func tabCard(_ t: CronTabRow) -> some View {
        AdminSection(title: t.user.map { "User \($0)" } ?? t.source) {
            if t.user != nil {
                Button("Edit…") { editing = t }.buttonStyle(.fleetSecondary)
            } else {
                Text("read-only").font(.caption11).foregroundStyle(Color.textMuted)
            }
        } content: {
            if t.entries.isEmpty {
                Text("No entries").font(.secondary).foregroundStyle(Color.textMuted)
            }
            // Blank entries would render as empty rows; comments only show when non-empty.
            ForEach(Indexed.wrap(t.entries.filter { !$0.schedule.isEmpty || !$0.command.isEmpty })) { e in
                HStack(alignment: .firstTextBaseline) {
                    Text(e.value.schedule).font(.mono(11)).frame(width: 140, alignment: .leading)
                    Text(e.value.command).font(.mono(11)).lineLimit(2).textSelection(.enabled)
                    Spacer()
                    if let c = e.value.comment, !c.isEmpty { Text(c).font(.caption11).foregroundStyle(Color.textMuted) }
                }
            }
        }
    }

    private func open(_ user: String) async {
        guard let api = core.api else { return }
        do {
            let t = try await api.cronList(serverId: server.id, userName: user)
            editing = t.first ?? CronTabRow(user: user, source: "", version: 0, entries: [])
        } catch {
            self.error = error.fleetMessage
        }
    }

    private func load() async {
        guard let api = core.api else { return }
        loading = true
        defer { loading = false }
        do {
            tabs = try await api.cronList(serverId: server.id, userName: nil)
            timers = try await api.timersList(serverId: server.id)
            error = nil
        } catch {
            self.error = error.fleetMessage
        }
    }
}
