import SwiftUI

extension ContainerRow: Identifiable {}
extension ImageRow: Identifiable {}
extension VolumeRow: Identifiable { public var id: String { name } }
extension NetworkRow: Identifiable {}
extension ComposeProjectRow: Identifiable { public var id: String { project } }

/// Live `docker.stats`, keyed by container id.
@Observable
@MainActor
final class DockerStatsModel {
    private(set) var stats: [String: ContainerStatsRow] = [:]
    private(set) var status: StreamStatus?
    @ObservationIgnored private var handle: StreamHandle?

    var live: Bool { handle != nil }

    func start(api: FleetCore, serverId: String) {
        stop()
        handle = try? api.streamDockerStats(serverId: serverId, containers: [], sink: StatsRelay(model: self))
    }

    func stop() {
        handle?.cancel()
        handle = nil
        status = nil
    }

    fileprivate func set(_ rows: [ContainerStatsRow]) {
        for r in rows { stats[r.id] = r }
    }

    fileprivate func setStatus(_ s: StreamStatus) {
        status = s
        if case .ended = s { handle = nil }
    }
}

private final class StatsRelay: DockerStatsSink {
    private let model: DockerStatsModel
    init(model: DockerStatsModel) { self.model = model }
    func onStats(timeMs: UInt64, stats: [ContainerStatsRow]) {
        Task { @MainActor [model] in model.set(stats) }
    }
    func onStatus(status: StreamStatus) {
        Task { @MainActor [model] in model.setStatus(status) }
    }
}

/// `docker.logs` follow for one container (untrusted text, display only).
@Observable
@MainActor
final class DockerLogModel {
    struct Line: Identifiable {
        let id: Int
        let row: DockerLogLineRow
    }

    private(set) var lines: [Line] = []
    private(set) var status: StreamStatus?
    private(set) var error: String?
    @ObservationIgnored private var handle: StreamHandle?
    @ObservationIgnored private var next = 0
    static let cap = 5000

    func start(api: FleetCore, serverId: String, container: String) {
        stop()
        lines = []
        do {
            handle = try api.followDockerLogs(serverId: serverId, container: container, tail: 500,
                                              sink: LogRelay(model: self))
        } catch {
            self.error = error.fleetMessage
        }
    }

    func stop() {
        handle?.cancel()
        handle = nil
    }

    fileprivate func append(_ rows: [DockerLogLineRow]) {
        for r in rows {
            lines.append(Line(id: next, row: r))
            next += 1
        }
        if lines.count > Self.cap { lines.removeFirst(lines.count - Self.cap) }
    }

    fileprivate func setStatus(_ s: StreamStatus) { status = s }
}

private final class LogRelay: DockerLogSink {
    private let model: DockerLogModel
    init(model: DockerLogModel) { self.model = model }
    func onLines(lines: [DockerLogLineRow]) {
        Task { @MainActor [model] in model.append(lines) }
    }
    func onStatus(status: StreamStatus) {
        Task { @MainActor [model] in model.setStatus(status) }
    }
}

struct DockerLogsSheet: View {
    @Environment(CoreBridge.self) private var core
    @Environment(\.dismiss) private var dismiss
    let serverId: String
    let container: ContainerRow
    @State private var model = DockerLogModel()

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Text("Logs · \(container.name)").font(.system(size: 15, weight: .semibold))
                switch model.status {
                case .live?: StatusPill(label: "Following", tone: .ok)
                case .reconnecting?: StatusPill(label: "Reconnecting", tone: .warn)
                case .ended?: StatusPill(label: "Ended", tone: .neutral)
                case nil: EmptyView()
                }
                Spacer()
                Button("Close") { dismiss() }
            }
            if let e = model.error { Text(e).foregroundStyle(Tone.warn.text) }
            ScrollViewReader { proxy in
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 1) {
                        ForEach(model.lines) { l in
                            Text(l.row.text)
                                .font(.mono(11))
                                .foregroundStyle(l.row.stderr ? Tone.warn.text : Color.text)
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .id(l.id)
                        }
                    }
                    .textSelection(.enabled)
                }
                .onChange(of: model.lines.last?.id) { _, id in
                    if let id { proxy.scrollTo(id, anchor: .bottom) }
                }
            }
            .padding(8)
            .background(Color.track, in: RoundedRectangle(cornerRadius: 8))
        }
        .padding(20)
        .frame(minWidth: 760, minHeight: 480)
        .task {
            if let api = core.api { model.start(api: api, serverId: serverId, container: container.id) }
        }
        .onDisappear { model.stop() }
    }
}

struct ComposeDeploySheet: View {
    @Environment(CoreBridge.self) private var core
    @Environment(\.dismiss) private var dismiss
    let server: ServerRow
    var project = ""
    let done: () -> Void
    @State private var name = ""
    @State private var yaml = "services:\n  web:\n    image: nginx:1.27\n    ports:\n      - \"127.0.0.1:8080:80\"\n"
    @State private var pull = true
    @State private var check: ComposeCheckRow?
    @State private var busy = false
    @State private var error: String?
    @State private var pending: PendingAction?

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Deploy Compose project").font(.system(size: 15, weight: .semibold))
            HStack {
                TextField("Project (lowercase, lives in /srv/<project>/)", text: $name)
                    .textFieldStyle(.roundedBorder).frame(width: 320)
                Toggle("Pull images first", isOn: $pull)
            }
            TextEditor(text: $yaml)
                .font(.mono(12))
                .scrollContentBackground(.hidden)
                .padding(6)
                .background(Color.track, in: RoundedRectangle(cornerRadius: 8))
                .frame(minHeight: 280)
            if let e = error { Text(e).foregroundStyle(Tone.critical.text).font(.secondary) }
            if let c = check {
                ForEach(c.errors, id: \.self) { e in
                    Label(e, systemImage: "xmark.octagon").foregroundStyle(Tone.critical.text).font(.secondary)
                }
                if !c.findings.isEmpty {
                    Text("Needs Touch ID approval (root key):").font(.secondary).foregroundStyle(Tone.warn.text)
                    ForEach(c.findings, id: \.self) { f in
                        Text("• \(f)").font(.caption11).foregroundStyle(Tone.warn.text)
                    }
                }
                if c.ok && c.findings.isEmpty {
                    Label("Valid", systemImage: "checkmark.circle").foregroundStyle(Tone.ok.text).font(.secondary)
                }
            }
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }
                Button("Deploy…") { askDeploy() }
                    .buttonStyle(.borderedProminent).tint(.accent)
                    .disabled(busy || !(check?.ok ?? false))
            }
        }
        .padding(20)
        .frame(minWidth: 720, minHeight: 520)
        .onAppear { name = project; validate() }
        .onChange(of: yaml) { _, _ in validate() }
        .onChange(of: name) { _, _ in validate() }
        .confirmAction($pending)
    }

    private func validate() {
        do {
            check = try composeValidate(project: name, yaml: yaml)
            error = nil
        } catch {
            check = nil
            self.error = name.isEmpty ? nil : "Project name: lowercase letters, digits, - and _."
        }
    }

    private func askDeploy() {
        let (p, y, pl) = (name, yaml, pull)
        pending = PendingAction(title: "Deploy \(p) on \(server.name)?",
                                message: "Writes /srv/\(p)/compose.yaml and brings the project up.",
                                button: "Deploy", elevated: !(check?.findings.isEmpty ?? true)) {
            guard let api = core.api else { return }
            busy = true
            Task {
                defer { busy = false }
                do {
                    try await api.composeDeploy(serverId: server.id, project: p, yaml: y, pull: pl)
                    done()
                    dismiss()
                } catch {
                    self.error = error.fleetMessage
                }
            }
        }
    }
}

/// Docker (design §2.5): containers, images, volumes, networks, Compose.
struct DockerTab: View {
    enum Section: String, CaseIterable, Identifiable {
        case containers = "Containers", images = "Images", volumes = "Volumes"
        case networks = "Networks", compose = "Compose"
        var id: String { rawValue }
    }

    @Environment(CoreBridge.self) private var core
    let server: ServerRow
    @State private var section: Section = .containers
    @State private var containers: [ContainerRow] = []
    @State private var images: [ImageRow] = []
    @State private var volumes: [VolumeRow] = []
    @State private var networks: [NetworkRow] = []
    @State private var projects: [ComposeProjectRow] = []
    @State private var showAll = true
    @State private var pullRef = ""
    @State private var logsFor: ContainerRow?
    @State private var deploying: String?
    @State private var stats = DockerStatsModel()
    @State private var loading = false
    @State private var error: String?
    @State private var notice: String?
    @State private var pending: PendingAction?

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            TabHeader(title: "Docker", loading: loading, error: error, refresh: { Task { await load() } }) {
                Picker("", selection: $section) {
                    ForEach(Section.allCases) { Text($0.rawValue).tag($0) }
                }
                .pickerStyle(.segmented).labelsHidden().frame(width: 460)
            }
            if let notice { Text(notice).font(.secondary).foregroundStyle(Tone.ok.text) }
            switch section {
            case .containers: containersView
            case .images: imagesView
            case .volumes: volumesView
            case .networks: networksView
            case .compose: composeView
            }
        }
        .padding(24)
        .task(id: "\(server.id)/\(section.rawValue)") { await load() }
        .onDisappear { stats.stop() }
        .confirmAction($pending)
        .sheet(item: $logsFor) { c in DockerLogsSheet(serverId: server.id, container: c) }
        .sheet(isPresented: Binding(get: { deploying != nil }, set: { if !$0 { deploying = nil } })) {
            ComposeDeploySheet(server: server, project: deploying ?? "") { Task { await load() } }
        }
    }

    // MARK: containers

    private var containersView: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Toggle("Show stopped", isOn: $showAll).onChange(of: showAll) { _, _ in Task { await load() } }
                Toggle("Live stats", isOn: Binding(get: { stats.live }, set: { on in
                    if on, let api = core.api { stats.start(api: api, serverId: server.id) } else { stats.stop() }
                }))
                Spacer()
            }
            Table(containers) {
                TableColumn("Name") { c in Text(c.name).lineLimit(1) }
                TableColumn("Image") { c in Text(c.image).font(.mono(11)).lineLimit(1) }
                TableColumn("State") { c in StatusPill(label: c.state, tone: tone(c.state)) }.width(100)
                TableColumn("Status") { c in Text(c.status).lineLimit(1).foregroundStyle(Color.textSecondary) }
                TableColumn("Ports") { c in Text(c.ports.joined(separator: ", ")).font(.mono(11)).lineLimit(1) }
                TableColumn("CPU") { c in Text(stats.stats[c.id].map { String(format: "%.1f%%", $0.cpuPct) } ?? "–") }
                    .width(60)
                TableColumn("Memory") { c in Text(stats.stats[c.id].map { Format.bytes($0.memBytes) } ?? "–") }
                    .width(80)
                TableColumn("") { c in
                    Menu {
                        containerMenu(c)
                    } label: { Image(systemName: "ellipsis.circle") }
                    .menuStyle(.borderlessButton).frame(width: 30)
                }
                .width(40)
            }
            .contextMenu(forSelectionType: String.self) { ids in
                if let c = containers.first(where: { ids.first == $0.id }) { containerMenu(c) }
            }
            .tableCard()
        }
    }

    @ViewBuilder private func containerMenu(_ c: ContainerRow) -> some View {
        Button("Logs…") { logsFor = c }
        Divider()
        Button("Start") { ask(c, .start) }
        Button("Stop") { ask(c, .stop) }
        Button("Restart") { ask(c, .restart) }
        Divider()
        Button("Remove…") { ask(c, .remove) }
        Button("Force remove…") { ask(c, .forceRemove) }
    }

    private func ask(_ c: ContainerRow, _ a: DockerContainerAction) {
        let (verb, destructive): (String, Bool) = switch a {
        case .start: ("Start", false)
        case .stop: ("Stop", true)
        case .restart: ("Restart", false)
        case .remove: ("Remove", true)
        case .forceRemove: ("Force remove", true)
        }
        pending = PendingAction(title: "\(verb) \(c.name) on \(server.name)?",
                                message: a == .forceRemove ? "A running container is killed first." : "",
                                button: verb, destructive: destructive) {
            run { try await $0.dockerContainerAction(serverId: server.id, container: c.id, action: a) }
        }
    }

    // MARK: images, volumes, networks

    private var imagesView: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                TextField("Image to pull, e.g. nginx:1.27", text: $pullRef)
                    .textFieldStyle(.roundedBorder).frame(width: 300)
                Button("Pull") {
                    let r = pullRef
                    pending = PendingAction(title: "Pull \(r) on \(server.name)?", button: "Pull") {
                        run { try await $0.dockerImagePull(serverId: server.id, image: r) }
                    }
                }
                .disabled(pullRef.isEmpty)
                Spacer()
                Button("Prune…") {
                    pending = PendingAction(title: "Prune unused images on \(server.name)?",
                                            message: "Removes dangling images and every image no container uses.",
                                            button: "Prune", destructive: true) {
                        run { api in
                            let p = try await api.dockerImagesPrune(serverId: server.id, allUnused: true)
                            notice = "Removed \(p.removed) images, reclaimed \(Format.bytes(p.reclaimedBytes))."
                        }
                    }
                }
            }
            Table(images) {
                TableColumn("Tags") { i in Text(i.tags.isEmpty ? "<none>" : i.tags.joined(separator: ", ")).lineLimit(1) }
                TableColumn("ID") { i in Text(String(i.id.prefix(19))).font(.mono(11)) }.width(150)
                TableColumn("Size") { i in Text(Format.bytes(i.sizeBytes)) }.width(80)
                TableColumn("Created") { i in Text(fmtDate(i.createdMs)) }.width(140)
                TableColumn("In use") { i in StatusPill(label: i.inUse ? "in use" : "unused", tone: i.inUse ? .ok : .neutral) }
                    .width(90)
                TableColumn("") { i in
                    Button("Remove") {
                        guard let tag = i.tags.first else { return }
                        pending = PendingAction(title: "Remove image \(tag)?", button: "Remove", destructive: true) {
                            run { try await $0.dockerImageRemove(serverId: server.id, image: tag, force: false) }
                        }
                    }
                    .controlSize(.small).disabled(i.tags.isEmpty || i.inUse)
                }
                .width(80)
            }
            .tableCard()
        }
    }

    private var volumesView: some View {
        Table(volumes) {
            TableColumn("Name") { v in Text(v.name).lineLimit(1) }
            TableColumn("Driver") { v in Text(v.driver) }.width(80)
            TableColumn("Mountpoint") { v in Text(v.mountpoint).font(.mono(11)).lineLimit(1) }
            TableColumn("Size") { v in Text(v.sizeBytes.map(Format.bytes) ?? "–") }.width(80)
            TableColumn("In use") { v in StatusPill(label: v.inUse ? "in use" : "unused", tone: v.inUse ? .ok : .neutral) }
                .width(90)
            TableColumn("") { v in
                Button("Remove") {
                    pending = PendingAction(title: "Remove volume \(v.name)?",
                                            message: "Its data is deleted permanently.",
                                            button: "Remove", destructive: true) {
                        run { try await $0.dockerVolumeRemove(serverId: server.id, name: v.name) }
                    }
                }
                .controlSize(.small).disabled(v.inUse)
            }
            .width(80)
        }
        .tableCard()
    }

    private var networksView: some View {
        Table(networks) {
            TableColumn("Name") { n in Text(n.name) }
            TableColumn("Driver") { n in Text(n.driver) }.width(90)
            TableColumn("Subnets") { n in Text(n.subnets.joined(separator: ", ")).font(.mono(11)) }
            TableColumn("ID") { n in Text(String(n.id.prefix(12))).font(.mono(11)) }.width(110)
        }
        .tableCard()
    }

    // MARK: compose

    private var composeView: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                HStack {
                    Spacer()
                    Button("Deploy project…", systemImage: "plus") { deploying = "" }
                }
                if projects.isEmpty && !loading {
                    Text("No Compose projects under /srv.").foregroundStyle(Color.textMuted)
                }
                ForEach(projects) { p in
                    AdminSection(title: p.project) {
                        HStack(spacing: 6) {
                            Button("Edit & deploy…") { deploying = p.project }
                            Button("Pull") { askCompose(p, .pull) }
                            Button("Restart") { askCompose(p, .restart) }
                            Menu("Down") {
                                Button("Down") { askCompose(p, .down) }
                                Button("Down and remove volumes…") { askCompose(p, .downRemoveVolumes) }
                            }
                            .frame(width: 80)
                        }
                        .controlSize(.small)
                    } content: {
                        Text(p.path).font(.mono(11)).foregroundStyle(Color.textMuted)
                        ForEach(p.services, id: \.name) { s in
                            HStack {
                                Text(s.name).frame(width: 160, alignment: .leading)
                                StatusPill(label: s.state, tone: tone(s.state))
                                Text(s.image).font(.mono(11)).foregroundStyle(Color.textSecondary).lineLimit(1)
                                Spacer()
                                if s.updateAvailable == true { StatusPill(label: "update available", tone: .info) }
                            }
                            .font(.secondary)
                        }
                    }
                }
            }
        }
    }

    private func askCompose(_ p: ComposeProjectRow, _ a: ComposeAction) {
        let (verb, msg, destructive): (String, String, Bool) = switch a {
        case .pull: ("Pull", "Pulls newer images; running containers are not replaced.", false)
        case .restart: ("Restart", "Restarts every service of the project.", false)
        case .down: ("Down", "Stops and removes the project's containers and networks.", true)
        case .downRemoveVolumes: ("Down and remove volumes", "Also deletes the project's named volumes and their data.", true)
        }
        pending = PendingAction(title: "\(verb) \(p.project) on \(server.name)?", message: msg,
                                button: verb, destructive: destructive) {
            run { try await $0.composeAction(serverId: server.id, project: p.project, action: a) }
        }
    }

    // MARK: plumbing

    private func tone(_ state: String) -> Tone {
        switch state {
        case "running": .ok
        case "restarting", "paused": .warn
        case "dead": .critical
        default: .neutral
        }
    }

    private func run(_ op: @escaping (FleetCore) async throws -> Void) {
        guard let api = core.api else { return }
        Task {
            do {
                notice = nil
                try await op(api)
                error = nil
            } catch {
                self.error = error.fleetMessage
            }
            await load()
        }
    }

    private func load() async {
        guard let api = core.api else { return }
        loading = true
        defer { loading = false }
        do {
            switch section {
            case .containers: containers = try await api.dockerContainers(serverId: server.id, all: showAll)
            case .images: images = try await api.dockerImages(serverId: server.id)
            case .volumes: volumes = try await api.dockerVolumes(serverId: server.id)
            case .networks: networks = try await api.dockerNetworks(serverId: server.id)
            case .compose: projects = try await api.composeList(serverId: server.id)
            }
            error = nil
        } catch {
            self.error = error.fleetMessage
        }
    }
}
