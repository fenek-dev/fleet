import XCTest

/// Exploratory/regression tests for the operator's day-to-day screens
/// (onboarding, add server, overview, services, logs, packages, users,
/// cron, files, terminal, docker, alerts, timeline, search, vulns,
/// palette, sudo, offline) against two real pool servers.
///
/// One fixed data dir (`/tmp/fl-ops`) shared by every test: `test01`
/// creates the fleet, `test02`/`test03` add the servers, later tests
/// relaunch on the same dir and unlock. Run them one at a time, in order.
///
/// Host-side control files (the runner is sandboxed, it only reads them):
/// - `/tmp/fl-ops-ctl/pool.json`: `{"a": <port debian12>, "b": <port ubuntu24>}`
///   (written once the app's `ssh_pubkey` is authorized on both servers).
/// - `/tmp/fl-ops-ctl/<flag>`: flags a helper script touches while a test
///   waits (`waitFlag`), e.g. after `docker stop`.
/// The agent artifact comes from `FLEET_UI_ENV_FLEET_TEST_AGENT_ARTIFACT`.
final class OpsTests: FleetUITestCase {
    static let dir = "/tmp/fl-ops"
    static let ctl = "/tmp/fl-ops-ctl"

    override func setUpWithError() throws {
        extraEnvironment["FLEET_DATA_DIR"] = Self.dir
        try super.setUpWithError()
    }

    override func tearDownWithError() throws {
        if let app, app.state != .notRunning {
            wsnap("teardown")
            app.terminate()
        }
        try super.tearDownWithError()
    }

    // MARK: helpers

    /// Accessibility tree + screenshot, both kept in the result bundle.
    func dump(_ name: String) {
        wsnap(name)
        let a = XCTAttachment(string: app.debugDescription)
        a.name = "tree-\(name)"
        a.lifetime = .keepAlways
        add(a)
    }

    /// Screenshot of the app's front window only (app.screenshot() grabs
    /// the whole desktop, including unrelated windows).
    func wsnap(_ name: String) {
        let w = app.windows.firstMatch
        let shot = w.exists ? w.screenshot() : app.screenshot()
        let a = XCTAttachment(screenshot: shot)
        a.name = name
        a.lifetime = .keepAlways
        add(a)
    }

    func note(_ name: String, _ text: String) {
        let a = XCTAttachment(string: text)
        a.name = "note-\(name)"
        a.lifetime = .keepAlways
        add(a)
    }

    func ports() throws -> (a: Int, b: Int) {
        let deadline = Date().addingTimeInterval(600)
        while Date() < deadline {
            if let d = FileManager.default.contents(atPath: "\(Self.ctl)/pool.json"),
               let o = try? JSONSerialization.jsonObject(with: d) as? [String: Int],
               let a = o["a"], let b = o["b"] {
                return (a, b)
            }
            Thread.sleep(forTimeInterval: 1)
        }
        throw XCTSkip("no \(Self.ctl)/pool.json")
    }

    @discardableResult
    func waitFlag(_ flag: String, timeout: TimeInterval = 300) -> Bool {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if FileManager.default.fileExists(atPath: "\(Self.ctl)/\(flag)") { return true }
            Thread.sleep(forTimeInterval: 1)
        }
        return false
    }

    /// Relaunch on the existing dir: unlock if the app starts locked.
    func unlockIfNeeded() {
        wait("sidebar.fleet", timeout: 30)
        if exists("locked.unlock", timeout: 3) {
            tap("locked.unlock")
        } else if exists("sidebar.lock", timeout: 1),
                  (element("sidebar.lockState").label + ((element("sidebar.lockState").value as? String) ?? ""))
                    .localizedCaseInsensitiveContains("locked") {
            tap("sidebar.lock")
        }
        Thread.sleep(forTimeInterval: 2)
    }

    func button(_ label: String) -> XCUIElement {
        app.buttons[label].firstMatch
    }

    func clickButton(_ label: String, timeout: TimeInterval = 10) -> Bool {
        let b = button(label)
        guard b.waitForExistence(timeout: timeout) else { return false }
        b.click()
        return true
    }

    /// Picks `item` in the pop-up button with identifier `id`.
    func pick(_ id: String, _ item: String) {
        tap(id)
        let mi = app.menuItems[item].firstMatch
        XCTAssertTrue(mi.waitForExistence(timeout: 5), "menu item \(item)")
        mi.click()
    }

    func openServer(_ name: String, tab: String) {
        sidebar("server.\(name)")
        if exists("serverTab.\(tab)", timeout: 5) {
            serverTab(tab)
        } else {
            tap("serverTab.more")
            let mi = app.menuItems.matching(NSPredicate(format: "identifier == %@ OR label ==[c] %@",
                                                        "serverTab.\(tab)", tab)).firstMatch
            if mi.waitForExistence(timeout: 5) { mi.click() }
        }
        Thread.sleep(forTimeInterval: 2)
    }

    /// Adds a server through the sheet; stops after trust if `install` is false.
    func addServer(_ name: String, port: Int, security: String? = nil, install: Bool = true,
                   shots: String) {
        tap("sidebar.fleet")
        if exists("fleet.addServer", timeout: 5) { tap("fleet.addServer") } else { tap("fleet.empty.add") }
        replace("addServer.name", with: name)
        replace("addServer.host", with: "127.0.0.1")
        replace("addServer.port", with: String(port))
        replace("addServer.user", with: "ops")
        dump("\(shots)-details")
        tap("addServer.addConnect")
        trustAndInstall(security: security, install: install, shots: shots)
    }

    /// From the host-key step of the sheet: trust, pick artifact, install.
    func trustAndInstall(security: String?, install: Bool, shots: String) {
        wait("addServer.fingerprint", timeout: 60)
        dump("\(shots)-hostkey")
        tap("addServer.trust")
        wait("addServer.chooseArtifact")
        tap("addServer.chooseArtifact")
        if let security { pick("addServer.security", security) }
        dump("\(shots)-install")
        guard install else { return }
        tap("addServer.install")
        // Progress: sample the step list while it runs.
        let deadline = Date().addingTimeInterval(300)
        var i = 0
        while Date() < deadline {
            if exists("addServer.done", timeout: 1) || exists("addServer.retry", timeout: 1) { break }
            if i % 5 == 0 { wsnap("\(shots)-progress-\(i)") }
            i += 1
        }
        dump("\(shots)-end")
    }

    // MARK: tests

    /// Onboarding (create fleet) and empty fleet state.
    func test01Onboard() throws {
        wait("onboarding.create", timeout: 30)
        dump("onboarding-start")
        createFleet(name: "Ops fleet")
        Thread.sleep(forTimeInterval: 2)
        dump("fleet-empty")
    }

    /// Host key reject, then add A (debian12) Managed via the artifact in
    /// FLEET_TEST_AGENT_ARTIFACT (.deb).
    func test02AddServerA() throws {
        unlockIfNeeded()
        let p = try ports()
        // Reject first.
        tap("sidebar.fleet")
        if exists("fleet.addServer", timeout: 5) { tap("fleet.addServer") } else { tap("fleet.empty.add") }
        replace("addServer.name", with: "deb-a")
        replace("addServer.host", with: "127.0.0.1")
        replace("addServer.port", with: String(p.a))
        replace("addServer.user", with: "ops")
        tap("addServer.addConnect")
        wait("addServer.fingerprint", timeout: 60)
        note("fingerprint-a", element("addServer.fingerprint").label + " | " + ((element("addServer.fingerprint").value as? String) ?? ""))
        tap("addServer.reject")
        Thread.sleep(forTimeInterval: 3)
        dump("after-reject")
        if exists("sidebar.server.deb-a", timeout: 3) {
            sidebar("server.deb-a")
            Thread.sleep(forTimeInterval: 3)
            dump("rejected-server-detail")
        }
    }

    /// Install the agent on the rejected deb-a from its detail page
    /// (.deb, Managed).
    func test03InstallA() throws {
        unlockIfNeeded()
        sidebar("server.deb-a")
        tap("server.installAgentPrimary")
        Thread.sleep(forTimeInterval: 2)
        dump("installA-open")
        trustAndInstall(security: nil, install: true, shots: "installA")
        if exists("addServer.done", timeout: 2) {
            tap("addServer.done")
            Thread.sleep(forTimeInterval: 5)
            dump("installA-after")
        }
    }

    /// Install B from its detail page with the .deb, Agent only.
    func test05InstallB() throws {
        unlockIfNeeded()
        sidebar("server.ubu-b")
        tap("server.installAgentPrimary")
        trustOrSkip()
        tap("addServer.chooseArtifact")
        pick("addServer.security", "Agent only (don't change security)")
        dump("installB-install")
        tap("addServer.install")
        let deadline = Date().addingTimeInterval(300)
        while Date() < deadline {
            if exists("addServer.done", timeout: 1) || exists("addServer.retry", timeout: 1) { break }
        }
        dump("installB-end")
    }

    /// Host key step may be skipped when the key is already pinned.
    func trustOrSkip() {
        if exists("addServer.trust", timeout: 30) { tap("addServer.trust") }
        wait("addServer.chooseArtifact")
    }

    /// Answers a confirmation dialog/sheet by its button label.
    @discardableResult
    func confirm(_ label: String, timeout: TimeInterval = 5) -> Bool {
        for q in [app.sheets.buttons, app.dialogs.buttons] {
            let b = q[label].firstMatch
            if b.waitForExistence(timeout: timeout) { b.click(); return true }
        }
        note("confirm-missing-\(label)", app.debugDescription)
        return false
    }

    /// Overview ranges, fleet table, services actions, journal query/follow.
    func test06OverviewServicesLogs() throws {
        unlockIfNeeded()
        sidebar("fleet")
        Thread.sleep(forTimeInterval: 5)
        dump("fleet-table")
        sidebar("server.deb-a")
        for r in ["1h", "24h", "7d"] {
            let id = "overview.range.\(r)"
            if exists(id, timeout: 3) { tap(id) } else {
                let b = app.buttons.matching(NSPredicate(format: "identifier BEGINSWITH 'overview.range'")).allElementsBoundByIndex
                note("ranges", b.map { $0.identifier }.joined(separator: ","))
                break
            }
            Thread.sleep(forTimeInterval: 4)
            dump("overview-\(r)")
        }
        app.scrollViews.firstMatch.scroll(byDeltaX: 0, deltaY: -800)
        Thread.sleep(forTimeInterval: 1)
        dump("overview-scrolled")

        // Services.
        openServer("deb-a", tab: "services")
        let f = app.textFields["Filter"].firstMatch
        if f.waitForExistence(timeout: 10) { f.click(); f.typeText("nginx") }
        Thread.sleep(forTimeInterval: 2)
        let row = app.staticTexts["nginx.service"].firstMatch
        XCTAssertTrue(row.waitForExistence(timeout: 20), "nginx.service row")
        row.click()
        Thread.sleep(forTimeInterval: 3)
        dump("svc-selected")
        for a in ["Stop", "Start", "Restart"] {
            let b = app.buttons[a].firstMatch
            guard b.waitForExistence(timeout: 5) else { note("svc-no-\(a)", ""); continue }
            b.click()
            Thread.sleep(forTimeInterval: 1)
            dump("svc-confirm-\(a)")
            confirm(a)
            Thread.sleep(forTimeInterval: 6)
            dump("svc-after-\(a)")
        }
        row.rightClick()
        let dis = app.menuItems["Disable"].firstMatch
        if dis.waitForExistence(timeout: 5) {
            dis.click()
            confirm("Disable")
            Thread.sleep(forTimeInterval: 6)
            dump("svc-after-Disable")
            row.rightClick()
            let en = app.menuItems["Enable"].firstMatch
            if en.waitForExistence(timeout: 5) { en.click(); confirm("Enable"); Thread.sleep(forTimeInterval: 6) }
            dump("svc-after-Enable")
        } else {
            note("svc-no-context-menu", app.debugDescription)
            app.typeKey(.escape, modifierFlags: [])
        }

        // Logs: query then follow.
        openServer("deb-a", tab: "logs")
        let contains = app.textFields["Contains"].firstMatch
        if contains.waitForExistence(timeout: 10) { contains.click(); contains.typeText("opsmark") }
        if clickButton("Search") { Thread.sleep(forTimeInterval: 5) }
        dump("logs-query")
        let live = app.switches["Live"].firstMatch
        if live.waitForExistence(timeout: 5) { live.click() } else if app.checkBoxes["Live"].exists { app.checkBoxes["Live"].click() }
        Thread.sleep(forTimeInterval: 20)
        dump("logs-live-20s")
        Thread.sleep(forTimeInterval: 15)
        dump("logs-live-35s")
    }

    /// Clicks the first non-Cancel button of the frontmost sheet/dialog.
    @discardableResult
    func confirmAny(_ shot: String, timeout: TimeInterval = 5) -> Bool {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            for q in [app.sheets, app.dialogs] where q.count > 0 {
                let s = q.element(boundBy: q.count - 1)
                wsnap("confirm-\(shot)")
                note("confirm-\(shot)", s.debugDescription)
                let bs = s.buttons.allElementsBoundByIndex.filter {
                    $0.isEnabled && !["Cancel", "Back to editing", "Close"].contains($0.label) && !$0.label.isEmpty
                }
                if let b = bs.first { b.click(); return true }
            }
            Thread.sleep(forTimeInterval: 0.5)
        }
        note("confirm-missing-\(shot)", "")
        return false
    }

    func field(_ placeholderOrLabel: String) -> XCUIElement {
        app.textFields.matching(NSPredicate(format: "label == %@ OR placeholderValue == %@ OR title == %@",
                                            placeholderOrLabel, placeholderOrLabel, placeholderOrLabel)).firstMatch
    }

    /// Packages (apt update, security-only upgrade), users (create, lock,
    /// delete), cron (add entry) on deb-a.
    func test07PackagesUsersCron() throws {
        unlockIfNeeded()
        openServer("deb-a", tab: "packages")
        Thread.sleep(forTimeInterval: 5)
        dump("pkg-list")
        if clickButton("apt update") { Thread.sleep(forTimeInterval: 40) }
        dump("pkg-after-update")
        let sec = button("Upgrade security")
        note("pkg-security-enabled", "\(sec.exists) \(sec.exists && sec.isEnabled)")
        if sec.exists && sec.isEnabled {
            sec.click()
            confirmAny("pkg-security")
            Thread.sleep(forTimeInterval: 90)
            dump("pkg-after-security")
        }

        openServer("deb-a", tab: "users")
        Thread.sleep(forTimeInterval: 4)
        dump("users")
        if clickButton("New user…") {
            let n = field("Login name")
            if n.waitForExistence(timeout: 5) { n.click(); n.typeText("opsuser1") }
            let g = field("Groups (comma-separated)")
            if g.exists { g.click(); g.typeText("users") }
            dump("users-new")
            if clickButton("Create…") { confirmAny("users-create") }
            Thread.sleep(forTimeInterval: 6)
            dump("users-after-create")
        }
        let u = app.staticTexts["opsuser1"].firstMatch
        if u.waitForExistence(timeout: 10) {
            u.click()
            Thread.sleep(forTimeInterval: 2)
            dump("users-selected")
            if clickButton("Lock", timeout: 3) { confirmAny("users-lock"); Thread.sleep(forTimeInterval: 5) }
            dump("users-after-lock")
            if clickButton("Delete…", timeout: 3) { confirmAny("users-delete"); Thread.sleep(forTimeInterval: 5) }
            dump("users-after-delete")
        }

        openServer("deb-a", tab: "cron")
        Thread.sleep(forTimeInterval: 4)
        dump("cron")
        let cu = field("User")
        if cu.waitForExistence(timeout: 5) { cu.click(); cu.typeKey("a", modifierFlags: .command); cu.typeText("ops") }
        if clickButton("Edit user crontab…") {
            Thread.sleep(forTimeInterval: 3)
            if clickButton("Add entry") {
                let s = app.sheets.textFields.matching(NSPredicate(format: "placeholderValue == %@ OR label == %@", "m h dom mon dow", "m h dom mon dow")).allElementsBoundByIndex.last
                s?.click(); s?.typeText("*/5 * * * *")
                let c = app.sheets.textFields.matching(NSPredicate(format: "placeholderValue == 'Command' OR label == 'Command'")).allElementsBoundByIndex.last
                c?.click(); c?.typeText("/usr/bin/true opscron")
            }
            dump("cron-editor")
            if clickButton("Save…") { confirmAny("cron-save") }
            Thread.sleep(forTimeInterval: 6)
            dump("cron-after-save")
        }
    }

    /// Files: browse /etc, edit /etc/motd with review, config history,
    /// upload from /tmp/fl-ops-up/upload.txt, download to /tmp/fl-ops-dl.
    func test08Files() throws {
        unlockIfNeeded()
        openServer("deb-a", tab: "files")
        Thread.sleep(forTimeInterval: 5)
        dump("files-home")
        // Upload into the home dir.
        if clickButton("Upload…") {
            Thread.sleep(forTimeInterval: 2)
            app.typeKey("g", modifierFlags: [.command, .shift])
            Thread.sleep(forTimeInterval: 1)
            app.typeText("/tmp/fl-ops-up/upload.txt\n")
            Thread.sleep(forTimeInterval: 1)
            app.typeKey(.return, modifierFlags: [])
            Thread.sleep(forTimeInterval: 6)
            dump("files-after-upload")
        }
        // Download it back.
        let up = app.staticTexts["upload.txt"].firstMatch
        if up.waitForExistence(timeout: 5) {
            up.rightClick()
            let d = app.menuItems["Download…"].firstMatch
            if d.waitForExistence(timeout: 3) {
                d.click()
                Thread.sleep(forTimeInterval: 2)
                app.typeKey("g", modifierFlags: [.command, .shift])
                Thread.sleep(forTimeInterval: 1)
                app.typeText("/tmp/fl-ops-dl\n")
                Thread.sleep(forTimeInterval: 1)
                app.typeKey(.return, modifierFlags: [])
                Thread.sleep(forTimeInterval: 5)
                dump("files-after-download")
            } else { app.typeKey(.escape, modifierFlags: []) }
        }
        // /etc/motd: edit with review.
        if clickButton("/", timeout: 3) {
            Thread.sleep(forTimeInterval: 3)
            let etc = app.staticTexts["etc"].firstMatch
            if etc.waitForExistence(timeout: 5) { etc.doubleClick(); Thread.sleep(forTimeInterval: 4) }
        }
        dump("files-etc")
        let motd = app.staticTexts["motd"].firstMatch
        if motd.waitForExistence(timeout: 8) {
            motd.click()
            Thread.sleep(forTimeInterval: 3)
            dump("files-motd-selected")
            if clickButton("Edit", timeout: 3) {
                Thread.sleep(forTimeInterval: 3)
                let ed = app.textViews.firstMatch
                if ed.waitForExistence(timeout: 5) {
                    ed.click()
                    ed.typeKey(.downArrow, modifierFlags: .command)
                    ed.typeText("\nops-edit-marker-5521\n")
                }
                if clickButton("Review changes…", timeout: 3) { Thread.sleep(forTimeInterval: 2); dump("files-review") }
                if clickButton("Save to server", timeout: 3) { confirmAny("files-save", timeout: 3) }
                Thread.sleep(forTimeInterval: 6)
                dump("files-after-save")
            }
            motd.click()
            Thread.sleep(forTimeInterval: 3)
            if exists("files.history", timeout: 3) {
                tap("files.history")
                Thread.sleep(forTimeInterval: 4)
                dump("files-history")
            }
        }
    }

    /// Terminal: tabs mixing servers, record, broadcast (confirm), close.
    func test09Terminal() throws {
        unlockIfNeeded()
        openServer("deb-a", tab: "terminal")
        tap("terminal.new")
        Thread.sleep(forTimeInterval: 5)
        openServer("ubu-b", tab: "terminal")
        tap("terminal.new")
        Thread.sleep(forTimeInterval: 5)
        let tabs = app.descendants(matching: .any).matching(identifier: "terminal.tab")
        note("terminal-tabs", "count=\(tabs.count) " + tabs.allElementsBoundByIndex.map { $0.label }.joined(separator: " | "))
        dump("terminal-two")
        app.typeText("echo single-$((6*7))\n")
        Thread.sleep(forTimeInterval: 2)
        dump("terminal-typed")
        tap("terminal.record")
        Thread.sleep(forTimeInterval: 2)
        dump("terminal-recording")
        tap("terminal.broadcast")
        Thread.sleep(forTimeInterval: 1)
        dump("terminal-broadcast-confirm")
        if exists("terminal.broadcastConfirm", timeout: 3) { tap("terminal.broadcastConfirm") } else { confirmAny("broadcast") }
        Thread.sleep(forTimeInterval: 1)
        app.typeText("echo bcast-ops-$((40+2)) > /tmp/bcast-ops.txt; hostname\n")
        Thread.sleep(forTimeInterval: 4)
        dump("terminal-broadcast")
        tap("terminal.broadcast")
        tap("terminal.record")
        Thread.sleep(forTimeInterval: 2)
        dump("terminal-end")
    }

    /// Docker: containers stop/start, logs, compose deploy.
    func test10Docker() throws {
        unlockIfNeeded()
        openServer("deb-a", tab: "docker")
        Thread.sleep(forTimeInterval: 5)
        dump("docker-containers")
        let row = app.staticTexts["web1"].firstMatch
        if row.waitForExistence(timeout: 10) {
            for a in ["Stop", "Start", "Restart"] {
                row.rightClick()
                let mi = app.menuItems[a].firstMatch
                if mi.waitForExistence(timeout: 3) { mi.click(); confirmAny("docker-\(a)") } else { app.typeKey(.escape, modifierFlags: []) }
                Thread.sleep(forTimeInterval: 8)
                dump("docker-after-\(a)")
            }
            row.rightClick()
            let lg = app.menuItems["Logs…"].firstMatch
            if lg.waitForExistence(timeout: 3) {
                lg.click(); Thread.sleep(forTimeInterval: 5); dump("docker-logs")
                _ = clickButton("Close", timeout: 3)
            } else { app.typeKey(.escape, modifierFlags: []) }
        }
        let seg = app.radioButtons["Compose"].firstMatch
        if seg.waitForExistence(timeout: 3) { seg.click() } else { _ = clickButton("Compose", timeout: 2) }
        Thread.sleep(forTimeInterval: 4)
        dump("docker-compose")
        if clickButton("Deploy project…", timeout: 3) {
            let n = field("Project (lowercase, lives in /srv/<project>/)")
            if n.waitForExistence(timeout: 5) { n.click(); n.typeText("opsdemo") }
            let ed = app.sheets.textViews.firstMatch
            if ed.waitForExistence(timeout: 5) {
                ed.click()
                ed.typeKey("a", modifierFlags: .command)
                ed.typeText("services:\n  app:\n    image: busybox\n    command: [\"sh\", \"-c\", \"while true; do echo compose-tick; sleep 5; done\"]\n")
            }
            Thread.sleep(forTimeInterval: 2)
            dump("docker-deploy-sheet")
            if clickButton("Deploy…", timeout: 3) { confirmAny("docker-deploy") }
            Thread.sleep(forTimeInterval: 30)
            dump("docker-after-deploy")
        }
    }

    /// Alerts, fleet timeline, fleet search, vulnerabilities, palette.
    func test11Intel() throws {
        unlockIfNeeded()
        sidebar("alerts")
        Thread.sleep(forTimeInterval: 3)
        dump("alerts")
        sidebar("timeline")
        Thread.sleep(forTimeInterval: 6)
        dump("timeline")
        sidebar("search")
        Thread.sleep(forTimeInterval: 2)
        let q = app.searchFields.firstMatch.exists ? app.searchFields.firstMatch : app.textFields.firstMatch
        q.click(); q.typeText("nginx\n")
        Thread.sleep(forTimeInterval: 15)
        dump("search-nginx")
        sidebar("vulnerabilities")
        Thread.sleep(forTimeInterval: 3)
        dump("vulns")
        if exists("vulns.scan", timeout: 3) { tap("vulns.scan"); Thread.sleep(forTimeInterval: 60); dump("vulns-after-scan") }
        app.typeKey("k", modifierFlags: .command)
        Thread.sleep(forTimeInterval: 1)
        dump("palette")
        if exists("palette.query", timeout: 3) {
            element("palette.query").typeText("restart")
            Thread.sleep(forTimeInterval: 1)
            dump("palette-restart")
            element("palette.query").typeKey("a", modifierFlags: .command)
            element("palette.query").typeText("ubu")
            Thread.sleep(forTimeInterval: 1)
            dump("palette-ubu")
            app.typeKey(.return, modifierFlags: [])
            Thread.sleep(forTimeInterval: 2)
            dump("palette-after-enter")
        }
    }

    /// Sudo password button (no provisioning → no password yet).
    func test12Sudo() throws {
        unlockIfNeeded()
        for s in ["deb-a", "ubu-b"] {
            sidebar("server.\(s)")
            Thread.sleep(forTimeInterval: 3)
            if exists("server.sudoPassword", timeout: 3) {
                tap("server.sudoPassword")
                Thread.sleep(forTimeInterval: 3)
                dump("sudo-\(s)")
                app.typeKey(.escape, modifierFlags: [])
            } else {
                dump("sudo-missing-\(s)")
            }
        }
        note("approvals", approvalsLog)
    }

    /// Offline: a helper stops deb-a's container (flag `stopped`), then
    /// starts it again (flag `started`).
    func test13Offline() throws {
        unlockIfNeeded()
        sidebar("fleet")
        dump("offline-before")
        XCTAssertTrue(waitFlag("stopped", timeout: 300), "no stopped flag")
        for i in 0..<8 {
            Thread.sleep(forTimeInterval: 15)
            if i % 2 == 1 { dump("offline-stopped-\(i)") }
        }
        sidebar("server.deb-a")
        Thread.sleep(forTimeInterval: 3)
        dump("offline-detail")
        serverTab("services")
        Thread.sleep(forTimeInterval: 5)
        dump("offline-services")
        sidebar("alerts")
        Thread.sleep(forTimeInterval: 2)
        dump("offline-alerts")
        sidebar("fleet")
        XCTAssertTrue(waitFlag("started", timeout: 300), "no started flag")
        for i in 0..<10 {
            Thread.sleep(forTimeInterval: 15)
            dump("offline-restarted-\(i)")
        }
        sidebar("server.deb-a")
        Thread.sleep(forTimeInterval: 3)
        dump("offline-detail-after")
        sidebar("timeline")
        Thread.sleep(forTimeInterval: 5)
        dump("offline-timeline")
    }

    /// Add B (ubuntu24) Agent only with the static binary.
    func test04AddServerB() throws {
        unlockIfNeeded()
        // A: after the host-side group fix (OPS-3), Reconnect.
        sidebar("server.deb-a")
        Thread.sleep(forTimeInterval: 2)
        dump("A-before-reconnect")
        if exists("server.reconnect", timeout: 3) { tap("server.reconnect") }
        Thread.sleep(forTimeInterval: 15)
        dump("A-after-reconnect")
        let p = try ports()
        addServer("ubu-b", port: p.b, security: "Agent only (don't change security)", shots: "addB")
        if exists("addServer.done", timeout: 2) {
            tap("addServer.done")
            Thread.sleep(forTimeInterval: 5)
            dump("addB-after")
        }
    }
}
