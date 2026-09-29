import XCTest

/// Fleet-area exploratory tests (overview, bulk run, runbooks, agent
/// releases, devices/recovery, Settings, palette) against 3 pool servers.
///
/// The tests share one data dir (`/tmp/fl-flt1`) and run in name order:
/// `test01Setup` onboards and adds the servers, later tests relaunch the
/// same instance. A watcher (scratch `fleet/watch.sh`) waits for
/// `<dir>/ssh_pubkey`, starts 3 pool servers authorizing it and writes
/// `<dir>/ports` (`p1,p2,p3`). Runner env (TEST_RUNNER_ prefix for
/// xcodebuild): `FLEET_FLT=1`. The agent binary is `/tmp/fl-flt-agent`.
/// Release builds for `test05Releases`: `/tmp/fl-flt-rel/good` (bumped
/// version) and `/tmp/fl-flt-rel/bad` (can't start), with their BLAKE3 in
/// `<file>.b3`.
final class FleetAreaTests: FleetUITestCase {
    static let dir = "/tmp/fl-flt1"
    static let dirB = "/tmp/fl-flt2"
    static let names = ["flt-1", "flt-2", "flt-3"]

    /// Survives between test methods (the runner's own container).
    static var wordsFile: URL {
        URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("fl-flt-words.txt")
    }

    override func setUpWithError() throws {
        guard ProcessInfo.processInfo.environment["FLEET_FLT"] == "1" else {
            throw XCTSkip("needs pool servers; see the class comment")
        }
        extraEnvironment["FLEET_DATA_DIR"] = Self.dir
        extraEnvironment["FLEET_TEST_AGENT_ARTIFACT"] = "/tmp/fl-flt-agent"
        try super.setUpWithError()
    }

    // MARK: helpers

    func file(_ name: String, in dir: String = FleetAreaTests.dir,
              timeout: TimeInterval = 20) -> String? {
        let url = URL(fileURLWithPath: dir).appendingPathComponent(name)
        let end = Date().addingTimeInterval(timeout)
        while Date() < end {
            if let s = try? String(contentsOf: url, encoding: .utf8), !s.isEmpty {
                return s.trimmingCharacters(in: .whitespacesAndNewlines)
            }
            Thread.sleep(forTimeInterval: 0.5)
        }
        return nil
    }

    var log: String { file("approvals.log", timeout: 1) ?? "" }

    func count(_ needle: String, in s: String) -> Int {
        s.components(separatedBy: needle).count - 1
    }

    func waitGone(_ id: String, timeout: TimeInterval = 10) -> Bool {
        let e = element(id)
        let end = Date().addingTimeInterval(timeout)
        while e.exists && Date() < end { Thread.sleep(forTimeInterval: 0.3) }
        return !e.exists
    }

    func unlock() {
        if exists("locked.unlock", timeout: 5) {
            tap("locked.unlock")
            _ = waitGone("locked.banner")
        }
    }

    func note(_ s: String) {
        let a = XCTAttachment(string: s)
        a.name = "note"
        a.lifetime = .keepAlways
        add(a)
        print("FLT-NOTE: \(s)")
    }

    /// All static texts' labels/values under the window (for evidence).
    func dumpTexts(_ tag: String) {
        let t = app.staticTexts.allElementsBoundByIndex.prefix(250).map {
            ($0.value as? String).flatMap { $0.isEmpty ? nil : $0 } ?? $0.label
        }.filter { !$0.isEmpty }
        note("\(tag): " + t.joined(separator: " | "))
    }

    /// Onboarding with the recovery words kept for the drill.
    func createFleetKeepingWords(name: String) -> [String] {
        tap("onboarding.create", timeout: 30)
        type("onboarding.fleetName", name)
        tap("onboarding.continue")
        wait("onboarding.word.1")
        var words: [Int: String] = [:]
        for i in 1...24 {
            let e = element("onboarding.word.\(i)")
            words[i] = (e.value as? String) ?? e.label
        }
        snap("onboarding-words")
        tap("onboarding.wroteDown")
        var i = 0
        while exists("onboarding.verify.\(i)", timeout: 5) {
            let field = element("onboarding.verify.\(i)")
            let title = field.label + " " + (field.placeholderValue ?? "")
            guard let n = title.split(whereSeparator: { !$0.isNumber })
                .compactMap({ Int($0) }).first, let w = words[n]
            else { XCTFail("can't read verify field \(i): \(title)"); return [] }
            field.click()
            field.typeText(w)
            i += 1
        }
        tap("onboarding.check")
        tap("onboarding.createFleet")
        tap("onboarding.openFleet", timeout: 180)
        wait("sidebar.fleet", timeout: 30)
        return (1...24).map { words[$0] ?? "" }
    }

    func addPoolServer(name: String, port: String, tags: String) {
        tap("fleet.addServer")
        replace("addServer.name", with: name)
        replace("addServer.host", with: "127.0.0.1")
        replace("addServer.port", with: port)
        replace("addServer.user", with: "ops")
        replace("addServer.tags", with: tags)
        tap("addServer.addConnect")
        tap("addServer.trust", timeout: 60)
        tap("addServer.chooseArtifact", timeout: 120)
        tap("addServer.install")
        let done = wait("addServer.done", timeout: 240)
        snap("add-\(name)-done")
        done.click()
    }

    // MARK: tests

    func test01Setup() throws {
        let words = createFleetKeepingWords(name: "Flt fleet")
        XCTAssertEqual(words.count, 24)
        try words.joined(separator: " ").write(to: Self.wordsFile, atomically: true, encoding: .utf8)
        note("recovery-words-saved \(Self.wordsFile.path)")
        wait("fleet.empty")
        snap("01-empty")
        guard let ports = file("ports", timeout: 300)?.split(separator: ",").map(String.init),
              ports.count == 3 else { return XCTFail("no ports file") }
        unlock()
        let tags = ["web, eu", "web, docker", "db"]
        for (i, p) in ports.enumerated() {
            addPoolServer(name: Self.names[i], port: p, tags: tags[i])
        }
        wait("fleet.table")
        wait("fleet.digest", timeout: 120)
        Thread.sleep(forTimeInterval: 15)
        snap("01-overview")
        dumpTexts("overview")
    }

    /// Picks `item` from a pop-up picker.
    func pick(_ id: String, _ item: String) {
        tap(id)
        let m = app.menuItems[item].firstMatch
        XCTAssertTrue(m.waitForExistence(timeout: 5), "menu item \(item) missing")
        m.click()
    }

    func segment(_ id: String, _ label: String) {
        let seg = wait(id)
        let b = seg.buttons[label].firstMatch
        if b.exists { b.click() } else { seg.radioButtons[label].firstMatch.click() }
    }

    /// Batch size stepper down to `n` from its default.
    func setBatch(_ n: Int) {
        let s = wait("bulk.concurrency")
        for _ in 0..<70 {
            let label = (s.label + " " + ((s.value as? String) ?? ""))
            if label.contains("batches of \(n)") && !label.contains("batches of \(n)0") { break }
            let dec = s.decrementArrows.firstMatch
            if dec.exists { dec.click() } else {
                app.steppers.firstMatch.decrementArrows.firstMatch.click()
            }
        }
        note("stepper: \(s.label) \(s.value ?? "")")
    }

    func openBulk() {
        sidebar("fleet")
        tap("fleet.runCommand")
        wait("bulk.run")
    }

    func runAndWait(_ tag: String, timeout: TimeInterval = 300) {
        tap("bulk.run")
        tap("bulk.confirmRun")
        wait("bulk.summary", timeout: timeout)
        snap("\(tag)-done")
        dumpTexts(tag)
    }

    func test02Overview() throws {
        unlock()
        wait("fleet.table", timeout: 30)
        wait("fleet.digest", timeout: 120)
        Thread.sleep(forTimeInterval: 30)
        snap("02-overview")
        dumpTexts("overview")
        for c in ["security", "reboot", "online", "alerts"] {
            note("card \(c): \(exists("fleet.card.\(c)", timeout: 1))")
        }
        note("subtitle: \(element("fleet.subtitle").label)")
        // Filter.
        let f = wait("fleet.filter")
        note("filter kind: \(f.elementType.rawValue) label=\(f.label)")
        f.click()
        if f.elementType == .textField || f.elementType == .searchField {
            f.typeText("flt-2")
            Thread.sleep(forTimeInterval: 1)
            snap("02-filter-text")
            dumpTexts("filter-text")
            f.typeKey("a", modifierFlags: .command)
            f.typeText(XCUIKeyboardKey.delete.rawValue)
        } else {
            snap("02-filter-open")
            dumpTexts("filter-open")
            app.typeKey(.escape, modifierFlags: [])
        }
        // Tags in the sidebar.
        for t in ["web", "docker", "db", "eu"] {
            if exists("sidebar.tag.\(t)", timeout: 2) {
                tap("sidebar.tag.\(t)")
                Thread.sleep(forTimeInterval: 1)
                snap("02-tag-\(t)")
                dumpTexts("tag-\(t)")
            } else { note("no sidebar.tag.\(t)") }
        }
        // Groups: none can be created from the UI; list what the sidebar has.
        let groups = app.descendants(matching: .any)
            .matching(NSPredicate(format: "identifier BEGINSWITH 'sidebar.group.'"))
            .allElementsBoundByIndex.map { $0.identifier }
        note("groups: \(groups)")
        sidebar("fleet")
        // Context menu on the first row.
        let table = wait("fleet.table")
        let row = table.tableRows.firstMatch
        if row.waitForExistence(timeout: 5) {
            row.rightClick()
            snap("02-row-menu")
            app.typeKey(.escape, modifierFlags: [])
        }
        // Digest line click-through.
        if exists("fleet.digest.timeline", timeout: 2) {
            tap("fleet.digest.timeline")
            Thread.sleep(forTimeInterval: 2)
            snap("02-digest-timeline")
        }
    }

    func test03BulkOperation() throws {
        unlock()
        let signsBefore = count("root-sign", in: log)
        openBulk()
        snap("03-form-default")
        dumpTexts("bulk-form")
        note("reboot toggle (pkg.upgrade default): \(exists("bulk.reboot", timeout: 1))")
        pick("bulk.operation", "agent.health")
        tap("bulk.targets.all")
        setBatch(1)
        tap("bulk.dryRun")
        wait("bulk.dryResult", timeout: 120)
        snap("03-dry")
        if exists("bulk.viewPlan", timeout: 3) {
            tap("bulk.viewPlan")
            snap("03-plan")
            dumpTexts("plan")
            tap("bulk.plan.close")
        } else { note("no View plan for agent.health dry run") }
        runAndWait("03-health")
        note("state: \(element("bulk.state").label) summary: \(element("bulk.summary").label)")

        // Save as runbook.
        tap("bulk.saveRunbook")
        let tf = app.dialogs.textFields.firstMatch.exists ? app.dialogs.textFields.firstMatch
            : app.sheets.textFields.firstMatch
        if tf.waitForExistence(timeout: 5) {
            tf.click(); tf.typeText("flt health")
            let save = app.buttons["Save"].firstMatch
            save.click()
            note("savedNote: \(exists("bulk.savedNote", timeout: 5)) \(element("bulk.savedNote").label)")
        } else { note("save-as-runbook alert has no text field"); snap("03-save-alert") }
        snap("03-saved")
        tap("bulk.close")

        // Failure stops the rollout: a unit that doesn't exist, canary on.
        openBulk()
        pick("bulk.operation", "unit.*")
        type("bulk.unit", "flt-nonexistent.service")
        tap("bulk.targets.all")
        runAndWait("03-fail")
        note("fail state: \(element("bulk.state").label) summary: \(element("bulk.summary").label)")
        tap("bulk.close")

        // Pause / resume / cancel: pkg.refresh one at a time, no canary.
        openBulk()
        pick("bulk.operation", "pkg.refresh")
        tap("bulk.targets.all")
        tap("bulk.canary")
        setBatch(1)
        tap("bulk.run")
        tap("bulk.confirmRun")
        tap("bulk.pause", timeout: 20)
        Thread.sleep(forTimeInterval: 1)
        snap("03-paused")
        note("after pause: state=\(element("bulk.state").label) pauseBtn=\(element("bulk.pause").label)")
        Thread.sleep(forTimeInterval: 20)
        dumpTexts("paused-20s")
        tap("bulk.pause")
        note("after resume: state=\(element("bulk.state").label)")
        Thread.sleep(forTimeInterval: 2)
        if exists("bulk.cancel", timeout: 2) { tap("bulk.cancel") }
        wait("bulk.summary", timeout: 120)
        snap("03-cancelled")
        dumpTexts("cancelled")
        tap("bulk.close")

        let signsAfter = count("root-sign", in: log)
        note("root-sign typed ops: \(signsBefore) -> \(signsAfter)")
    }

    func test04BulkShell() throws {
        unlock()
        let before = count("root-sign", in: log)
        openBulk()
        segment("bulk.runType", "Shell")
        let cmd = wait("bulk.shellCommand")
        cmd.click()
        cmd.typeText("uname -a")
        tap("bulk.targets.all")
        snap("04-shell-form")
        tap("bulk.dryRun")
        wait("bulk.dryResult", timeout: 60)
        snap("04-shell-dry")
        runAndWait("04-shell")
        let after = log
        note("root-sign shell: \(before) -> \(count("root-sign", in: after)); tail: \(after.suffix(600))")
        tap("bulk.close")
    }

    // MARK: agent releases

    /// NSOpenPanel: go to a path with ⌘⇧G.
    func openPanelChoose(_ path: String) {
        let panel = app.sheets.firstMatch.exists ? app.sheets.firstMatch : app.dialogs.firstMatch
        _ = panel.waitForExistence(timeout: 10)
        app.typeKey("g", modifierFlags: [.command, .shift])
        Thread.sleep(forTimeInterval: 1)
        app.typeText(path)
        Thread.sleep(forTimeInterval: 1)
        app.typeKey(.return, modifierFlags: [])
        Thread.sleep(forTimeInterval: 1.5)
        snap("open-panel-\((path as NSString).lastPathComponent)")
        app.typeKey(.return, modifierFlags: [])
        Thread.sleep(forTimeInterval: 2)
    }

    func importRelease(_ path: String, version: String, arch: String) {
        tap("releases.choose")
        openPanelChoose(path)
        Thread.sleep(forTimeInterval: 3)
        replace("releases.version", with: version)
        let arches = app.popUpButtons.matching(NSPredicate(format: "label CONTAINS 'Architecture' OR value CONTAINS 'x86_64'"))
        if arches.firstMatch.exists {
            arches.firstMatch.click()
            app.menuItems[arch == "aarch64" ? "aarch64 (arm64)" : "x86_64 (amd64)"].firstMatch.click()
        } else { note("arch picker not found") }
        let b3 = file("\((path as NSString).lastPathComponent).b3", in: (path as NSString).deletingLastPathComponent) ?? ""
        // Wrong hash first: sign stays disabled, mismatch shown.
        replace("releases.attested", with: String(repeating: "0", count: 64))
        Thread.sleep(forTimeInterval: 1)
        note("sign enabled with wrong hash: \(element("releases.sign").isEnabled)")
        snap("05-wrong-hash-\(version)")
        replace("releases.attested", with: b3)
        Thread.sleep(forTimeInterval: 1)
        note("sign enabled with right hash: \(element("releases.sign").isEnabled)")
        tap("releases.sign")
        Thread.sleep(forTimeInterval: 5)
        snap("05-signed-\(version)")
        dumpTexts("signed-\(version)")
    }

    func test05Releases() throws {
        unlock()
        openSettings()
        tap("settings.nav.releases")
        wait("settings.agentReleases")
        snap("05-releases-empty")
        let signs0 = count("root-sign", in: log)
        importRelease("/tmp/fl-flt-rel/good/fleet-agent", version: "0.1.1", arch: "aarch64")
        note("root-sign after import: \(signs0) -> \(count("root-sign", in: log)); tail: \(log.suffix(300))")
        let rollouts = app.buttons.matching(identifier: "releases.rollout")
        guard rollouts.firstMatch.waitForExistence(timeout: 10) else {
            return XCTFail("no signed release to roll out")
        }
        let signs1 = count("root-sign", in: log)
        rollouts.element(boundBy: rollouts.count - 1).click()
        Thread.sleep(forTimeInterval: 2)
        snap("05-rollout-clicked")
        dumpTexts("rollout-start")
        let end = Date().addingTimeInterval(400)
        while Date() < end, !app.staticTexts.matching(NSPredicate(format: "label CONTAINS 'updated,'")).firstMatch.exists {
            Thread.sleep(forTimeInterval: 5)
        }
        snap("05-rollout-done")
        dumpTexts("rollout-done")
        note("root-sign rollout: \(signs1) -> \(count("root-sign", in: log)); tail: \(log.suffix(400))")
    }

    func test06BrokenRelease() throws {
        unlock()
        openSettings()
        tap("settings.nav.releases")
        wait("settings.agentReleases")
        importRelease("/tmp/fl-flt-rel/bad/fleet-agent", version: "0.1.2", arch: "aarch64")
        let rollouts = app.buttons.matching(identifier: "releases.rollout")
        guard rollouts.firstMatch.waitForExistence(timeout: 10) else { return XCTFail("no release") }
        dumpTexts("releases-list")
        // Newest release: the list order is not stated, pick by row text.
        var clicked = false
        for i in 0..<rollouts.count {
            let b = rollouts.element(boundBy: i)
            let rowText = app.staticTexts.matching(NSPredicate(format: "label CONTAINS 'v0.1.2'")).firstMatch
            if rowText.exists, abs(rowText.frame.midY - b.frame.midY) < 30 { b.click(); clicked = true; break }
        }
        if !clicked { note("could not match v0.1.2 row; clicking last"); rollouts.element(boundBy: rollouts.count - 1).click() }
        let end = Date().addingTimeInterval(420)
        while Date() < end, !app.staticTexts.matching(NSPredicate(format: "label CONTAINS 'updated,'")).firstMatch.exists {
            Thread.sleep(forTimeInterval: 5)
        }
        snap("06-broken-done")
        dumpTexts("broken-done")
    }

    // MARK: settings, recovery, devices

    func test07SettingsRecovery() throws {
        unlock()
        openSettings()
        for s in ["devices", "recovery", "ai", "sync", "releases", "alertRules", "profiles",
                  "appearance", "general"] {
            tap("settings.nav.\(s)")
            Thread.sleep(forTimeInterval: 2)
            snap("07-settings-\(s)")
            dumpTexts("settings-\(s)")
        }
        // Recovery drill with the onboarding words.
        tap("settings.nav.recovery")
        let words = (try? String(contentsOf: Self.wordsFile, encoding: .utf8)) ?? ""
        note("have words: \(words.split(separator: " ").count)")
        type("recovery.words", words)
        tap("recovery.checkCode")
        Thread.sleep(forTimeInterval: 40)
        snap("07-drill")
        dumpTexts("drill")
        // Wrong code.
        var wrong = words.split(separator: " ").map(String.init)
        if wrong.count == 24 { wrong.swapAt(0, 1) }
        type("recovery.words", wrong.joined(separator: " "))
        tap("recovery.checkCode")
        Thread.sleep(forTimeInterval: 30)
        snap("07-drill-wrong")
        dumpTexts("drill-wrong")
        // Replace the code.
        let before = count("root-sign", in: log)
        tap("recovery.replaceCode")
        if exists("recovery.wroteDown", timeout: 120) {
            snap("07-new-code")
            tap("recovery.wroteDown")
        } else { note("no new words after replace") }
        dumpTexts("after-replace")
        note("root-sign replace: \(before) -> \(count("root-sign", in: log)); tail: \(log.suffix(300))")
        // Devices: roster card, this Mac can't revoke itself.
        tap("settings.nav.devices")
        Thread.sleep(forTimeInterval: 3)
        note("revoke buttons: \(app.buttons.matching(identifier: "devices.revoke").count)")
        snap("07-devices")
        tap("devices.recoveryDrill")
        note("drill link lands on recovery: \(exists("settings.recovery", timeout: 3))")
    }

    // MARK: palette

    func test08Palette() throws {
        unlock()
        app.typeKey("k", modifierFlags: .command)
        let q = wait("palette.query", timeout: 5)
        snap("08-palette")
        dumpTexts("palette")
        let items = app.descendants(matching: .any)
            .matching(NSPredicate(format: "identifier BEGINSWITH 'palette.item.'"))
            .allElementsBoundByIndex.map { $0.identifier }
        note("palette items: \(items)")
        q.typeText("flt-2")
        Thread.sleep(forTimeInterval: 1)
        snap("08-palette-server")
        dumpTexts("palette-server")
        q.typeKey("a", modifierFlags: .command)
        q.typeText("runbook")
        Thread.sleep(forTimeInterval: 1)
        dumpTexts("palette-runbook")
        q.typeKey("a", modifierFlags: .command)
        q.typeText("pkg.refresh")
        Thread.sleep(forTimeInterval: 1)
        snap("08-palette-op")
        dumpTexts("palette-op")
        app.typeKey(.return, modifierFlags: [])
        Thread.sleep(forTimeInterval: 2)
        snap("08-palette-enter")
        if exists("bulk.close", timeout: 3) { tap("bulk.close") } else { app.typeKey(.escape, modifierFlags: []) }
        // Runbooks screen: the one saved from bulk run.
        sidebar("runbooks")
        Thread.sleep(forTimeInterval: 2)
        snap("08-runbooks")
        dumpTexts("runbooks")
    }

    // MARK: two Macs

    func test09AddMac() throws {
        // Mac B: fresh dir, join flow, read the pairing code.
        app.terminate()
        app.launchEnvironment["FLEET_DATA_DIR"] = Self.dirB
        app.launch()
        tap("onboarding.join", timeout: 30)
        snap("09-join")
        dumpTexts("join")
        replace("onboarding.join.deviceName", with: "Mac B")
        tap("onboarding.join.showCode")
        let code = app.staticTexts.matching(NSPredicate(format: "label BEGINSWITH 'FLEETPAIR1-' OR value BEGINSWITH 'FLEETPAIR1-'")).firstMatch
        XCTAssertTrue(code.waitForExistence(timeout: 30), "no pairing code shown")
        let text = ((code.value as? String).flatMap { $0.hasPrefix("FLEETPAIR1-") ? $0 : nil }) ?? code.label
        note("pairing code length \(text.count)")
        snap("09-join-code")
        Thread.sleep(forTimeInterval: 20)
        snap("09-join-waiting-20s")
        dumpTexts("join-waiting")
        // Mac A: paste it.
        app.terminate()
        app.launchEnvironment["FLEET_DATA_DIR"] = Self.dir
        app.launch()
        unlock()
        openSettings()
        tap("settings.nav.devices")
        tap("devices.addMac")
        snap("09-addmac")
        segment("addMac.mode", "Paste code")
        let ed = wait("addMac.pasteCode")
        ed.click()
        ed.typeText(text)
        tap("addMac.continue")
        Thread.sleep(forTimeInterval: 30)
        snap("09-addmac-after-continue")
        dumpTexts("addmac-after")
        // Garbage code.
        app.typeKey(.escape, modifierFlags: [])
        if exists("devices.addMac", timeout: 3) {
            tap("devices.addMac")
            segment("addMac.mode", "Paste code")
            let e2 = wait("addMac.pasteCode")
            e2.click()
            e2.typeText("FLEETPAIR1-ABCDEF")
            tap("addMac.continue")
            Thread.sleep(forTimeInterval: 3)
            snap("09-addmac-garbage")
            dumpTexts("addmac-garbage")
        }
    }

    // MARK: cloud-init, mesh, games

    func test10CloudInitMeshGames() throws {
        unlock()
        sidebar("provisioning")
        Thread.sleep(forTimeInterval: 2)
        snap("10-provision")
        if exists("provision.exportCloudInit", timeout: 5) {
            tap("provision.exportCloudInit")
            snap("10-cloudinit-sheet")
            if exists("cloudInit.hostname", timeout: 3) { replace("cloudInit.hostname", with: "flt-ci") }
            tap("cloudInit.generate")
            Thread.sleep(forTimeInterval: 5)
            snap("10-cloudinit-generated")
            dumpTexts("cloudinit")
            if exists("cloudInit.save", timeout: 3) {
                tap("cloudInit.save")
                Thread.sleep(forTimeInterval: 2)
                app.typeKey("g", modifierFlags: [.command, .shift])
                Thread.sleep(forTimeInterval: 1)
                app.typeText("/tmp/fl-flt-ci")
                app.typeKey(.return, modifierFlags: [])
                Thread.sleep(forTimeInterval: 1)
                snap("10-save-panel")
                app.typeKey(.return, modifierFlags: [])
                Thread.sleep(forTimeInterval: 3)
                snap("10-saved")
            }
            if exists("cloudInit.close", timeout: 2) { tap("cloudInit.close") }
        } else { note("no provision.exportCloudInit on first step") }
        for n in ["flt-1", "flt-2"] {
            sidebar("server.\(n)")
            if exists("serverTab.mesh", timeout: 5) { tap("serverTab.mesh") } else {
                tap("serverTab.more"); app.menuItems["Mesh"].firstMatch.click()
            }
            Thread.sleep(forTimeInterval: 5)
            snap("10-mesh-\(n)")
            dumpTexts("mesh-\(n)")
        }
        if exists("serverTab.games", timeout: 3) { tap("serverTab.games") } else {
            tap("serverTab.more"); app.menuItems["Games"].firstMatch.click()
        }
        Thread.sleep(forTimeInterval: 5)
        snap("10-games")
        dumpTexts("games")
    }
}
