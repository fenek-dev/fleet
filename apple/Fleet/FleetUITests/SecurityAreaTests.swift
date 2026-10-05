import XCTest

/// Exploratory security-area walkthrough (provisioning, auto-revert,
/// firewall, bans, security tab, config history, Agent-only, uninstall)
/// against real pool servers, one step per test, sharing one data dir.
///
/// The steps depend on each other and on shell-side setup between runs, so
/// run them one at a time, in order:
///
/// - data dir: `/tmp/fl-sec1` (or `TEST_RUNNER_FLEET_UI_SEC_DIR`); delete it
///   before `test01Onboard`, and run with `TEST_RUNNER_FLEET_UI_KEEP_DATA=1`;
/// - `<dir>/sec.json` (written from the shell after onboarding, once the
///   app's `ssh_pubkey` is authorized on the servers):
///   `{"s1":"<port>","s2":"<port>",...}`, keys `s1`...`s5`;
/// - `TEST_RUNNER_FLEET_UI_ENV_FLEET_TEST_AGENT_ARTIFACT=<static agent>`.
final class SecurityAreaTests: FleetUITestCase {
    static var dir: String {
        ProcessInfo.processInfo.environment["FLEET_UI_SEC_DIR"] ?? "/tmp/fl-sec1"
    }

    override func setUpWithError() throws {
        extraEnvironment["FLEET_DATA_DIR"] = Self.dir
        try super.setUpWithError()
    }

    private var dirURL: URL { URL(fileURLWithPath: Self.dir, isDirectory: true) }

    private func param(_ key: String) throws -> String {
        let data = try Data(contentsOf: dirURL.appendingPathComponent("sec.json"))
        let obj = try JSONSerialization.jsonObject(with: data) as? [String: String] ?? [:]
        return try XCTUnwrap(obj[key], "sec.json has no \(key)")
    }

    private func sapprovals() -> String {
        (try? String(contentsOf: dirURL.appendingPathComponent("approvals.log"), encoding: .utf8)) ?? ""
    }

    private func mark(_ name: String) {
        // Evidence for the shell side: a step marker with a timestamp.
        let line = "\(Date().timeIntervalSince1970) \(name)\n"
        let url = dirURL.appendingPathComponent("steps.log")
        if let h = try? FileHandle(forWritingTo: url) {
            h.seekToEndOfFile(); h.write(line.data(using: .utf8)!); try? h.close()
        } else {
            try? line.write(to: url, atomically: true, encoding: .utf8)
        }
    }

    private func unlock() {
        wait("sidebar.fleet", timeout: 30)
        let lock = wait("sidebar.lock")
        if lock.label == "Unlock" { lock.click(); Thread.sleep(forTimeInterval: 2) }
    }

    /// Clicks the button titled `title` in the frontmost confirmation dialog.
    private func confirm(_ title: String, timeout: TimeInterval = 10) {
        let candidates = [app.sheets.buttons[title], app.dialogs.buttons[title]]
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            for c in candidates where c.exists && c.isHittable {
                c.click(); return
            }
            Thread.sleep(forTimeInterval: 0.3)
        }
        snap("no-dialog-\(title)")
        XCTFail("no dialog button \(title)")
    }

    private func bannerText() -> String {
        let b = element("autorevert.banner")
        guard b.exists else { return "" }
        return b.staticTexts.allElementsBoundByIndex.map { $0.label }.joined(separator: " | ")
    }

    /// Waits until the auto-revert banner says one of `words`.
    @discardableResult
    private func waitBanner(_ words: [String], timeout: TimeInterval = 120) -> String {
        let deadline = Date().addingTimeInterval(timeout)
        var last = ""
        while Date() < deadline {
            last = bannerText()
            if words.contains(where: { last.contains($0) }) { return last }
            Thread.sleep(forTimeInterval: 1)
        }
        return last
    }

    private func addServer(_ name: String, port: String, agentOnly: Bool) {
        sidebar("fleet")
        tap("fleet.addServer")
        replace("addServer.name", with: name)
        replace("addServer.host", with: "127.0.0.1")
        replace("addServer.port", with: port)
        replace("addServer.user", with: "ops")
        tap("addServer.addConnect")
        tap("addServer.trust", timeout: 60)
        tap("addServer.chooseArtifact")
        let picker = wait("addServer.security")
        snap("add-\(name)-security-picker")
        if agentOnly {
            let seg = picker.radioButtons.element(boundBy: 1)
            if seg.exists { seg.click() } else {
                let b = picker.buttons.element(boundBy: 1)
                if b.exists { b.click() }
            }
            snap("add-\(name)-agent-only-picked")
        }
        tap("addServer.install")
        let done = element("addServer.done")
        let err = element("addServer.error")
        let deadline = Date().addingTimeInterval(300)
        while Date() < deadline {
            if done.exists { break }
            if err.exists { snap("add-\(name)-error"); XCTFail("install error: \(err.label) \(err.value ?? "")"); return }
            Thread.sleep(forTimeInterval: 2)
        }
        snap("add-\(name)-done")
        XCTAssertTrue(done.exists, "install did not finish")
        done.click()
    }

    // MARK: steps

    func test01Onboard() throws {
        createFleet(name: "Sec fleet")
        XCTAssertNotNil(waitForFile("ssh_pubkey"))
        mark("onboarded")
    }

    func test02AddManagedS1() throws {
        unlock()
        addServer("s1", port: try param("s1"), agentOnly: false)
        mark("s1-added")
        sidebar("server.s1")
        Thread.sleep(forTimeInterval: 5)
        snap("s1-overview")
    }

    func test03AddAgentOnlyS3() throws {
        unlock()
        addServer("s3", port: try param("s3"), agentOnly: true)
        mark("s3-added")
        sidebar("server.s3")
        Thread.sleep(forTimeInterval: 8)
        snap("s3-overview")
    }

    /// Firewall on s1: add a rule, apply, auto-confirm; then roll back to v1.
    func test04FirewallApplyConfirmRollback() throws {
        unlock()
        sidebar("server.s1")
        serverTab("firewall")
        wait("firewall.tableSubtitle", timeout: 60)
        Thread.sleep(forTimeInterval: 3)
        snap("fw-initial")
        let mode = wait("firewall.mode")
        snap("fw-mode-\(mode.value ?? "")")
        tap("firewall.addRule")
        // New row: fill ports and comment (last text fields of the list).
        let ports = app.textFields.matching(NSPredicate(format: "placeholderValue == '22, 8000-8100'")).allElementsBoundByIndex.last
        XCTAssertNotNil(ports)
        ports?.click(); ports?.typeText("8080")
        let comment = app.textFields.matching(NSPredicate(format: "placeholderValue == 'Comment'")).allElementsBoundByIndex.last
        comment?.click(); comment?.typeText("sec test")
        snap("fw-rule-draft")
        tap("firewall.previewDiff")
        Thread.sleep(forTimeInterval: 1)
        snap("fw-preview-diff")
        if app.buttons["Close"].exists { app.buttons["Close"].click() }
        tap("firewall.apply")
        confirm("Apply")
        mark("fw-apply-clicked")
        Thread.sleep(forTimeInterval: 1)
        snap("fw-banner-confirming")
        let txt = waitBanner(["Change confirmed", "reverted", "failed", "Could not"])
        snap("fw-banner-final")
        mark("fw-banner: \(txt)")
        XCTAssertTrue(txt.contains("Change confirmed"), "banner: \(txt)")
        Thread.sleep(forTimeInterval: 3)
        snap("fw-after-apply")
        XCTAssertTrue(exists("firewall.history.v2", timeout: 20), "history v2")
        // Roll back to v1.
        tap("firewall.rollback.v1")
        confirm("Roll back")
        let t2 = waitBanner(["Change confirmed", "reverted", "failed", "Could not"], timeout: 120)
        mark("fw-rollback-banner: \(t2)")
        snap("fw-rollback-final")
        XCTAssertTrue(t2.contains("Change confirmed"), "rollback banner: \(t2)")
        Thread.sleep(forTimeInterval: 3)
        snap("fw-history-after-rollback")
    }

    /// Applies a firewall rule and quits before the confirm can finish, so
    /// the server's timer must revert it. The shell side checks nft.
    func test05FirewallApplyThenQuit() throws {
        unlock()
        sidebar("server.s1")
        serverTab("firewall")
        wait("firewall.tableSubtitle", timeout: 60)
        Thread.sleep(forTimeInterval: 3)
        tap("firewall.addRule")
        let ports = app.textFields.matching(NSPredicate(format: "placeholderValue == '22, 8000-8100'")).allElementsBoundByIndex.last
        ports?.click(); ports?.typeText("9091")
        tap("firewall.apply")
        confirm("Apply")
        mark("fw-noconfirm-apply-clicked")
        // Kill hard, no graceful shutdown.
        Thread.sleep(forTimeInterval: 0.2)
        app.terminate()
        mark("fw-noconfirm-terminated")
    }

    /// Re-opens the firewall tab after the unconfirmed change and records
    /// what the app shows (history, banner).
    func test06FirewallAfterRevert() throws {
        // Past the 60 s window (+ timer slack) of test05's change.
        Thread.sleep(forTimeInterval: 100)
        unlock()
        sidebar("server.s1")
        serverTab("firewall")
        wait("firewall.tableSubtitle", timeout: 60)
        Thread.sleep(forTimeInterval: 8)
        mark("fw-after-revert banner: \(bannerText())")
        snap("fw-after-revert")
    }

    func test07SecurityTab() throws {
        unlock()
        sidebar("server.s1")
        serverTab("security")
        wait("hardening.run", timeout: 60)
        tap("hardening.run")
        XCTAssertTrue(exists("security.scoreRing", timeout: 120), "score ring")
        Thread.sleep(forTimeInterval: 3)
        snap("sec-top")
        mark("sec counts passing=\(element("hardening.passingCount").label) tofix=\(element("hardening.toFixCount").label) accepted=\(element("hardening.acceptedCount").label)")
        let accept = app.buttons.matching(NSPredicate(format: "identifier BEGINSWITH 'hardening.accept.'")).firstMatch
        if accept.waitForExistence(timeout: 5) {
            let id = accept.identifier
            accept.click()
            Thread.sleep(forTimeInterval: 2)
            snap("sec-accepted")
            mark("sec accepted \(id): accepted=\(element("hardening.acceptedCount").label) note=\(exists("security.acceptedNote"))")
        } else {
            mark("sec no accept button")
        }
        app.scrollViews.firstMatch.scroll(byDeltaX: 0, deltaY: -600)
        snap("sec-mid")
        app.scrollViews.firstMatch.scroll(byDeltaX: 0, deltaY: -1200)
        snap("sec-bottom")
        let logins = app.descendants(matching: .any).matching(NSPredicate(format: "identifier BEGINSWITH 'security.login.'")).count
        let attention = app.descendants(matching: .any).matching(NSPredicate(format: "identifier BEGINSWITH 'security.attention.'")).count
        let alerts = app.descendants(matching: .any).matching(NSPredicate(format: "identifier BEGINSWITH 'security.alert.'")).count
        mark("sec logins=\(logins) attention=\(attention) alerts=\(alerts) alertOK=\(exists("security.alertOK", timeout: 1)) banCount=\(element("security.banCount").label)")
    }

    /// Bans on s1 (the shell caused failed logins from a sibling container).
    func test08Bans() throws {
        unlock()
        sidebar("server.s1")
        serverTab("security")
        Thread.sleep(forTimeInterval: 6)
        mark("bans security banCount=\(element("security.banCount").label)")
        snap("bans-security")
        serverTab("firewall")
        wait("firewall.tableSubtitle", timeout: 60)
        Thread.sleep(forTimeInterval: 4)
        snap("bans-firewall")
        let unban = app.buttons["Unban"].firstMatch
        if unban.waitForExistence(timeout: 10) {
            unban.click()
            confirm("Unban")
            Thread.sleep(forTimeInterval: 4)
            snap("bans-after-unban")
            mark("bans unbanned; remaining Unban buttons=\(app.buttons.matching(identifier: "Unban").count)")
        } else {
            mark("bans no Unban button")
        }
    }

    /// Adds an exemption (never-ban range) on s1.
    func test09BanExemption() throws {
        let cidr = try param("exempt")
        unlock()
        sidebar("server.s1")
        serverTab("firewall")
        wait("firewall.tableSubtitle", timeout: 60)
        Thread.sleep(forTimeInterval: 4)
        let editor = app.textViews.firstMatch
        XCTAssertTrue(editor.waitForExistence(timeout: 10))
        editor.click()
        editor.typeKey(.end, modifierFlags: .command)
        editor.typeText("\n\(cidr)")
        app.buttons["Save"].firstMatch.click()
        confirm("Save")
        Thread.sleep(forTimeInterval: 4)
        snap("bans-exempt-saved")
        mark("exempt saved \(cidr)")
    }

    func test10AgentOnlyUI() throws {
        unlock()
        sidebar("server.s3")
        Thread.sleep(forTimeInterval: 5)
        snap("ao-overview")
        serverTab("firewall")
        wait("security.modeNotice", timeout: 60)
        mark("ao firewall addRule enabled=\(element("firewall.addRule").isEnabled) apply enabled=\(element("firewall.apply").isEnabled) mode enabled=\(element("firewall.mode").isEnabled)")
        snap("ao-firewall")
        serverTab("security")
        Thread.sleep(forTimeInterval: 5)
        snap("ao-security")
        let fix = app.buttons.matching(NSPredicate(format: "identifier BEGINSWITH 'hardening.fix.'")).firstMatch
        mark("ao security modeNotice=\(exists("security.modeNotice")) fixExists=\(fix.exists) fixEnabled=\(fix.exists && fix.isEnabled)")
        serverTab("users")
        Thread.sleep(forTimeInterval: 5)
        snap("ao-users")
    }

    /// Switch s3 Agent-only -> Managed from Overview (Touch ID expected).
    func test11AgentOnlyToManaged() throws {
        unlock()
        sidebar("server.s3")
        serverTab("overview")
        Thread.sleep(forTimeInterval: 5)
        let before = sapprovals()
        let b = app.buttons["Enable Fleet security management…"]
        XCTAssertTrue(b.waitForExistence(timeout: 20), "enable managed button")
        snap("ao-enable-button")
        b.click()
        Thread.sleep(forTimeInterval: 1)
        snap("ao-enable-dialog")
        for t in ["Enable", "Enable management", "Switch to Managed", "Continue"] where app.sheets.buttons[t].exists || app.dialogs.buttons[t].exists {
            confirm(t); break
        }
        Thread.sleep(forTimeInterval: 10)
        snap("ao-after-enable")
        let after = sapprovals()
        mark("ao enable approvals delta: \(after.dropFirst(before.count).replacingOccurrences(of: "\n", with: " || "))")
    }

    func test12ConfigHistory() throws {
        unlock()
        sidebar("server.s1")
        serverTab("config")
        Thread.sleep(forTimeInterval: 8)
        snap("cfg-list")
        mark("cfg texts: \(app.staticTexts.allElementsBoundByIndex.prefix(60).map { $0.label }.joined(separator: " ~ "))")
    }

    /// Provision s2 with Baseline (+ roles from sec.json "roles2").
    func test13ProvisionBaseline() throws {
        try provision(key: "s2name", level: "Baseline", roles: (try? param("roles2")) ?? "")
    }

    func test14ProvisionStrict() throws {
        try provision(key: "s4name", level: "Strict", roles: (try? param("roles4")) ?? "")
    }

    func test15ProvisionRoles() throws {
        try provision(key: "s5name", level: "Baseline", roles: (try? param("roles5")) ?? "")
    }

    private func provision(key: String, level: String, roles: String) throws {
        let name = try param(key)
        let port = try param(key.replacingOccurrences(of: "name", with: ""))
        unlock()
        // Add the server without the agent first? The wizard's "Add server…"
        // runs the same install flow.
        sidebar("provisioning")
        wait("provision.server", timeout: 20)
        snap("prov-\(name)-connect")
        tap("provision.addServer")
        replace("addServer.name", with: name)
        replace("addServer.host", with: "127.0.0.1")
        replace("addServer.port", with: port)
        replace("addServer.user", with: "ops")
        tap("addServer.addConnect")
        tap("addServer.trust", timeout: 60)
        tap("addServer.chooseArtifact")
        snap("prov-\(name)-install-step")
        tap("addServer.install")
        tap("addServer.done", timeout: 300)
        Thread.sleep(forTimeInterval: 2)
        snap("prov-\(name)-after-install")
        // Pick the server if not selected.
        let picker = wait("provision.server")
        if (picker.value as? String)?.contains(name) != true {
            picker.click()
            let item = app.menuItems.matching(NSPredicate(format: "title BEGINSWITH %@", name)).firstMatch
            if item.waitForExistence(timeout: 5) { item.click() }
        }
        Thread.sleep(forTimeInterval: 2)
        snap("prov-\(name)-profile")
        if level == "Strict" {
            let lv = wait("provision.level")
            lv.radioButtons["Strict"].firstMatch.click()
        }
        for r in roles.split(separator: ",").map(String.init) where !r.isEmpty {
            switch r {
            case "docker": tap("provision.role.Docker / Compose")
            case "web", "caddy": tap("provision.role.Web / reverse proxy")
            case "nginx":
                tap("provision.role.Web / reverse proxy")
                let ws = wait("provision.webServer")
                let seg = ws.radioButtons["nginx"].exists ? ws.radioButtons["nginx"] : ws.buttons["nginx"]
                seg.click()
            case "game": tap("provision.role.Game server")
            case "anywhere":
                let sf = wait("provision.sshFrom")
                sf.radioButtons.element(boundBy: 1).click()
            default: break
            }
        }
        Thread.sleep(forTimeInterval: 3)
        mark("prov \(name) macIP=\(exists("provision.macIP", timeout: 1) ? element("provision.macIP").label : "none") macErr=\(exists("provision.macIPError", timeout: 1) ? element("provision.macIPError").label : "none")")
        snap("prov-\(name)-profile-filled")
        app.scrollViews.firstMatch.scroll(byDeltaX: 0, deltaY: -800)
        snap("prov-\(name)-profile-filled-bottom")
        tap("provision.reviewPlan")
        wait("provision.apply", timeout: 240)
        Thread.sleep(forTimeInterval: 2)
        snap("prov-\(name)-review")
        app.scrollViews.firstMatch.scroll(byDeltaX: 0, deltaY: -800)
        snap("prov-\(name)-review-bottom")
        let before = sapprovals()
        tap("provision.apply")
        mark("prov \(name) apply clicked")
        // Watch until done or failed.
        let deadline = Date().addingTimeInterval(520)
        var n = 0
        while Date() < deadline {
            if exists("provision.openServer", timeout: 1) || exists("provision.another", timeout: 1) { break }
            if exists("provision.resume", timeout: 1) || exists("provision.cancelFailed", timeout: 1) { snap("prov-\(name)-failed"); break }
            if exists("provision.reviewPlan", timeout: 1) && !exists("provision.apply", timeout: 1) { }
            n += 1
            if n % 10 == 0 { snap("prov-\(name)-progress-\(n)") }
            Thread.sleep(forTimeInterval: 3)
        }
        snap("prov-\(name)-final")
        app.scrollViews.firstMatch.scroll(byDeltaX: 0, deltaY: -800)
        snap("prov-\(name)-final-bottom")
        let texts = app.staticTexts.allElementsBoundByIndex.prefix(80).map { $0.label }.joined(separator: " ~ ")
        mark("prov \(name) final texts: \(texts)")
        mark("prov \(name) approvals delta: \(sapprovals().dropFirst(before.count).replacingOccurrences(of: "\n", with: " || "))")
    }

    /// Uninstall the agent from s1.
    func test20Uninstall() throws {
        let name = (try? param("uninstall")) ?? "s1"
        unlock()
        sidebar("server.\(name)")
        serverTab("overview")
        Thread.sleep(forTimeInterval: 5)
        let before = sapprovals()
        let b = app.buttons["Uninstall agent…"]
        XCTAssertTrue(b.waitForExistence(timeout: 20))
        b.click()
        confirm("Uninstall, keep audit database")
        mark("uninstall \(name) clicked")
        Thread.sleep(forTimeInterval: 60)
        snap("uninstall-\(name)-after")
        mark("uninstall approvals delta: \(sapprovals().dropFirst(before.count).replacingOccurrences(of: "\n", with: " || "))")
        mark("uninstall texts: \(app.staticTexts.allElementsBoundByIndex.prefix(40).map { $0.label }.joined(separator: " ~ "))")
    }

    /// Generic screenshot pass of a server's tab (sec.json "shot": "server:tab").
    func test30Shot() throws {
        let spec = try param("shot").split(separator: ":").map(String.init)
        unlock()
        sidebar("server.\(spec[0])")
        serverTab(spec[1])
        Thread.sleep(forTimeInterval: 10)
        snap("shot-\(spec[0])-\(spec[1])")
        mark("shot \(spec[0]) \(spec[1]) texts: \(app.staticTexts.allElementsBoundByIndex.prefix(80).map { $0.label }.joined(separator: " ~ "))")
        app.scrollViews.firstMatch.scroll(byDeltaX: 0, deltaY: -900)
        snap("shot-\(spec[0])-\(spec[1])-2")
    }
}
