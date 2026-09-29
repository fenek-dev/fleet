import XCTest

/// Shell and navigation: sidebar, command palette, alerts, Settings.
/// These tests need no server.
final class ShellTests: FleetUITestCase {
    func testSidebarPaletteSettings() throws {
        wait("onboarding.create", timeout: 30)
        createFleet(name: "Shell fleet")
        snap("shell-01-fleet")

        // Sidebar items of the mockup, in place.
        for id in ["fleet", "alerts", "timeline", "search", "vulnerabilities", "runbooks",
                   "provisioning", "settings"] {
            XCTAssertTrue(exists("sidebar.\(id)"), "sidebar.\(id) missing")
        }
        XCTAssertTrue(exists("sidebar.aiPause"))
        XCTAssertTrue(exists("sidebar.lock"))
        XCTAssertTrue(exists("sidebar.aiState"))

        // Palette: navigation and run actions (the app starts locked, and
        // run actions only exist unlocked).
        tap("sidebar.lock")
        XCTAssertTrue(shellWaitGone("locked.banner", in: self))
        openCommandPalette()
        wait("palette.query")
        snap("shell-02-palette")
        for id in ["nav.timeline", "nav.runbooks", "nav.provision", "nav.settings",
                   "nav.search", "nav.vulnerabilities", "settings.alertRules", "lock",
                   "run.agent.health", "run.shell.exec"] {
            XCTAssertTrue(exists("palette.item.\(id)"), "palette item \(id) missing")
        }
        type("palette.query", "settings appearance")
        tap("palette.item.settings.appearance")
        wait("settings.appearance")
        snap("shell-03-settings-appearance")

        // Every Settings section renders.
        let sections: [(String, String)] = [
            ("devices", "settings.devices"), ("recovery", "settings.recovery"),
            ("ai", "settings.ai"), ("sync", "settings.sync"),
            ("releases", "settings.agentReleases"), ("alertRules", "settings.alertRules"),
            ("profiles", "settings.profiles"), ("appearance", "settings.appearance"),
            ("general", "settings.general"),
        ]
        for (s, page) in sections {
            tap("settings.nav.\(s)")
            wait(page)
            snap("shell-settings-\(s)")
        }

        // Devices: this Mac is listed with its badge and chips.
        tap("settings.nav.devices")
        wait("devices.rosterTitle")
        XCTAssertTrue(exists("devices.addMac"))
        XCTAssertTrue(app.staticTexts["This Mac"].waitForExistence(timeout: 5))
        XCTAssertTrue(app.staticTexts["Secure Enclave keys"].exists)
        XCTAssertTrue(app.staticTexts["Full admin"].exists)
        XCTAssertTrue(app.staticTexts["Never tested"].exists)

        // Profiles: built-in catalog, modules expand.
        tap("settings.nav.profiles")
        wait("profiles.card.baseline")
        tap("profiles.toggle.strict")
        XCTAssertTrue(app.staticTexts["Strict"].exists)
        snap("shell-profiles-expanded")

        // Appearance: the accent changes.
        tap("settings.nav.appearance")
        tap("appearance.accent.teal")
        wait("settings.appearance")
        snap("shell-appearance-teal")
        tap("appearance.accent.blue")

        // AI: pause from the sidebar shows in Settings.
        tap("sidebar.aiPause")
        XCTAssertTrue(app.staticTexts["AI agents paused"].waitForExistence(timeout: 5))
        tap("settings.nav.ai")
        wait("ai.summary")
        snap("shell-ai-paused")
        tap("sidebar.aiPause")

        // ⌘, opens Settings from anywhere.
        sidebar("fleet")
        app.typeKey(",", modifierFlags: .command)
        wait("settings.nav.devices")
    }

    func testLockedBannerAndAlertsChrome() throws {
        createFleet(name: "Lock fleet")
        sidebar("alerts")
        wait("alerts.empty")
        snap("shell-alerts-empty")

        // The app starts locked (monitor key only): every screen says so.
        wait("locked.banner")
        snap("shell-locked")
        sidebar("provisioning")
        XCTAssertTrue(exists("locked.banner"))
        sidebar("runbooks")
        XCTAssertTrue(exists("locked.banner"))
        // Run actions are not offered while locked.
        openCommandPalette()
        wait("palette.query")
        XCTAssertFalse(exists("palette.item.run.agent.health", timeout: 1))
        XCTAssertTrue(exists("palette.item.lock"))
        app.typeKey(.escape, modifierFlags: [])

        tap("locked.unlock")
        XCTAssertTrue(shellWaitGone("locked.banner", in: self))
        XCTAssertTrue(approvalsLog.contains("app-unlock"), "approvals.log: \(approvalsLog)")

        // Locking again brings the banner back.
        tap("sidebar.lock")
        wait("locked.banner")
    }
}

private func shellWaitGone(_ id: String, in t: FleetUITestCase, timeout: TimeInterval = 10) -> Bool {
    let e = t.element(id)
    let end = Date().addingTimeInterval(timeout)
    while e.exists && Date() < end { Thread.sleep(forTimeInterval: 0.3) }
    return !e.exists
}

/// Needs a pool server and the agent artifact. The data dir is fixed so a
/// watcher can authorize `ssh_pubkey` on a pool container and write its
/// port to `pool.txt` (scratch script, see the package report):
///
///     FLEET_SHELL_POOL=1 (runner env, TEST_RUNNER_ prefix for xcodebuild)
///     /tmp/fl-shell-agent   the static fleet-agent binary
final class ShellServerTests: FleetUITestCase {
    static let dir = "/tmp/fl-shell"

    override func setUpWithError() throws {
        guard ProcessInfo.processInfo.environment["FLEET_SHELL_POOL"] == "1" else {
            throw XCTSkip("needs a pool server; see the class comment")
        }
        extraEnvironment["FLEET_DATA_DIR"] = Self.dir
        extraEnvironment["FLEET_TEST_AGENT_ARTIFACT"] = "/tmp/fl-shell-agent"
        try super.setUpWithError()
    }

    private func shellFile(_ name: String, timeout: TimeInterval = 20) -> String? {
        let url = URL(fileURLWithPath: Self.dir).appendingPathComponent(name)
        let end = Date().addingTimeInterval(timeout)
        while Date() < end {
            if let s = try? String(contentsOf: url, encoding: .utf8), !s.isEmpty {
                return s.trimmingCharacters(in: .whitespacesAndNewlines)
            }
            Thread.sleep(forTimeInterval: 0.5)
        }
        return nil
    }

    /// Alert rules edited with Touch ID, the alert worded in plain
    /// language, acknowledged, and a palette run action.
    func testServerBackedShell() throws {
        createFleet(name: "Shell pool")
        guard let port = shellFile("pool.txt", timeout: 180) else {
            return XCTFail("no pool.txt: the watcher did not start a server")
        }
        tap("fleet.addServer")
        type("addServer.name", "pool-1")
        replace("addServer.host", with: "127.0.0.1")
        replace("addServer.port", with: port)
        replace("addServer.user", with: "ops")
        tap("addServer.addConnect")
        tap("addServer.trust", timeout: 60)
        tap("addServer.chooseArtifact")
        tap("addServer.install")
        wait("addServer.done", timeout: 240)
        tap("addServer.done")
        snap("shell-server-added")

        // Alert rule: memory at or above 0.1% for 0 minutes fires at once.
        app.typeKey(",", modifierFlags: .command)
        tap("settings.nav.alertRules")
        tap("alertRules.server")
        app.menuItems["pool-1"].firstMatch.click()
        wait("alertRules.add", timeout: 60)
        tap("alertRules.add")
        app.menuItems["Memory usage"].firstMatch.click()
        replace("alertRules.threshold.memory", with: "0.1")
        replace("alertRules.for.memory", with: "0")
        snap("shell-alert-rule-edit")
        tap("alertRules.save")
        wait("alertRules.saved", timeout: 60)
        let log = shellFile("approvals.log") ?? ""
        XCTAssertTrue(log.contains("alert_rules.update"), "approvals.log: \(log)")
        snap("shell-alert-rule-saved")

        // The alert arrives worded as the rule, not as its id.
        sidebar("alerts")
        let title = wait("alerts.rule", timeout: 180)
        XCTAssertTrue(title.label.contains("Memory usage above"), "alert title: \(title.label)")
        snap("shell-alerts-open")
        XCTAssertTrue(exists("sidebar.alerts.badge"))

        // Acknowledge: the badge and the list clear, the alert stays reachable.
        tap("alerts.ack")
        XCTAssertTrue(shellWaitGone("sidebar.alerts.badge", in: self))
        wait("alerts.empty")
        tap("alerts.showAcked")
        wait("alerts.list")
        snap("shell-alerts-acked")

        // Palette run action opens the bulk sheet with the operation.
        openCommandPalette()
        type("palette.query", "agent health")
        tap("palette.item.run.agent.health")
        wait("bulk.close")
        snap("shell-palette-bulk")
        tap("bulk.close")
    }
}
