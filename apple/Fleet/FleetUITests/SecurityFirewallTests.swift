import XCTest

/// Security and Firewall tabs against a real pool server.
///
/// Needs (forwarded to the runner as `TEST_RUNNER_<NAME>`):
/// - `FLEET_UI_SERVER_PORT`: port of a pool server (`tests/vm/pool.sh`);
/// - `FLEET_UI_ENV_FLEET_TEST_AGENT_ARTIFACT`: static agent binary;
/// and a watcher that authorizes `/tmp/fleet-ui-*/ssh_pubkey` on that
/// server as soon as the key appears (the key exists only after onboarding).
final class SecurityFirewallTests: FleetUITestCase {
    private var port: String {
        ProcessInfo.processInfo.environment["FLEET_UI_SERVER_PORT"] ?? ""
    }

    /// Onboards, adds the pool server and installs the agent (Agent-only
    /// when `agentOnly`).
    private func addServer(agentOnly: Bool) throws {
        try XCTSkipIf(port.isEmpty, "FLEET_UI_SERVER_PORT not set")
        createFleet()
        _ = waitForFile("ssh_pubkey")
        // Give the watcher a moment to authorize the key on the server.
        Thread.sleep(forTimeInterval: 6)
        tap("fleet.addServer")
        replace("addServer.name", with: "sec-1")
        replace("addServer.host", with: "127.0.0.1")
        replace("addServer.port", with: port)
        replace("addServer.user", with: "ops")
        tap("addServer.addConnect")
        tap("addServer.trust", timeout: 60)
        tap("addServer.chooseArtifact")
        if agentOnly {
            // Security picker: second segment is "Agent only".
            let picker = wait("addServer.security")
            let seg = picker.radioButtons.element(boundBy: 1)
            if seg.exists { seg.click() }
        }
        tap("addServer.install")
        tap("addServer.done", timeout: 240)
        sidebar("server.sec-1")
    }

    func testSecurityTabSections() throws {
        try addServer(agentOnly: false)
        serverTab("security")
        wait("hardening.run", timeout: 60)
        snap("security-top")
        XCTAssertTrue(exists("security.scoreRing", timeout: 90), "score ring")
        wait("hardening.passingCount")
        wait("hardening.toFixCount")
        wait("hardening.acceptedCount")
        wait("security.banCount")
        wait("security.allBans")
        wait("vulns.scan")
        snap("security-full")

        // Accept the first open finding as an exception: counts change and
        // the footnote appears; undo restores it.
        let accept = app.buttons.matching(NSPredicate(format: "identifier BEGINSWITH 'hardening.accept.'")).firstMatch
        if accept.waitForExistence(timeout: 5) {
            accept.click()
            wait("security.acceptedNote")
            snap("security-accepted")
            let undo = app.buttons.matching(NSPredicate(format: "identifier BEGINSWITH 'hardening.unaccept.'")).firstMatch
            XCTAssertTrue(undo.waitForExistence(timeout: 5))
            undo.click()
        }

        // "All bans" jumps to the Firewall tab.
        tap("security.allBans")
        wait("firewall.tableSubtitle")
        snap("all-bans-opened-firewall")
    }

    func testFirewallTab() throws {
        try addServer(agentOnly: false)
        serverTab("firewall")
        wait("firewall.tableSubtitle", timeout: 60)
        wait("firewall.history.v1", timeout: 30)
        wait("firewall.cooperative")
        snap("firewall-initial")

        tap("firewall.addRule")
        snap("firewall-new-rule")
        XCTAssertTrue(exists("firewall.ruleTag"), "unsaved rule is tagged")
    }

    func testAgentOnlyDisablesFirewallChanges() throws {
        try addServer(agentOnly: true)
        serverTab("firewall")
        wait("security.modeNotice", timeout: 60)
        XCTAssertFalse(element("firewall.addRule").isEnabled)
        XCTAssertFalse(element("firewall.apply").isEnabled)
        snap("firewall-agent-only")
        serverTab("security")
        wait("security.modeNotice", timeout: 30)
        snap("security-agent-only")
    }
}
