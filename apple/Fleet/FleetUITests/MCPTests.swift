import XCTest

/// Operator side of the MCP end-to-end run (tests/mcp/run.py drives it).
///
/// The Python driver is the master: it writes `<ctl>/cmd` lines
/// `<seq> <verb> [args…]` and this test performs the in-app part (onboarding,
/// Add server, approval sheets, pause, lock, revoke, quit/relaunch), then
/// answers in `<ctl>/ack` as `<seq> ok|fail <detail>`. Pairing prompts are
/// left to the operator (`FLEET_TEST_AUTO_PAIR=0`). Run it alone:
///
///   scripts/build-app-test.sh test -only-testing:FleetUITests/MCPTests
///
/// Without the driver it waits for `cmd` and times out (skipped unless
/// `/tmp/fl-mcp-ctl/go` exists).
final class MCPTests: FleetUITestCase {
    static let ctl = URL(fileURLWithPath: "/tmp/fl-mcp-ctl", isDirectory: true)

    override func setUpWithError() throws {
        guard FileManager.default.fileExists(atPath: Self.ctl.appendingPathComponent("go").path)
        else { throw XCTSkip("no MCP driver (tests/mcp/run.py) running") }
        extraEnvironment["FLEET_TEST_AUTO_PAIR"] = "0"
        // Repo root from this file: apple/Fleet/FleetUITests/MCPTests.swift.
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
        let arch = "aarch64"
        extraEnvironment["FLEET_TEST_AGENT_ARTIFACT"] =
            root.appendingPathComponent("target/linux/\(arch)/fleet-agent").path
        try super.setUpWithError()
    }

    func testOperatorSideOfMcpRun() throws {
        wait("onboarding.create", timeout: 60)
        var seq = 0
        let deadline = Date().addingTimeInterval(3 * 3600)
        ack(0, true, dataDir.path)
        while Date() < deadline {
            guard let line = try? String(contentsOf: Self.ctl.appendingPathComponent("cmd"), encoding: .utf8)
            else { Thread.sleep(forTimeInterval: 0.3); continue }
            let parts = line.trimmingCharacters(in: .whitespacesAndNewlines)
                .split(separator: " ", omittingEmptySubsequences: true).map(String.init)
            guard let n = parts.first.flatMap(Int.init), n == seq + 1 else {
                Thread.sleep(forTimeInterval: 0.3); continue
            }
            seq = n
            let verb = parts.count > 1 ? parts[1] : ""
            let args = Array(parts.dropFirst(2))
            if verb == "done" { ack(n, true, "bye"); return }
            let (ok, detail) = perform(verb, args)
            ack(n, ok, detail)
        }
        XCTFail("driver never sent done")
    }

    // MARK: verbs

    private func perform(_ verb: String, _ a: [String]) -> (Bool, String) {
        switch verb {
        case "create":
            createFleet(name: "MCP fleet")
            // The app comes out of onboarding locked (monitor only).
            let wasLocked = unlockIfLocked()
            return (true, dataDir.path + (wasLocked ? " (was locked after onboarding)" : ""))
        case "add":  // add <name> <port> <managed|agentonly>
            return addServer(name: a[0], port: a[1], agentOnly: a[2] == "agentonly")
        case "addonly":  // addonly <name> <port>: listed, never connected
            sidebar("fleet")
            tap("fleet.addServer")
            replace("addServer.name", with: a[0])
            replace("addServer.host", with: "127.0.0.1")
            replace("addServer.port", with: a[1])
            replace("addServer.user", with: "ops")
            tap("addServer.addOnly")
            Thread.sleep(forTimeInterval: 1)
            return (!exists("addServer.addOnly", timeout: 1), "")
        case "approve", "deny", "pausePrompt":
            let id = verb == "approve" ? "aiPrompt.approve"
                : verb == "deny" ? "aiPrompt.deny" : "aiPrompt.pause"
            let e = element(id)
            guard e.waitForExistence(timeout: Double(a.first ?? "30") ?? 30) else {
                return (false, "no prompt")
            }
            let text = sheetText()
            snap("prompt-\(verb)")
            e.click()
            return (true, text)
        case "prompt":  // is a prompt showing? returns its text
            let e = element("aiPrompt.approve")
            guard e.waitForExistence(timeout: Double(a.first ?? "5") ?? 5) else {
                return (false, "no prompt")
            }
            return (true, sheetText())
        case "pause", "resume":
            openAISettings()
            let t = wait("ai.pause")
            let on = (t.value as? Int) == 1 || (t.value as? String) == "1"
            if on != (verb == "pause") { t.click() }
            snap("ai-\(verb)")
            closeSettings()
            return (true, "")
        case "clients":
            openAISettings()
            Thread.sleep(forTimeInterval: 1)
            let names = app.descendants(matching: .any).matching(identifier: "ai.client.name")
                .allElementsBoundByIndex.map { ($0.value as? String) ?? $0.label }
            let all = app.descendants(matching: .any).matching(identifier: "settings.ai")
                .firstMatch.staticTexts.allElementsBoundByIndex.map { $0.label }
            snap("ai-clients")
            closeSettings()
            return (true, names.joined(separator: "|") + " ## " + all.joined(separator: " | "))
        case "revoke":
            openAISettings()
            let b = element("ai.client.revoke")
            guard b.waitForExistence(timeout: 5) else { closeSettings(); return (false, "none") }
            b.click()
            snap("ai-revoked")
            closeSettings()
            return (true, "")
        case "lock", "unlock":
            let b = wait("sidebar.lock")
            let want = verb == "lock" ? "Lock" : "Unlock"
            if b.label == want { b.click() }
            Thread.sleep(forTimeInterval: 1)
            snap("after-\(verb)")
            return (true, "label was \(b.label)")
        case "quit":
            app.terminate()
            return (true, "")
        case "launch":
            app.launch()
            Thread.sleep(forTimeInterval: 3)
            return (true, "")
        case "snap":
            snap(a.first ?? "snap")
            return (true, "")
        case "text":  // all static texts of the main window
            return (true, app.windows.firstMatch.staticTexts.allElementsBoundByIndex
                .prefix(300).map { $0.label }.joined(separator: " | "))
        case "sidebar":
            sidebar(a[0])
            Thread.sleep(forTimeInterval: 1)
            snap("sidebar-\(a[0])")
            return (true, "")
        default:
            return (false, "unknown verb \(verb)")
        }
    }

    private func addServer(name: String, port: String, agentOnly: Bool) -> (Bool, String) {
        sidebar("fleet")
        tap("fleet.addServer")
        replace("addServer.name", with: name)
        replace("addServer.host", with: "127.0.0.1")
        replace("addServer.port", with: port)
        replace("addServer.user", with: "ops")
        tap("addServer.addConnect")
        tap("addServer.trust", timeout: 60)
        tap("addServer.chooseArtifact", timeout: 60)
        if agentOnly {
            let p = wait("addServer.security")
            p.click()
            let item = app.menuItems["Agent only (don't change security)"]
            if item.waitForExistence(timeout: 5) { item.click() } else {
                return (false, "no Agent-only menu item")
            }
        }
        snap("install-\(name)")
        tap("addServer.install")
        let done = element("addServer.done")
        let err = element("addServer.retry")
        let deadline = Date().addingTimeInterval(300)
        while Date() < deadline {
            if done.exists {
                let info = sheetText()
                snap("installed-\(name)")
                done.click()
                return (true, info)
            }
            if err.exists {
                let info = sheetText()
                snap("install-failed-\(name)")
                return (false, info)
            }
            Thread.sleep(forTimeInterval: 1)
        }
        snap("install-timeout-\(name)")
        return (false, "timeout: " + sheetText())
    }

    // MARK: helpers

    @discardableResult
    private func unlockIfLocked() -> Bool {
        let b = wait("sidebar.lock")
        guard b.label == "Unlock" else { return false }
        b.click()
        Thread.sleep(forTimeInterval: 1)
        return true
    }

    private func sheetText() -> String {
        let s = app.sheets.firstMatch
        let root: XCUIElement = s.exists ? s : app.windows.firstMatch
        return root.staticTexts.allElementsBoundByIndex.prefix(200).map {
            let v = ($0.value as? String) ?? ""
            return v.isEmpty ? $0.label : v
        }.joined(separator: " | ")
    }

    private func openAISettings() {
        openSettings()
        let b = app.toolbars.buttons["AI"]
        if b.waitForExistence(timeout: 5) { b.click() }
        _ = element("ai.pause").waitForExistence(timeout: 5)
    }

    private func closeSettings() {
        app.typeKey("w", modifierFlags: .command)
    }

    private func ack(_ n: Int, _ ok: Bool, _ detail: String) {
        let s = "\(n) \(ok ? "ok" : "fail") \(detail.replacingOccurrences(of: "\n", with: " "))\n"
        // The sandboxed runner can't write /tmp; its own temporary directory
        // (~/Library/Containers/<runner>/Data/tmp) is readable by the driver.
        let url = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("fl-mcp-ack")
        try? s.write(to: url, atomically: true, encoding: .utf8)
        let a = XCTAttachment(string: s)
        a.name = "ack-\(n)"
        a.lifetime = .keepAlways
        add(a)
    }
}
