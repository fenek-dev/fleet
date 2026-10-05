import XCTest

/// Operator steps for the MCP end-to-end run (tests/mcp/run.py).
///
/// Unlike the other UI tests this one doesn't launch the app: run.py starts
/// its own instance (a copy of Fleet.app with bundle id
/// `dev.fleet.FleetMCP`, so it is never confused with other test instances)
/// and calls this test once per phase with a batch of operator steps,
/// keeping each UI run short. Steps are the lines of `/tmp/fl-mcp-ctl/cmd`
/// (`<verb> [args…]`); progress goes to the runner's temporary directory as
/// `fl-mcp-ack` (`start`, `<i> ok|fail <detail>`, `end`), since the sandboxed
/// runner can't write /tmp.
/// Skipped when there is no step to run.
final class MCPTests: XCTestCase {
    static let ctl = URL(fileURLWithPath: "/tmp/fl-mcp-ctl", isDirectory: true)
    var app: XCUIApplication!

    override func setUpWithError() throws {
        // Stop at the first failure: the driver sees the missing ack, and
        // the machine-wide UI lock is released quickly.
        continueAfterFailure = false
        guard (try? String(contentsOf: Self.ctl.appendingPathComponent("cmd"), encoding: .utf8)) != nil
        else { throw XCTSkip("no MCP step (tests/mcp/run.py) pending") }
        // By path: the runner can't resolve this copy by bundle id.
        // (/private/tmp: the running app's bundle URL, symlinks resolved.)
        app = XCUIApplication(url: URL(fileURLWithPath: "/private/tmp/fl-mcp-app/FleetMCP.app"))
    }

    /// Runs every line of `cmd` in order; appends `<i> ok|fail <detail>` per
    /// line (after a `start` line) so the driver can pace its MCP calls.
    func testStep() throws {
        let text = try String(contentsOf: Self.ctl.appendingPathComponent("cmd"), encoding: .utf8)
        let lines = text.split(separator: "\n").map {
            $0.trimmingCharacters(in: .whitespaces).split(separator: " ").map(String.init)
        }.filter { !$0.isEmpty }
        try? FileManager.default.removeItem(at: ackURL)
        guard app.state != .notRunning else { return ack("start fail app not running") }
        app.activate()
        // Every session starts unlocked (the app locks on launch and idle);
        // before onboarding there is no lock control yet.
        let wasLocked = element("sidebar.lock").waitForExistence(timeout: 3) && unlockIfLocked()
        ack("start ok\(wasLocked ? " (was locked)" : "")")
        for (i, parts) in lines.enumerated() {
            let (ok, detail) = perform(parts[0], Array(parts.dropFirst()))
            ack("\(i) \(ok ? "ok" : "fail") \(detail)")
        }
        ack("end ok")
    }

    // MARK: verbs

    private func perform(_ verb: String, _ a: [String]) -> (Bool, String) {
        switch verb {
        case "create":
            createFleet(name: "MCP fleet")
            let was = unlockIfLocked()
            return (exists("sidebar.fleet", 5), was ? "was locked after onboarding" : "")
        case "add":  // add <name> <port> <managed|agentonly>
            return addServer(name: a[0], port: a[1], agentOnly: a[2] == "agentonly")
        case "addonly":  // addonly <name> <port>: listed, never connected
            tap("sidebar.fleet")
            tap("fleet.addServer")
            replace("addServer.name", a[0])
            replace("addServer.host", "127.0.0.1")
            replace("addServer.port", a[1])
            replace("addServer.user", "ops")
            tap("addServer.addOnly")
            return (!exists("addServer.addOnly", 2), "")
        case "approve", "deny", "pausePrompt":
            let id = verb == "approve" ? "aiPrompt.approve"
                : verb == "deny" ? "aiPrompt.deny" : "aiPrompt.pause"
            let e = element(id)
            guard e.waitForExistence(timeout: Double(a.first ?? "30") ?? 30) else {
                snap("no-prompt-\(verb)")
                return (false, "no prompt")
            }
            let text = sheetText()
            snap("prompt-\(verb)")
            e.click()
            return (true, text)
        case "prompt":  // is a prompt showing? its text
            guard element("aiPrompt.approve").waitForExistence(timeout: Double(a.first ?? "5") ?? 5)
            else { return (false, "no prompt") }
            snap("prompt")
            return (true, sheetText())
        case "pause", "resume":
            openAISettings()
            let t = element("ai.pause")
            guard t.waitForExistence(timeout: 5) else { return (false, "no ai.pause") }
            let on = "\(t.value ?? "")" == "1"
            if on != (verb == "pause") { t.click() }
            snap("ai-\(verb)")
            closeSettings()
            return (true, "was \(on ? "on" : "off")")
        case "clients":
            openAISettings()
            let names = app.descendants(matching: .any).matching(identifier: "ai.client.name")
                .allElementsBoundByIndex.map { ($0.value as? String) ?? $0.label }
            let texts = app.windows.allElementsBoundByIndex.flatMap {
                $0.staticTexts.allElementsBoundByIndex.map { $0.label }
            }
            snap("ai-clients")
            closeSettings()
            return (true, names.joined(separator: "|") + " ## " + texts.joined(separator: " | "))
        case "revoke":  // revoke [index]
            openAISettings()
            let all = app.descendants(matching: .any).matching(identifier: "ai.client.revoke")
            let i = Int(a.first ?? "0") ?? 0
            guard all.count > i else { closeSettings(); return (false, "none") }
            all.element(boundBy: i).click()
            snap("ai-revoked")
            closeSettings()
            return (true, "")
        case "lock", "unlock":
            let b = element("sidebar.lock")
            guard b.waitForExistence(timeout: 10) else { return (false, "no sidebar.lock") }
            let was = b.label
            if verb == "unlock" {
                unlockIfLocked()
            } else if b.label == "Lock" {
                b.click()
            }
            snap("after-\(verb)")
            return (true, "label was \(was)")
        case "idle8h":  // Settings → General → Lock after idle: 8 hours
            app.typeKey(",", modifierFlags: .command)
            let g = app.toolbars.buttons["General"]
            if g.waitForExistence(timeout: 5) { g.click() }
            let p = element("settings.general.idleLock")
            guard p.waitForExistence(timeout: 5) else { closeSettings(); return (false, "no picker") }
            p.click()
            let item = app.menuItems["8 hours"]
            guard item.waitForExistence(timeout: 5) else { closeSettings(); return (false, "no item") }
            item.click()
            closeSettings()
            return (true, "")
        case "waitfile":  // waitfile <name> [seconds]: driver's go signal in ctl dir
            let url = Self.ctl.appendingPathComponent(a[0])
            let deadline = Date().addingTimeInterval(Double(a.count > 1 ? a[1] : "300") ?? 300)
            while Date() < deadline {
                if FileManager.default.fileExists(atPath: url.path) { return (true, "") }
                Thread.sleep(forTimeInterval: 0.3)
            }
            return (false, "timeout")
        case "snap":
            snap(a.first ?? "snap")
            return (true, "")
        case "text":
            return (true, app.windows.firstMatch.staticTexts.allElementsBoundByIndex
                .prefix(300).map { $0.label }.joined(separator: " | "))
        default:
            return (false, "unknown verb \(verb)")
        }
    }

    private func addServer(name: String, port: String, agentOnly: Bool) -> (Bool, String) {
        tap("sidebar.fleet")
        tap("fleet.addServer")
        replace("addServer.name", name)
        replace("addServer.host", "127.0.0.1")
        replace("addServer.port", port)
        replace("addServer.user", "ops")
        tap("addServer.addConnect")
        tap("addServer.trust", 60)
        tap("addServer.chooseArtifact", 60)
        if agentOnly {
            element("addServer.security").click()
            let item = app.menuItems["Agent only (don't change security)"]
            guard item.waitForExistence(timeout: 5) else { return (false, "no Agent-only item") }
            item.click()
        }
        snap("install-\(name)")
        tap("addServer.install")
        let done = element("addServer.done"), retry = element("addServer.retry")
        let deadline = Date().addingTimeInterval(300)
        while Date() < deadline {
            if done.exists {
                let info = sheetText()
                snap("installed-\(name)")
                done.click()
                return (true, info)
            }
            if retry.exists || element("addServer.close").exists {
                let info = sheetText()
                snap("install-failed-\(name)")
                element("addServer.close").click()
                return (false, info)
            }
            Thread.sleep(forTimeInterval: 1)
        }
        snap("install-timeout-\(name)")
        return (false, "timeout: " + sheetText())
    }

    /// Onboarding "Create a new fleet", no passphrase (FleetUITestCase.createFleet).
    private func createFleet(name: String) {
        tap("onboarding.create", 30)
        let f = element("onboarding.fleetName")
        f.click(); f.typeText(name)
        tap("onboarding.continue")
        XCTAssertTrue(element("onboarding.word.1").waitForExistence(timeout: 15))
        var words: [Int: String] = [:]
        for i in 1...24 {
            let e = element("onboarding.word.\(i)")
            words[i] = (e.value as? String) ?? e.label
        }
        tap("onboarding.wroteDown")
        var i = 0
        while exists("onboarding.verify.\(i)", 5) {
            let field = element("onboarding.verify.\(i)")
            let title = field.label + " " + (field.placeholderValue ?? "")
            guard let n = title.split(whereSeparator: { !$0.isNumber })
                .compactMap({ Int($0) }).first, let w = words[n]
            else { XCTFail("can't read verify field \(i): \(title)"); return }
            field.click(); field.typeText(w)
            i += 1
        }
        tap("onboarding.check")
        tap("onboarding.createFleet")
        tap("onboarding.openFleet", 120)
        XCTAssertTrue(element("sidebar.fleet").waitForExistence(timeout: 30))
    }

    // MARK: helpers

    private func element(_ id: String) -> XCUIElement {
        app.descendants(matching: .any).matching(identifier: id).firstMatch
    }

    private func exists(_ id: String, _ t: TimeInterval) -> Bool {
        element(id).waitForExistence(timeout: t)
    }

    private func tap(_ id: String, _ t: TimeInterval = 15) {
        let e = element(id)
        XCTAssertTrue(e.waitForExistence(timeout: t), "element \(id) did not appear")
        e.click()
    }

    private func replace(_ id: String, _ text: String) {
        let e = element(id)
        XCTAssertTrue(e.waitForExistence(timeout: 15), "element \(id) did not appear")
        e.click()
        e.typeKey("a", modifierFlags: .command)
        e.typeText(text)
    }

    @discardableResult
    private func unlockIfLocked() -> Bool {
        let b = element("sidebar.lock")
        guard b.waitForExistence(timeout: 10), b.label == "Unlock" else { return false }
        // A click right after activation is sometimes dropped: retry until
        // the footer says "Lock".
        for _ in 0..<3 where b.label == "Unlock" {
            b.click()
            let deadline = Date().addingTimeInterval(4)
            while Date() < deadline, b.label == "Unlock" { Thread.sleep(forTimeInterval: 0.3) }
        }
        XCTAssertEqual(b.label, "Lock", "app did not unlock")
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
        app.typeKey(",", modifierFlags: .command)
        let b = app.toolbars.buttons["AI"]
        if b.waitForExistence(timeout: 5) { b.click() }
        _ = element("ai.pause").waitForExistence(timeout: 5)
    }

    private func closeSettings() {
        app.typeKey("w", modifierFlags: .command)
    }

    private func snap(_ name: String) {
        let a = XCTAttachment(screenshot: app.screenshot())
        a.name = name
        a.lifetime = .keepAlways
        add(a)
    }

    private var acked = ""
    private var ackURL: URL {
        URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("fl-mcp-ack")
    }

    private func ack(_ line: String) {
        acked += line.replacingOccurrences(of: "\n", with: " ") + "\n"
        try? acked.write(to: ackURL, atomically: true, encoding: .utf8)
        let a = XCTAttachment(string: line)
        a.name = "ack"
        a.lifetime = .keepAlways
        add(a)
    }
}
