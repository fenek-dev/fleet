import XCTest

/// Base class for end-to-end UI tests of the real app (Debug build).
///
/// Each test launches the app with a fresh data directory and the test
/// signer, so nothing touches the Keychain, Touch ID or the operator's own
/// Fleet data. See apple/Fleet/TESTING.md.
///
/// Environment (read from the test runner's process):
/// - `FLEET_UI_KEEP_DATA=1`: keep the data directory after the test.
/// - `FLEET_UI_ENV_*`: forwarded to the app minus the `FLEET_UI_ENV_`
///   prefix (e.g. `FLEET_UI_ENV_FLEET_TEST_AGENT_ARTIFACT=/path/agent`).
class FleetUITestCase: XCTestCase {
    var app: XCUIApplication!
    /// The app instance's `FLEET_DATA_DIR`. Short on purpose: it holds a
    /// Unix socket (`mcp.sock`), and socket paths are limited to ~100 bytes.
    private(set) var dataDir: URL!
    /// Extra launch environment; set in `setUp` overrides before `super`.
    var extraEnvironment: [String: String] = [:]

    override func setUpWithError() throws {
        continueAfterFailure = false
        let id = UUID().uuidString.prefix(8)
        dataDir = URL(fileURLWithPath: "/tmp/fleet-ui-\(id)", isDirectory: true)
        try FileManager.default.createDirectory(at: dataDir, withIntermediateDirectories: true)

        app = XCUIApplication()
        app.launchEnvironment["FLEET_DATA_DIR"] = dataDir.path
        app.launchEnvironment["FLEET_TEST_SIGNER"] = "1"
        let prefix = "FLEET_UI_ENV_"
        for (k, v) in ProcessInfo.processInfo.environment where k.hasPrefix(prefix) {
            app.launchEnvironment[String(k.dropFirst(prefix.count))] = v
        }
        for (k, v) in extraEnvironment { app.launchEnvironment[k] = v }
        app.launch()
    }

    override func tearDownWithError() throws {
        if let app, app.state != .notRunning {
            snap("teardown")
            app.terminate()
        }
        if ProcessInfo.processInfo.environment["FLEET_UI_KEEP_DATA"] != "1", let dataDir {
            try? FileManager.default.removeItem(at: dataDir)
        }
    }

    // MARK: elements

    /// Any element with this accessibility identifier.
    func element(_ id: String) -> XCUIElement {
        app.descendants(matching: .any).matching(identifier: id).firstMatch
    }

    @discardableResult
    func wait(_ id: String, timeout: TimeInterval = 15,
              file: StaticString = #filePath, line: UInt = #line) -> XCUIElement {
        let e = element(id)
        XCTAssertTrue(e.waitForExistence(timeout: timeout),
                      "element \(id) did not appear", file: file, line: line)
        return e
    }

    func exists(_ id: String, timeout: TimeInterval = 2) -> Bool {
        element(id).waitForExistence(timeout: timeout)
    }

    func tap(_ id: String, timeout: TimeInterval = 15,
             file: StaticString = #filePath, line: UInt = #line) {
        wait(id, timeout: timeout, file: file, line: line).click()
    }

    func type(_ id: String, _ text: String, timeout: TimeInterval = 15,
              file: StaticString = #filePath, line: UInt = #line) {
        let e = wait(id, timeout: timeout, file: file, line: line)
        e.click()
        e.typeText(text)
    }

    /// Replaces a text field's contents.
    func replace(_ id: String, with text: String) {
        let e = wait(id)
        e.click()
        e.typeKey("a", modifierFlags: .command)
        e.typeText(text)
    }

    // MARK: navigation

    /// Sidebar items: `fleet`, `alerts`, `timeline`, `search`,
    /// `vulnerabilities`, `runbooks`, `provisioning`, `server.<name>`,
    /// `group.<name>`.
    func sidebar(_ item: String) {
        tap("sidebar.\(item)")
    }

    /// Server detail tabs: `overview`, `terminal`, `files`, `logs`,
    /// `security`, `users`, `services`, `firewall`, `packages`, `docker`,
    /// `cron`, `config`, `mesh`, `games`, `timeline`.
    func serverTab(_ tab: String) {
        tap("serverTab.\(tab)")
    }

    func openCommandPalette() {
        tap("sidebar.palette")
    }

    func openSettings() {
        app.typeKey(",", modifierFlags: .command)
    }

    // MARK: evidence

    /// Full-screen-of-the-app screenshot, kept in the result bundle.
    func snap(_ name: String) {
        let a = XCTAttachment(screenshot: app.screenshot())
        a.name = name
        a.lifetime = .keepAlways
        add(a)
    }

    // MARK: test-hook files

    var approvalsLog: String {
        (try? String(contentsOf: dataDir.appendingPathComponent("approvals.log"), encoding: .utf8)) ?? ""
    }

    func waitForFile(_ name: String, timeout: TimeInterval = 20) -> String? {
        let url = dataDir.appendingPathComponent(name)
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if let s = try? String(contentsOf: url, encoding: .utf8), !s.isEmpty {
                return s.trimmingCharacters(in: .whitespacesAndNewlines)
            }
            Thread.sleep(forTimeInterval: 0.5)
        }
        return nil
    }

    // MARK: flows

    /// Onboarding "Create a new fleet" with no passphrase; ends with the
    /// main window showing. Returns after the sidebar appears.
    func createFleet(name: String = "Test fleet", passphrase: String = "") {
        tap("onboarding.create")
        type("onboarding.fleetName", name)
        tap("onboarding.continue")

        // Recovery words: read them from the screen, then re-type the
        // four the app asks for.
        wait("onboarding.word.1")
        var words: [Int: String] = [:]
        for i in 1...24 {
            let e = element("onboarding.word.\(i)")
            words[i] = (e.value as? String) ?? e.label
        }
        tap("onboarding.wroteDown")

        var i = 0
        while exists("onboarding.verify.\(i)", timeout: 5) {
            let field = element("onboarding.verify.\(i)")
            let title = field.label + " " + (field.placeholderValue ?? "")
            guard let n = title.split(whereSeparator: { !$0.isNumber })
                .compactMap({ Int($0) }).first, let w = words[n]
            else {
                XCTFail("can't read verify field \(i): \(title)")
                return
            }
            field.click()
            field.typeText(w)
            i += 1
        }
        tap("onboarding.check")

        if !passphrase.isEmpty {
            type("onboarding.passphrase", passphrase)
            type("onboarding.passphraseAgain", passphrase)
        }
        tap("onboarding.createFleet")
        tap("onboarding.openFleet", timeout: 120)
        wait("sidebar.fleet", timeout: 30)
    }
}
