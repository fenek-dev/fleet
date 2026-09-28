import XCTest

/// Server header and Overview against a real pool server with the agent
/// installed. Needs Docker, the pool (`tests/vm/pool.sh`) and an agent
/// binary: `FLEET_UI_ENV_FLEET_TEST_AGENT_ARTIFACT=<path>` (defaults to
/// `target/linux/aarch64/fleet-agent` of the checkout).
final class ServerHeaderTests: FleetUITestCase {
    private var poolName: String?
    private var root: URL {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
    }

    override func setUpWithError() throws {
        let env = ProcessInfo.processInfo.environment
        if env["FLEET_UI_ENV_FLEET_TEST_AGENT_ARTIFACT"] == nil {
            extraEnvironment["FLEET_TEST_AGENT_ARTIFACT"] =
                root.appendingPathComponent("target/linux/aarch64/fleet-agent").path
        }
        try super.setUpWithError()
    }

    override func tearDownWithError() throws {
        if let poolName { _ = try? sh("tests/vm/pool.sh", "down", poolName) }
        try super.tearDownWithError()
    }

    private func sh(_ args: String...) throws -> String {
        let p = Process()
        p.executableURL = root.appendingPathComponent(args[0])
        p.arguments = Array(args.dropFirst())
        p.currentDirectoryURL = root
        var e = ProcessInfo.processInfo.environment
        e["PATH"] = "/usr/local/bin:/opt/homebrew/bin:" + (e["PATH"] ?? "")
        p.environment = e
        let out = Pipe()
        p.standardOutput = out
        try p.run()
        p.waitUntilExit()
        return String(decoding: out.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
    }

    func testHeaderAndOverview() throws {
        wait("onboarding.create", timeout: 30)
        createFleet(name: "Header fleet")
        let key = try XCTUnwrap(waitForFile("ssh_pubkey"))
        _ = key

        let json = try sh("tests/vm/pool.sh", "up", "1", "debian12",
                          "--key", dataDir.appendingPathComponent("ssh_pubkey").path, "--json")
        let rows = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(json.utf8)) as? [[String: Any]])
        let row = try XCTUnwrap(rows.first)
        let name = try XCTUnwrap(row["name"] as? String)
        poolName = name
        let port = try XCTUnwrap(row["port"] as? Int)

        tap("fleet.addServer")
        replace("addServer.name", with: "web-04")
        replace("addServer.host", with: "127.0.0.1")
        replace("addServer.port", with: "\(port)")
        replace("addServer.user", with: "ops")
        tap("addServer.addConnect")
        tap("addServer.trust", timeout: 60)
        tap("addServer.chooseArtifact")
        tap("addServer.install")
        tap("addServer.done", timeout: 240)

        sidebar("server.web-04")
        wait("server.name")
        wait("server.crumb.fleet")
        wait("server.facts")
        XCTAssertTrue(element("server.facts").label.contains("127.0.0.1"), element("server.facts").label)
        wait("overview.timeline")
        wait("overview.containers")
        wait("overview.profile")
        wait("overview.metric.Disk I/O")
        wait("overview.metric.Network")
        // Hardening score arrives.
        let score = wait("overview.profile.score", timeout: 60)
        snap("overview-24h")

        tap("overview.range.7d")
        sleep(2)
        snap("overview-7d")
        tap("overview.range.1h")

        tap("server.runCommand")
        wait("bulk.operation")
        snap("run-command-sheet")
        app.typeKey(.escape, modifierFlags: [])

        tap("serverTab.more")
        snap("more-menu")
        app.typeKey(.escape, modifierFlags: [])

        tap("overview.profile.score")
        wait("serverTab.security")
        _ = score
        serverTab("overview")
        tap("overview.timeline.viewAll")
        snap("timeline-tab")

        tap("server.crumb.fleet")
        wait("fleet.addServer")
    }
}
