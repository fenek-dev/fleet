import XCTest

/// Server header and Overview against a real pool server with the agent
/// installed. The runner is sandboxed (no Docker), so a host-side helper
/// provides the server: it waits for `/tmp/fl-hdr/ssh_pubkey`, runs
/// `tests/vm/pool.sh up 1 debian12 --key … --json` and writes the result
/// to `/tmp/fl-hdr-pool.json`. The agent binary comes from
/// `FLEET_UI_ENV_FLEET_TEST_AGENT_ARTIFACT`.
final class ServerHeaderTests: FleetUITestCase {
    static let dir = "/tmp/fl-hdr"
    static let poolFile = "/tmp/fl-hdr-pool.json"

    override func setUpWithError() throws {
        extraEnvironment["FLEET_DATA_DIR"] = Self.dir
        try super.setUpWithError()
    }

    private func poolServer() throws -> (name: String, port: Int) {
        let deadline = Date().addingTimeInterval(180)
        while Date() < deadline {
            if let d = FileManager.default.contents(atPath: Self.poolFile),
               let rows = try? JSONSerialization.jsonObject(with: d) as? [[String: Any]],
               let r = rows.first, let n = r["name"] as? String, let p = r["port"] as? Int {
                return (n, p)
            }
            Thread.sleep(forTimeInterval: 1)
        }
        throw XCTSkip("no pool server (\(Self.poolFile))")
    }

    func testHeaderAndOverview() throws {
        wait("onboarding.create", timeout: 30)
        createFleet(name: "Header fleet")
        let pool = try poolServer()

        tap("fleet.addServer")
        replace("addServer.name", with: "web-04")
        replace("addServer.host", with: "127.0.0.1")
        replace("addServer.port", with: "\(pool.port)")
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
        wait("overview.profile.score", timeout: 60)
        sleep(3)
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
        snap("security-tab")
        serverTab("overview")
        tap("overview.timeline.viewAll")
        snap("timeline-tab")

        tap("server.crumb.fleet")
        wait("fleet.addServer")
    }
}
