import XCTest

/// Terminal (mixed tabs, broadcast, recording), Files (detail bar, item
/// counts) and the Provision wizard against two real pool servers.
///
/// Needs a two-step launch because the runner can't authorize the app's
/// SSH key itself: the test creates the fleet in a fixed data dir, then
/// waits for `<dir>/pool.json` (`{"ports":[p1,p2]}`, written by whoever
/// runs `tests/vm/pool.sh up 2 --key <dir>/ssh_pubkey`), and needs
/// `FLEET_UI_ENV_FLEET_TEST_AGENT_ARTIFACT` for the agent install.
final class PackageETests: FleetUITestCase {
    static let dir = "/tmp/fl-e"

    override func setUpWithError() throws {
        extraEnvironment["FLEET_DATA_DIR"] = Self.dir
        try super.setUpWithError()
    }

    private var dataURL: URL { URL(fileURLWithPath: Self.dir, isDirectory: true) }

    private func addServer(_ name: String, port: Int) {
        tap("sidebar.fleet")
        tap("fleet.addServer")
        replace("addServer.name", with: name)
        replace("addServer.host", with: "127.0.0.1")
        replace("addServer.port", with: String(port))
        replace("addServer.user", with: "ops")
        tap("addServer.addConnect")
        tap("addServer.trust", timeout: 60)
        tap("addServer.chooseArtifact")
        tap("addServer.install")
        wait("addServer.done", timeout: 180)
        tap("addServer.done")
    }

    func testTerminalFilesProvision() throws {
        createFleet()
        _ = waitForFile("pool.json", timeout: 600)
        let raw = try String(contentsOf: dataURL.appendingPathComponent("pool.json"), encoding: .utf8)
        let ports = raw.components(separatedBy: CharacterSet.decimalDigits.inverted)
            .compactMap { Int($0) }.filter { $0 > 1024 }
        XCTAssertGreaterThanOrEqual(ports.count, 2)
        addServer("srv-a", port: ports[0])
        addServer("srv-b", port: ports[1])

        // Terminal: one tab per server, both visible in one tab bar.
        sidebar("server.srv-a")
        serverTab("terminal")
        tap("terminal.new")
        sidebar("server.srv-b")
        serverTab("terminal")
        tap("terminal.new")
        XCTAssertEqual(app.descendants(matching: .any).matching(identifier: "terminal.tab").count, 2)
        XCTAssertTrue(exists("terminal.size", timeout: 20))
        snap("terminal-two-tabs")

        // Record both sessions (local files), then broadcast.
        tap("terminal.record")
        wait("terminal.recordingFile")
        snap("terminal-recording")
        tap("terminal.broadcast")
        tap("terminal.broadcastConfirm")
        wait("terminal.broadcastBanner")
        snap("terminal-broadcast")
        app.typeText("echo bcast-marker-7431\n")
        Thread.sleep(forTimeInterval: 3)
        tap("terminal.broadcast")
        XCTAssertFalse(exists("terminal.broadcastBanner", timeout: 2))

        let rec = dataURL.appendingPathComponent("recordings")
        let files = (try? FileManager.default.contentsOfDirectory(atPath: rec.path)) ?? []
        XCTAssertFalse(files.isEmpty, "no recording written")
        let text = files.compactMap { try? String(contentsOf: rec.appendingPathComponent($0), encoding: .utf8) }
            .joined()
        XCTAssertTrue(text.contains("bcast-marker-7431"))
        tap("terminal.record")

        // Files.
        serverTab("files")
        wait("files.sftpBadge")
        Thread.sleep(forTimeInterval: 3)
        snap("files")

        // Provision.
        sidebar("provisioning")
        wait("provision.server")
        snap("provision-connect")
    }
}
