import XCTest

/// Fleet overview and bulk run (package B). The populated part needs local
/// servers: the driver starts them (`tests/vm/pool.sh`), authorizes the
/// instance's `ssh_pubkey` on each, and writes `<dataDir>/go` with the ports
/// (`p1,p2,p3`). Without that file the populated tests are skipped after
/// `fleet.empty` was checked. Set `FLEET_UI_ENV_FLEET_TEST_AGENT_ARTIFACT`.
final class FleetOverviewTests: FleetUITestCase {
    private func addPoolServer(name: String, port: String, tags: String) {
        tap("fleet.addServer")
        replace("addServer.name", with: name)
        replace("addServer.host", with: "127.0.0.1")
        replace("addServer.port", with: port)
        replace("addServer.user", with: "ops")
        if exists("addServer.tags", timeout: 1) { replace("addServer.tags", with: tags) }
        tap("addServer.addConnect")
        tap("addServer.trust", timeout: 60)
        snap("add-\(name)-after-trust")
        tap("addServer.chooseArtifact", timeout: 120)
        tap("addServer.install")
        tap("addServer.done", timeout: 180)
    }

    func testOverviewAndBulkRun() throws {
        wait("onboarding.create", timeout: 30)
        createFleet(name: "Overview fleet")
        wait("fleet.empty")
        XCTAssertTrue(exists("fleet.provision"))
        XCTAssertTrue(exists("fleet.runCommand"))
        snap("01-fleet-empty")

        guard let go = waitForFile("go", timeout: 900) else {
            throw XCTSkip("no servers provided (no <dataDir>/go)")
        }
        let ports = go.split(separator: ",").map(String.init)
        for (i, p) in ports.enumerated() {
            addPoolServer(name: "srv-\(i + 1)", port: p, tags: i == 0 ? "web" : "web, docker")
        }
        wait("fleet.table")
        // Facts (updates, CPU history) and the digest load after connect.
        wait("fleet.digest", timeout: 120)
        Thread.sleep(forTimeInterval: 20)
        snap("02-fleet-overview")
        XCTAssertTrue(exists("fleet.card.security"))
        XCTAssertTrue(exists("fleet.card.reboot"))

        // Bulk run from the header.
        tap("fleet.runCommand")
        wait("bulk.run")
        wait("bulk.saveRunbook")
        wait("bulk.runType")
        wait("bulk.targets.tag.docker")
        snap("03-bulk-form")

        tap("bulk.dryRun")
        wait("bulk.dryResult", timeout: 120)
        snap("04-bulk-dry-run")
        tap("bulk.viewPlan")
        snap("05-bulk-plan")
        tap("bulk.plan.close")

        tap("bulk.run")
        tap("bulk.confirmRun")
        wait("bulk.summary", timeout: 240)
        snap("06-bulk-done")
        XCTAssertTrue(exists("bulk.state"))
        tap("bulk.close")
    }
}
