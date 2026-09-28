import XCTest

final class SmokeTests: FleetUITestCase {
    /// Launch -> onboarding -> create fleet -> main window shows.
    func testLaunchCreateFleetShowsMainWindow() throws {
        wait("onboarding.create", timeout: 30)
        snap("onboarding")

        createFleet(name: "Smoke fleet")
        snap("main-window")

        // Main window: sidebar navigation works.
        sidebar("alerts")
        wait("alerts.empty")
        sidebar("fleet")

        // The root-key signature for the genesis roster was auto-approved
        // and logged; keys were exported for the tester.
        XCTAssertTrue(approvalsLog.contains("TEST-APPROVE"), "approvals.log: \(approvalsLog)")
        let key = waitForFile("ssh_pubkey")
        XCTAssertTrue(key?.hasPrefix("ecdsa-sha2-nistp256 ") == true, "ssh_pubkey: \(key ?? "nil")")
        XCTAssertNotNil(waitForFile("monitor_ssh_pubkey"))
    }
}
