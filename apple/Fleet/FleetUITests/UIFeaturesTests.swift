import XCTest

/// P3 UI features that need no server: groups from the sidebar, palette
/// actions, agent rollback section, per-screen window title.
final class UIFeaturesTests: FleetUITestCase {
    func testGroupsPaletteAndRollbackSection() throws {
        wait("onboarding.create", timeout: 30)
        createFleet(name: "P3 fleet")

        // FLT-2: create a group from the sidebar.
        tap("sidebar.newGroup")
        replace("group.name", with: "Production")
        tap("group.save")
        wait("sidebar.group.Production")
        snap("p3-01-group-created")

        // FLT-4: the palette reaches Add server, Add Mac, cloud-init, Sync now, New group.
        openCommandPalette()
        wait("palette.query")
        // The list is lazy and scrolls: filter to each item.
        let items = [("add server", "add.server"), ("add a mac", "add.mac"),
                     ("cloud-init", "cloudinit"), ("sync now", "sync.now"),
                     ("new group", "group.new"), ("roll back", "releases")]
        for (query, id) in items {
            replace("palette.query", with: query)
            XCTAssertTrue(exists("palette.item.\(id)"), "palette item \(id) missing")
        }
        replace("palette.query", with: "add server")
        tap("palette.item.add.server")
        wait("addServer.title")
        app.typeKey(.escape, modifierFlags: [])

        // FLT-1: the rollback control sits in Settings → Agent releases.
        tap("sidebar.settings")
        tap("settings.nav.releases")
        wait("releases.rollback")
        XCTAssertFalse(element("releases.rollback").isEnabled, "no server chosen yet")
        snap("p3-02-releases-rollback")

        // OPS-10: the window title follows the screen.
        XCTAssertTrue(app.windows["Settings"].waitForExistence(timeout: 5))
    }
}
