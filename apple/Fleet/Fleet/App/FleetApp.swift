import SwiftUI

@main
struct FleetApp: App {
    @State private var core = CoreBridge()
    @State private var lock: AppLock
    @State private var paletteShown = false
    private let gate: KeyGate

    init() {
        let gate = KeyGate()
        self.gate = gate
        _lock = State(initialValue: AppLock(gate: gate))
    }

    var body: some Scene {
        Window("Fleet", id: "main") {
            ContentView(paletteShown: $paletteShown)
                .environment(core)
                .environment(lock)
                .preferredColorScheme(.dark)
                .task { start() }
        }
        .commands {
            CommandGroup(after: .newItem) {
                Button("Command Palette…") { paletteShown.toggle() }
                    .keyboardShortcut("k")
                Button(lock.isLocked ? "Unlock" : "Lock") {
                    if lock.isLocked { Task { await lock.unlock() } } else { lock.lock() }
                }
                .keyboardShortcut("l", modifiers: [.command, .control])
            }
        }

        Settings {
            SettingsView()
                .environment(core)
                .environment(lock)
        }

        MenuBarExtra {
            MenuBarView()
                .environment(core)
                .environment(lock)
        } label: {
            MenuBarLabel()
                .environment(core)
        }
    }

    /// Opens the core once. Starts locked (monitor key) per design §5.10.
    private func start() {
        guard core.status == .starting else { return }
        lock.onChange = { [core] locked in core.setLocked(locked) }
        lock.install()
        do {
            let keys = try SecureEnclaveKeys(gate: gate)
            core.open(keys: keys, keyStore: NoiseKeyStore())
        } catch {
            core.fail("No Secure Enclave. Set FLEET_SOFTWARE_KEYS=1 for development.")
        }
    }
}
