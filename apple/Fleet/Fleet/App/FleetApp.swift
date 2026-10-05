import SwiftUI

@main
struct FleetApp: App {
    @State private var core = CoreBridge()
    @State private var terminals = TerminalStore()
    @State private var intel = IntelStore()
    @State private var lock: AppLock
    @State private var paletteShown = false
    @State private var ai = AIModel()
    @State private var scheduler = RunbookScheduler()
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
                .environment(terminals)
                .environment(lock)
                .environment(ai)
                .environment(intel)
                .preferredColorScheme(.dark)
                .task { start() }
                .onChange(of: core.status, initial: true) { startServices() }
        }
        .windowStyle(.hiddenTitleBar)
        .commands {
            // Settings is a screen of the main window, not a separate scene.
            CommandGroup(replacing: .appSettings) {
                Button("Settings…") {
                    NotificationCenter.default.post(name: .openSettings, object: nil)
                }
                .keyboardShortcut(",")
            }
            CommandGroup(after: .newItem) {
                Button("Command Palette…") { paletteShown.toggle() }
                    .keyboardShortcut("k")
                // ⌘F stays the standard Find of logs, terminal and files.
                Button("Fleet Search…") {
                    NotificationCenter.default.post(name: .fleetSearch, object: nil)
                }
                .keyboardShortcut("f", modifiers: [.command, .shift])
                Button(lock.isLocked ? "Unlock" : "Lock") {
                    if lock.isLocked { Task { await lock.unlock() } } else { lock.lock() }
                }
                .keyboardShortcut("l", modifiers: [.command, .control])
            }
        }

        MenuBarExtra {
            MenuBarView()
                .environment(core)
                .environment(lock)
                .environment(ai)
        } label: {
            MenuBarLabel()
                .environment(core)
        }
    }

    /// MCP socket and the runbook scheduler, once the manager runs.
    private func startServices() {
        guard core.status == .running, let api = core.api else { return }
        ai.start(core: api)
        scheduler.start(core: api) { [lock] in lock.isLocked }
    }

    /// Opens the core once. Starts locked (monitor key) per design §5.10.
    private func start() {
        guard core.status == .starting else { return }
        lock.onChange = { [core] locked in core.setLocked(locked) }
        lock.install()
        switch Keychain.startupChoice() {
        case .refuse(let r):
            core.fail(Keychain.refusalMessage(r))
        case .fallback:
            // Ad-hoc build: the Noise and cache keys are sealed to the
            // Secure Enclave with user presence (design §5.2 "Unsigned
            // builds"). Open them once with the first unlock's Touch ID;
            // the core opens after that.
            core.awaitingFirstUnlock = true
            lock.onUnlocked = { [core] ctx in
                guard core.awaitingFirstUnlock else { return }
                do {
                    try LocalKeyStore.unlockSecrets(context: ctx)
                } catch {
                    core.fail("Could not open Fleet's keys with the Secure Enclave. Unlock again.")
                    return
                }
                core.awaitingFirstUnlock = false
                openCore()
            }
        default:
            openCore()
        }
    }

    private func openCore() {
        do {
            let keys = try SecureEnclaveKeys(gate: gate)
            core.open(keys: keys, keyStore: NoiseKeyStore())
            intel.open()
            intel.startPeriodicScans(core)
        } catch {
            core.fail("No Secure Enclave. Set FLEET_SOFTWARE_KEYS=1 for development.")
        }
    }
}
