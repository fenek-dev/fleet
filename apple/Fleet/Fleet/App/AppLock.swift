import AppKit
import LocalAuthentication
import Observation

/// App lock (design §5.10): locked on launch, on sleep/screen sleep, screen
/// lock or screensaver, and after 15 minutes without operator input.
/// Unlocking takes Touch ID; its evaluated context is what device and SSH
/// keys sign with (`KeyGate`).
/// Locking switches every session to the monitor key; unlocking to the
/// device key.
@Observable
@MainActor
final class AppLock {
    static let defaultIdle: Duration = .seconds(15 * 60)
    static let maxIdle: Duration = .seconds(8 * 60 * 60)

    private(set) var isLocked = true
    private(set) var lastError: String?
    private(set) var lastActivity = ContinuousClock.now
    private(set) var idleLimit: Duration = AppLock.defaultIdle

    /// Clamped to 1 minute … 8 hours.
    func setIdleLimit(_ d: Duration) {
        idleLimit = min(max(d, .seconds(60)), Self.maxIdle)
    }

    /// Called with the new state; `CoreBridge` switches the session kind.
    var onChange: ((_ locked: Bool) -> Void)?

    let gate: KeyGate
    @ObservationIgnored private var observers: [NSObjectProtocol] = []
    @ObservationIgnored private var eventMonitor: Any?
    @ObservationIgnored private var idleTask: Task<Void, Never>?

    init(gate: KeyGate) {
        self.gate = gate
    }

    /// Starts watching sleep and operator activity. Call once.
    func install() {
        let ws = NSWorkspace.shared.notificationCenter
        for name in [NSWorkspace.willSleepNotification, NSWorkspace.screensDidSleepNotification,
                     NSWorkspace.sessionDidResignActiveNotification] {
            observers.append(ws.addObserver(forName: name, object: nil, queue: .main) { [weak self] _ in
                MainActor.assumeIsolated { self?.lock() }
            })
        }
        // Screen locked (⌃⌘Q, hot corner) or screensaver started: the Mac
        // is unattended even without sleeping.
        let dist = DistributedNotificationCenter.default()
        for name in ["com.apple.screenIsLocked", "com.apple.screensaver.didstart"] {
            observers.append(dist.addObserver(forName: Notification.Name(name), object: nil,
                                              queue: .main) { [weak self] _ in
                MainActor.assumeIsolated { self?.lock() }
            })
        }
        // Operator input only; AI (MCP) activity never resets the timer.
        eventMonitor = NSEvent.addLocalMonitorForEvents(
            matching: [.keyDown, .leftMouseDown, .rightMouseDown, .scrollWheel]
        ) { [weak self] event in
            MainActor.assumeIsolated { self?.lastActivity = .now }
            return event
        }
        idleTask = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(30))
                guard let self else { return }
                if !self.isLocked && ContinuousClock.now - self.lastActivity >= self.idleLimit {
                    self.lock()
                }
            }
        }
    }

    /// Remaining time before the idle lock, for the sidebar footer.
    var remaining: Duration {
        max(.zero, idleLimit - (ContinuousClock.now - lastActivity))
    }

    func lock() {
        // Invalidating the unlock context makes the device and SSH keys
        // unusable at once (their ACL needs it).
        gate.lock()
        guard !isLocked else { return }
        isLocked = true
        onChange?(true)
    }

    func unlock() async {
        let ctx = LAContext()
        ctx.localizedCancelTitle = "Stay locked"
        var err: NSError?
        guard ctx.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &err) else {
            lastError = err?.localizedDescription ?? "Touch ID unavailable"
            return
        }
        do {
            try await ctx.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics,
                                         localizedReason: "unlock Fleet")
        } catch {
            lastError = (error as? LAError)?.code == .userCancel ? nil : error.localizedDescription
            return
        }
        lastError = nil
        lastActivity = .now
        gate.unlock(with: ctx)
        isLocked = false
        onChange?(false)
    }
}
