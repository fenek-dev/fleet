import CryptoKit
import Foundation
import LocalAuthentication
import Security
import Synchronization

/// The app-unlock authentication (design §5.10), shared between `AppLock`
/// (main actor) and the signer (core thread). While unlocked it holds the
/// `LAContext` Touch ID evaluated at unlock; device and SSH keys sign with
/// it as their `authenticationContext`. Locking invalidates it, so those
/// keys stop working even if something still holds a reference.
final class KeyGate: Sendable {
    private struct Box: @unchecked Sendable { var context: LAContext? }
    private let state = Mutex(Box(context: nil))

    var isUnlocked: Bool { state.withLock { $0.context != nil } }

    /// The evaluated unlock context, if unlocked.
    var context: LAContext? { state.withLock { $0.context } }

    func unlock(with context: LAContext) {
        state.withLock { $0.context = context }
    }

    func lock() {
        let old = state.withLock { s -> LAContext? in
            let c = s.context
            s.context = nil
            return c
        }
        old?.invalidate()
    }
}

/// The Mac's P-256 keys (design §5.2), implementing the FFI `DeviceSigner`.
///
/// - Root: Secure Enclave, `.privateKeyUsage` + `.biometryCurrentSet`.
///   Never cached: every signature builds the key from its enclave blob
///   with a fresh `LAContext` whose prompt names the operation and server
///   count (`reason`, from Rust), signs, and invalidates the context.
/// - Device, SSH: Secure Enclave, `.privateKeyUsage` + `.userPresence`,
///   signing with the unlock context (`KeyGate`); unusable once locked.
///   **Migration:** keys created before this ACL keep `.privateKeyUsage`
///   only (still gated by `KeyGate` in software); new enrollments get the
///   new ACL. Moving an existing Mac over means new keys and a roster
///   update (design §5.12), not done automatically.
/// - Monitor, monitor SSH: Secure Enclave, `.privateKeyUsage`; usable while
///   locked. The monitor SSH key authenticates only the read-only monitor
///   bridge (`authorized_keys` forces `bridge --monitor`), so a locked app
///   keeps metrics and alerts without the unlock-gated SSH key.
///
/// Each key's `dataRepresentation` (an enclave-wrapped blob) is kept in the
/// Keychain. Keys are created only while `creationAllowed` (enrollment);
/// afterwards a missing key is `SignerError.Missing` — never silently
/// replaced, since the roster lists the old one. Signatures are raw `r‖s`
/// (64 bytes); Rust normalizes low-S.
///
/// **Software fallback (DEBUG builds only):** when the Secure Enclave is
/// unavailable (VMs, CI) *and* `FLEET_SOFTWARE_KEYS=1` is set, keys are
/// plain CryptoKit P-256 keys in the Keychain. Release builds refuse.
final class SecureEnclaveKeys: DeviceSigner {
    enum Backend: Sendable { case secureEnclave, software }

    let backend: Backend
    private let gate: KeyGate
    /// Public keys only; private key handles are never kept.
    private let publics = Mutex<[KeyRole: Data]>([:])
    private let creation = Mutex(false)

    enum Unavailable: Error { case noSecureEnclave }

    init(gate: KeyGate, environment: [String: String] = ProcessInfo.processInfo.environment) throws {
        self.gate = gate
        if SecureEnclave.isAvailable {
            backend = .secureEnclave
        } else {
            #if DEBUG
            guard environment["FLEET_SOFTWARE_KEYS"] == "1" else { throw Unavailable.noSecureEnclave }
            backend = .software
            #else
            throw Unavailable.noSecureEnclave
            #endif
        }
    }

    var usesSoftwareKeys: Bool { backend == .software }

    /// Whether missing keys may be generated: only before enrollment.
    var creationAllowed: Bool {
        get { creation.withLock { $0 } }
        set { creation.withLock { $0 = newValue } }
    }

    // MARK: DeviceSigner

    func publicKey(role: KeyRole) throws -> Data {
        if let p = publics.withLock({ $0[role] }) { return p }
        let ctx = Self.silentContext()
        defer { ctx.invalidate() }
        let p = try withKey(role, context: ctx) { key -> Data in
            switch key {
            case .enclave(let k): return k.publicKey.compressedRepresentation
            case .software(let k): return k.publicKey.compressedRepresentation
            }
        }
        publics.withLock { $0[role] = p }
        return p
    }

    func sign(role: KeyRole, msg: Data, reason: String) throws -> Data {
        switch role {
        case .root:
            return try signRoot(msg: msg, reason: reason)
        case .device, .ssh:
            guard let ctx = gate.context else { throw SignerError.Unavailable }
            return try signWith(role, context: ctx, msg: msg)
        case .monitor, .monitorSsh:
            let ctx = Self.silentContext()
            defer { ctx.invalidate() }
            return try signWith(role, context: ctx, msg: msg)
        }
    }

    // MARK: Signing

    private func signRoot(msg: Data, reason: String) throws -> Data {
        let ctx = LAContext()
        defer { ctx.invalidate() }
        ctx.localizedCancelTitle = "Don't approve"
        ctx.localizedReason = reason.isEmpty ? "approve a Fleet change" : reason
        if backend == .secureEnclave {
            var err: NSError?
            if !ctx.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &err) {
                if (err as? LAError)?.code == .biometryNotEnrolled { throw SignerError.Invalidated }
            }
            if let enrolled = try? Keychain.load(Self.biometryAccount),
               let now = Self.biometryState(ctx), enrolled != now
            {
                // Fingerprints were added or removed: `.biometryCurrentSet`
                // has invalidated the root key (design §5.2).
                throw SignerError.Invalidated
            }
        }
        return try signWith(.root, context: ctx, msg: msg)
    }

    private func signWith(_ role: KeyRole, context: LAContext, msg: Data) throws -> Data {
        do {
            return try withKey(role, context: context) { key -> Data in
                switch key {
                case .enclave(let k): return try k.signature(for: msg).rawRepresentation
                case .software(let k): return try k.signature(for: msg).rawRepresentation
                }
            }
        } catch let e as SignerError {
            throw e
        } catch let error as LAError {
            switch error.code {
            case .userCancel, .appCancel, .systemCancel, .authenticationFailed, .userFallback:
                throw SignerError.Cancelled
            case .biometryNotEnrolled, .biometryNotAvailable:
                throw role == .root ? SignerError.Invalidated : SignerError.Unavailable
            case .notInteractive, .invalidContext:
                throw SignerError.Unavailable
            default:
                throw SignerError.Failed
            }
        } catch {
            throw SignerError.Failed
        }
    }

    // MARK: Keys

    private enum Key {
        case enclave(SecureEnclave.P256.Signing.PrivateKey)
        case software(P256.Signing.PrivateKey)
    }

    private static let biometryAccount = "root-biometry-state"

    private static func account(_ role: KeyRole) -> String {
        switch role {
        case .root: "p256-root"
        case .device: "p256-device"
        case .monitor: "p256-monitor"
        case .monitorSsh: "p256-monitor-ssh"
        case .ssh: "p256-ssh"
        }
    }

    /// Builds `role`'s key bound to `context`, runs `f`, and lets the key
    /// go (it is never stored).
    private func withKey<T>(_ role: KeyRole, context: LAContext, _ f: (Key) throws -> T) throws -> T {
        let account = Self.account(role) + (backend == .software ? "-sw" : "")
        let stored: Data?
        do { stored = try Keychain.load(account) } catch { throw SignerError.Unavailable }
        let key: Key
        do {
            switch backend {
            case .secureEnclave:
                if let blob = stored {
                    key = .enclave(try SecureEnclave.P256.Signing.PrivateKey(
                        dataRepresentation: blob, authenticationContext: context))
                } else {
                    // The monitor SSH key is new for enrolled Macs: create it
                    // on first use (it only authenticates the read-only
                    // monitor bridge, and servers accept it once a roster
                    // lists it).
                    guard creationAllowed || role == .monitorSsh else { throw SignerError.Missing }
                    let k = try SecureEnclave.P256.Signing.PrivateKey(
                        compactRepresentable: false,
                        accessControl: try Self.accessControl(role),
                        authenticationContext: context)
                    try Keychain.add(account, k.dataRepresentation)
                    if role == .root, let state = Self.biometryState(LAContext()) {
                        try? Keychain.delete(Self.biometryAccount)
                        try? Keychain.add(Self.biometryAccount, state)
                    }
                    key = .enclave(k)
                }
            case .software:
                if let raw = stored {
                    key = .software(try P256.Signing.PrivateKey(rawRepresentation: raw))
                } else {
                    guard creationAllowed || role == .monitorSsh else { throw SignerError.Missing }
                    let k = P256.Signing.PrivateKey(compactRepresentable: false)
                    try Keychain.add(account, k.rawRepresentation)
                    key = .software(k)
                }
            }
        } catch let e as SignerError {
            throw e
        } catch {
            // The blob exists but the enclave won't load it: invalidated
            // (root after a fingerprint change) rather than cancelled.
            throw role == .root && stored != nil ? SignerError.Invalidated : SignerError.Failed
        }
        return try f(key)
    }

    /// Never prompts (public keys, monitor key).
    private static func silentContext() -> LAContext {
        let ctx = LAContext()
        ctx.interactionNotAllowed = true
        return ctx
    }

    /// Fingerprint set identifier (changes when fingerprints change).
    private static func biometryState(_ ctx: LAContext) -> Data? {
        var err: NSError?
        _ = ctx.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &err)
        return ctx.domainState.biometry.stateHash
    }

    private static func accessControl(_ role: KeyRole) throws -> SecAccessControl {
        var flags: SecAccessControlCreateFlags = [.privateKeyUsage]
        switch role {
        case .root: flags.insert(.biometryCurrentSet)
        case .device, .ssh: flags.insert(.userPresence)
        case .monitor, .monitorSsh: break
        }
        var error: Unmanaged<CFError>?
        guard let ac = SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, flags, &error)
        else {
            throw SignerError.Failed
        }
        return ac
    }
}
