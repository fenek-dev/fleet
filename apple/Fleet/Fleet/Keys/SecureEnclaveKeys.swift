import CryptoKit
import Foundation
import LocalAuthentication
import Security
import Synchronization

/// Whether the device and SSH keys may be used (app unlocked). Shared
/// between `AppLock` (main actor) and the signer (core thread).
final class KeyGate: Sendable {
    private let unlocked = Mutex(false)

    var isUnlocked: Bool { unlocked.withLock { $0 } }
    func set(unlocked value: Bool) { unlocked.withLock { $0 = value } }
}

/// The Mac's P-256 keys (design §5.2), implementing the FFI `DeviceSigner`.
///
/// - Root: Secure Enclave, `.privateKeyUsage` + `.biometryCurrentSet`,
///   Touch ID on every signature.
/// - Device, SSH: Secure Enclave, `.privateKeyUsage`; usable only while
///   `KeyGate` is unlocked (app lock, LocalAuthentication).
/// - Monitor: Secure Enclave, `.privateKeyUsage`; usable while locked.
///
/// Each key's `dataRepresentation` (an enclave-wrapped blob) is kept in the
/// Keychain. Signatures are raw `r‖s` (64 bytes); Rust normalizes low-S.
///
/// **Software fallback:** when the Secure Enclave is unavailable (VMs, CI)
/// *and* the `FLEET_SOFTWARE_KEYS=1` environment variable is set, keys are
/// plain CryptoKit P-256 keys stored in the Keychain. `usesSoftwareKeys`
/// is shown as a warning in the UI. Never for production use.
final class SecureEnclaveKeys: DeviceSigner {
    enum Backend: Sendable { case secureEnclave, software }

    let backend: Backend
    private let gate: KeyGate
    private let cache = Mutex<[KeyRole: Key]>([:])

    enum Key: @unchecked Sendable {
        case enclave(SecureEnclave.P256.Signing.PrivateKey)
        case software(P256.Signing.PrivateKey)
    }

    enum Unavailable: Error { case noSecureEnclave }

    init(gate: KeyGate, environment: [String: String] = ProcessInfo.processInfo.environment) throws {
        self.gate = gate
        if SecureEnclave.isAvailable {
            backend = .secureEnclave
        } else if environment["FLEET_SOFTWARE_KEYS"] == "1" {
            backend = .software
        } else {
            throw Unavailable.noSecureEnclave
        }
    }

    var usesSoftwareKeys: Bool { backend == .software }

    // MARK: DeviceSigner

    func publicKey(role: KeyRole) throws -> Data {
        switch try key(role) {
        case .enclave(let k): return k.publicKey.compressedRepresentation
        case .software(let k): return k.publicKey.compressedRepresentation
        }
    }

    func sign(role: KeyRole, msg: Data) throws -> Data {
        if (role == .device || role == .ssh) && !gate.isUnlocked {
            throw SignerError.Unavailable
        }
        let key = try key(role)
        do {
            switch key {
            case .enclave(let k): return try k.signature(for: msg).rawRepresentation
            case .software(let k): return try k.signature(for: msg).rawRepresentation
            }
        } catch let error as LAError where error.code == .userCancel || error.code == .appCancel
            || error.code == .systemCancel || error.code == .authenticationFailed
        {
            throw SignerError.Cancelled
        } catch {
            throw role == .root ? SignerError.Cancelled : SignerError.Failed
        }
    }

    // MARK: Keys

    private static func account(_ role: KeyRole) -> String {
        switch role {
        case .root: "p256-root"
        case .device: "p256-device"
        case .monitor: "p256-monitor"
        case .ssh: "p256-ssh"
        }
    }

    private func key(_ role: KeyRole) throws -> Key {
        if let k = cache.withLock({ $0[role] }) { return k }
        let k = try loadOrCreate(role)
        cache.withLock { $0[role] = k }
        return k
    }

    private func loadOrCreate(_ role: KeyRole) throws -> Key {
        let account = Self.account(role) + (backend == .software ? "-sw" : "")
        let stored: Data?
        do { stored = try Keychain.load(account) } catch { throw SignerError.Unavailable }
        do {
            switch backend {
            case .secureEnclave:
                if let blob = stored {
                    return .enclave(try SecureEnclave.P256.Signing.PrivateKey(
                        dataRepresentation: blob, authenticationContext: Self.context(role)))
                }
                let k = try SecureEnclave.P256.Signing.PrivateKey(
                    compactRepresentable: false,
                    accessControl: try Self.accessControl(role),
                    authenticationContext: Self.context(role))
                try Keychain.add(account, k.dataRepresentation)
                return .enclave(k)
            case .software:
                if let raw = stored {
                    return .software(try P256.Signing.PrivateKey(rawRepresentation: raw))
                }
                let k = P256.Signing.PrivateKey(compactRepresentable: false)
                try Keychain.add(account, k.rawRepresentation)
                return .software(k)
            }
        } catch let e as SignerError {
            throw e
        } catch {
            throw SignerError.Failed
        }
    }

    /// Root prompts with its own reason; other keys never prompt.
    private static func context(_ role: KeyRole) -> LAContext {
        let ctx = LAContext()
        if role == .root {
            ctx.localizedReason = "sign a Fleet roster or approval"
        } else {
            ctx.interactionNotAllowed = true
        }
        return ctx
    }

    private static func accessControl(_ role: KeyRole) throws -> SecAccessControl {
        var flags: SecAccessControlCreateFlags = [.privateKeyUsage]
        if role == .root { flags.insert(.biometryCurrentSet) }
        var error: Unmanaged<CFError>?
        guard let ac = SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, flags, &error)
        else {
            throw SignerError.Failed
        }
        return ac
    }
}
