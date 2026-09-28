import CryptoKit
import Foundation
import LocalAuthentication
import Security

/// The FFI `SyncSecrets` (design §5.2, §5.9, §7.6):
///
/// - the sync key (40 bytes) in the Keychain, this device only;
/// - the sync key-agreement key: a Secure Enclave P-256 *KeyAgreement* key
///   (`.privateKeyUsage`), created on first use. Only ECDH results leave
///   the enclave: Rust runs HPKE and asks for `agree(peer)`;
/// - per-server sudo passwords: Keychain items whose access control
///   requires user presence, so reading one (revealing it) always shows
///   Touch ID. They're never typed automatically.
///
/// DEBUG builds without an enclave (`FLEET_SOFTWARE_KEYS=1`) use a software
/// key-agreement key, like `SecureEnclaveKeys`.
final class SyncKeychain: SyncSecrets {
    private static let syncKeyAccount = "sync-key"
    private static let agreementAccount = "p256-sync-agreement"
    private static let sudoService = "dev.fleet.Fleet.sudo"

    private let software: Bool

    init(software: Bool) {
        self.software = software
    }

    // MARK: sync key

    func loadSyncKey() throws -> Data? {
        do { return try Keychain.load(Self.syncKeyAccount) } catch { throw SignerError.Unavailable }
    }

    /// Replaced on rotation (revocation, recovery).
    func storeSyncKey(key: Data) throws {
        do {
            try Keychain.set(Self.syncKeyAccount, key)
        } catch {
            throw SignerError.Failed
        }
    }

    // MARK: key agreement

    func agreementPublicKey() throws -> Data {
        if software {
            return try softwareKey().publicKey.x963Representation
        }
        return try enclaveKey().publicKey.x963Representation
    }

    func agree(peer: Data) throws -> Data {
        let pub: P256.KeyAgreement.PublicKey
        do { pub = try P256.KeyAgreement.PublicKey(x963Representation: peer) } catch { throw SignerError.Failed }
        do {
            let shared = software
                ? try softwareKey().sharedSecretFromKeyAgreement(with: pub)
                : try enclaveKey().sharedSecretFromKeyAgreement(with: pub)
            return shared.withUnsafeBytes { Data($0) }
        } catch let e as SignerError {
            throw e
        } catch {
            throw SignerError.Failed
        }
    }

    private func enclaveKey() throws -> SecureEnclave.P256.KeyAgreement.PrivateKey {
        let stored: Data?
        do { stored = try Keychain.load(Self.agreementAccount) } catch { throw SignerError.Unavailable }
        do {
            if let blob = stored {
                return try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: blob)
            }
            var err: Unmanaged<CFError>?
            guard let ac = SecAccessControlCreateWithFlags(
                nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, [.privateKeyUsage], &err)
            else { throw SignerError.Failed }
            let k = try SecureEnclave.P256.KeyAgreement.PrivateKey(
                compactRepresentable: false, accessControl: ac)
            try Keychain.add(Self.agreementAccount, k.dataRepresentation)
            return k
        } catch let e as SignerError {
            throw e
        } catch {
            throw SignerError.Failed
        }
    }

    private func softwareKey() throws -> P256.KeyAgreement.PrivateKey {
        let account = Self.agreementAccount + "-sw"
        do {
            if let raw = try Keychain.load(account) {
                return try P256.KeyAgreement.PrivateKey(rawRepresentation: raw)
            }
            let k = P256.KeyAgreement.PrivateKey(compactRepresentable: false)
            try Keychain.add(account, k.rawRepresentation)
            return k
        } catch {
            throw SignerError.Failed
        }
    }

    // MARK: sudo passwords

    /// Add-or-update, never delete-then-add: a failure midway can't lose
    /// the stored password. A new item gets the user-presence ACL; an
    /// existing one keeps its ACL and only its data is replaced.
    func storeSudoPassword(serverId: String, password: String) throws {
        #if FLEET_TEST_HOOKS
        if let dir = TestHooks.dataDir {
            _ = TestHooks.approve("sudo-store: replace the stored sudo password")
            do {
                _ = try TestHooks.FileKeychain.store(
                    dir, Self.sudoService, serverId, Data(password.utf8), replace: true)
            } catch { throw SignerError.Failed }
            return
        }
        #endif
        var error: Unmanaged<CFError>?
        guard let ac = SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, [.userPresence], &error)
        else { throw SignerError.Failed }
        let data = Data(password.utf8)
        var q = Self.sudoQuery(serverId)
        q[kSecValueData as String] = data
        q[kSecAttrAccessControl as String] = ac
        var status = SecItemAdd(q as CFDictionary, nil)
        if status == errSecDuplicateItem {
            let ctx = LAContext()
            ctx.localizedReason = "replace the stored sudo password"
            var match = Self.sudoQuery(serverId)
            match[kSecUseAuthenticationContext as String] = ctx
            status = SecItemUpdate(match as CFDictionary,
                                   [kSecValueData as String: data] as CFDictionary)
            ctx.invalidate()
        }
        switch status {
        case errSecSuccess: return
        case errSecUserCanceled, errSecAuthFailed: throw SignerError.Cancelled
        default: throw SignerError.Failed
        }
    }

    func deleteSudoPassword(serverId: String) throws {
        #if FLEET_TEST_HOOKS
        if let dir = TestHooks.dataDir {
            TestHooks.FileKeychain.delete(dir, Self.sudoService, serverId)
            return
        }
        #endif
        let status = SecItemDelete(Self.sudoQuery(serverId) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else { throw SignerError.Failed }
    }

    /// Whether `serverId` has a sudo password in this Mac's Keychain
    /// (doesn't read it, so no Touch ID).
    static func hasSudoPassword(_ serverId: String) -> Bool {
        #if FLEET_TEST_HOOKS
        if let dir = TestHooks.dataDir {
            return TestHooks.FileKeychain.exists(dir, sudoService, serverId)
        }
        #endif
        var q = sudoQuery(serverId)
        let ctx = LAContext()
        ctx.interactionNotAllowed = true
        q[kSecUseAuthenticationContext as String] = ctx
        q[kSecReturnAttributes as String] = true
        let status = SecItemCopyMatching(q as CFDictionary, nil)
        return status == errSecSuccess || status == errSecInteractionNotAllowed
    }

    /// Reads the password; the item's ACL shows Touch ID first. Runs off
    /// the main thread.
    static func revealSudoPassword(_ serverId: String, serverName: String) async throws -> String {
        #if FLEET_TEST_HOOKS
        if let dir = TestHooks.dataDir {
            guard TestHooks.approve("sudo-reveal: reveal the sudo password for \(serverName)")
            else { throw SignerError.Cancelled }
            guard let d = TestHooks.FileKeychain.load(dir, sudoService, serverId),
                  let s = String(data: d, encoding: .utf8) else { throw SignerError.Missing }
            return s
        }
        #endif
        return try await Task.detached {
            let ctx = LAContext()
            ctx.localizedReason = "reveal the sudo password for \(serverName)"
            var q = sudoQuery(serverId)
            q[kSecReturnData as String] = true
            q[kSecUseAuthenticationContext as String] = ctx
            var out: CFTypeRef?
            let status = SecItemCopyMatching(q as CFDictionary, &out)
            ctx.invalidate()
            switch status {
            case errSecSuccess:
                guard let d = out as? Data, let s = String(data: d, encoding: .utf8) else { throw SignerError.Failed }
                return s
            case errSecUserCanceled, errSecAuthFailed: throw SignerError.Cancelled
            case errSecItemNotFound: throw SignerError.Missing
            default: throw SignerError.Failed
            }
        }.value
    }

    private static func sudoQuery(_ serverId: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: sudoService,
            kSecAttrAccount as String: serverId,
            kSecUseDataProtectionKeychain as String: true,
        ]
    }
}
