import Foundation
import Security

/// Generic-password items in the data protection keychain, this device only.
/// Holds Secure Enclave key blobs (wrapped by the enclave, useless
/// elsewhere) and the X25519 Noise key.
enum Keychain {
    static let service = "dev.fleet.Fleet.keys"

    enum Failure: Error {
        case status(OSStatus)
    }

    static func load(_ account: String) throws -> Data? {
        #if FLEET_TEST_HOOKS
        if let dir = TestHooks.dataDir { return TestHooks.FileKeychain.load(dir, service, account) }
        #endif
        var query = base(account)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var out: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &out)
        switch status {
        case errSecSuccess: return out as? Data
        case errSecItemNotFound: return nil
        default: throw Failure.status(status)
        }
    }

    /// Adds `data`; never overwrites an existing item (keys are generated
    /// once, a silent replace would orphan the roster entry).
    static func add(_ account: String, _ data: Data) throws {
        #if FLEET_TEST_HOOKS
        if let dir = TestHooks.dataDir {
            guard try TestHooks.FileKeychain.store(dir, service, account, data, replace: false)
            else { throw Failure.status(errSecDuplicateItem) }
            return
        }
        #endif
        var query = base(account)
        query[kSecValueData as String] = data
        query[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else { throw Failure.status(status) }
    }

    /// Adds `data`, or replaces the existing item's data in place
    /// (`SecItemUpdate`), so there's never a moment without an item. Only
    /// for replaceable secrets (the sync key), never for key blobs.
    static func set(_ account: String, _ data: Data) throws {
        #if FLEET_TEST_HOOKS
        if let dir = TestHooks.dataDir {
            _ = try TestHooks.FileKeychain.store(dir, service, account, data, replace: true)
            return
        }
        #endif
        var query = base(account)
        query[kSecValueData as String] = data
        query[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        var status = SecItemAdd(query as CFDictionary, nil)
        if status == errSecDuplicateItem {
            status = SecItemUpdate(base(account) as CFDictionary,
                                   [kSecValueData as String: data] as CFDictionary)
        }
        guard status == errSecSuccess else { throw Failure.status(status) }
    }

    /// Removes an item (only for derived state, never for key blobs).
    static func delete(_ account: String) throws {
        #if FLEET_TEST_HOOKS
        if let dir = TestHooks.dataDir {
            TestHooks.FileKeychain.delete(dir, service, account)
            return
        }
        #endif
        let status = SecItemDelete(base(account) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw Failure.status(status)
        }
    }

    private static func base(_ account: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecUseDataProtectionKeychain as String: true,
        ]
    }
}

/// The FFI `KeyStore`: the Noise static key (design §5.2) and the cache
/// integrity key (MACs over pins and rosters in the local database), both
/// in the Keychain, this device only.
final class NoiseKeyStore: KeyStore {
    private static let account = "noise-static"
    private static let cacheAccount = "cache-integrity"

    func loadNoiseKey() throws -> Data? {
        do { return try Keychain.load(Self.account) } catch { throw SignerError.Unavailable }
    }

    func storeNoiseKey(secret: Data) throws {
        do { try Keychain.add(Self.account, secret) } catch { throw SignerError.Failed }
    }

    func loadCacheKey() throws -> Data? {
        do { return try Keychain.load(Self.cacheAccount) } catch { throw SignerError.Unavailable }
    }

    func storeCacheKey(secret: Data) throws {
        do { try Keychain.add(Self.cacheAccount, secret) } catch { throw SignerError.Failed }
    }
}
