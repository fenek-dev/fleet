import Foundation
import Security

/// Where a key operation goes (pure decision, unit-tested).
enum KeyStoreChoice: Equatable {
    /// The data protection Keychain works and no fallback files exist.
    case keychain
    /// The Keychain works and key files from an earlier ad-hoc run exist:
    /// move them into the Keychain once (write, verify, delete the file).
    case migrateThenKeychain
    /// Ad-hoc build, Keychain refused: enclave-bound file store.
    case fallback
    case refuse(Refusal)

    enum Refusal: Equatable {
        /// Keychain refused but this is not an ad-hoc build: fail closed.
        case notAdHoc
        /// Keys were created in the Keychain by a signed build; an ad-hoc
        /// build must not silently create a second set.
        case signedKeysExist
    }

    static func decide(
        keychainUsable: Bool, fallbackAllowed: Bool, fileKeysExist: Bool, keychainMarker: Bool
    ) -> KeyStoreChoice {
        if keychainUsable { return fileKeysExist ? .migrateThenKeychain : .keychain }
        if !fallbackAllowed { return .refuse(.notAdHoc) }
        if keychainMarker { return .refuse(.signedKeysExist) }
        return .fallback
    }
}

/// Generic-password items in the data protection keychain, this device only.
/// Holds Secure Enclave key blobs (wrapped by the enclave, useless
/// elsewhere) and the X25519 Noise key. Ad-hoc builds, which the Keychain
/// refuses, use `LocalKeyStore` (design §5.2 "Unsigned builds").
enum Keychain {
    static let service = "dev.fleet.Fleet.keys"

    enum Failure: Error {
        case status(OSStatus)
        case refused(KeyStoreChoice.Refusal)
        /// The Keychain and the fallback file hold different keys for the
        /// same account (a migration was interrupted, or keys were made by
        /// two builds). Nothing is deleted or overwritten.
        case conflict(String)
    }

    /// The fallback file store may be used only by an ad-hoc signed build
    /// (checked at runtime from the code signature) that was also built for
    /// it (`FLEET_ADHOC_KEYSTORE`, set by the ad-hoc build scripts). A
    /// team-signed build fails closed on `errSecMissingEntitlement`.
    static var fallbackAllowed: Bool {
        #if FLEET_ADHOC_KEYSTORE
        return CodeIdentity.isAdHoc
        #else
        return false
        #endif
    }

    static func refusalMessage(_ r: KeyStoreChoice.Refusal) -> String {
        switch r {
        case .notAdHoc:
            "The Keychain refused access (missing entitlement). This build is signed, so Fleet will not fall back to file storage. Check the provisioning profile."
        case .signedKeysExist:
            "This Mac's Fleet keys are in the Keychain, created by a signed build. This unsigned build can't use them and won't create a second set. Open the signed build."
        }
    }

    /// The Keychain refused for lack of entitlements and the file store is
    /// in use. Keychain-only features (sync key, sudo passwords, iCloud) are
    /// unavailable, and the sealed secrets need the first unlock of each run.
    nonisolated(unsafe) private(set) static var unsigned = false

    static let needsSignedBuild =
        "Needs a signed build: this copy of Fleet is not signed with a team, so the Keychain is unavailable. Sync keys and sudo passwords are not stored."

    // MARK: startup

    /// What to do at launch: nil = Keychain works, `.fallback` = the file
    /// store (open the core only after the first unlock), or a refusal.
    static func startupChoice() -> KeyStoreChoice {
        #if FLEET_TEST_HOOKS
        if TestHooks.dataDir != nil { return .keychain }
        #endif
        var q = base("startup-probe")
        q[kSecReturnData as String] = false
        let status = SecItemCopyMatching(q as CFDictionary, nil)
        return choice(status: status)
    }

    private static func choice(status: OSStatus) -> KeyStoreChoice {
        let c = KeyStoreChoice.decide(
            keychainUsable: status != errSecMissingEntitlement,
            fallbackAllowed: fallbackAllowed,
            fileKeysExist: (try? LocalKeyStore.hasFiles()) ?? true,
            keychainMarker: hasMarker())
        if c == .fallback { unsigned = true }
        return c
    }

    // MARK: marker (a signed build stored keys in the Keychain)

    private static func markerPath() -> String? {
        try? AppPaths.file("keychain-in-use").path
    }

    private static func hasMarker() -> Bool {
        guard let p = markerPath() else { return false }
        var st = stat()
        return lstat(p, &st) == 0
    }

    private static func writeMarker() -> Bool {
        guard let p = markerPath() else { return false }
        let fd = open(p, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        if fd < 0 { return errno == EEXIST }
        close(fd)
        return true
    }

    // MARK: items

    private static func copy(_ account: String) -> (OSStatus, Data?) {
        var query = base(account)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var out: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &out)
        return (status, status == errSecSuccess ? out as? Data : nil)
    }

    static func load(_ account: String) throws -> Data? {
        #if FLEET_TEST_HOOKS
        if let dir = TestHooks.dataDir { return TestHooks.FileKeychain.load(dir, service, account) }
        #endif
        // Finish or discard an interrupted wrap-key reseal before any
        // migration or reconcile read of the key files (every build mode).
        try LocalKeyStore.recoverPendingReseal()
        let (status, data) = copy(account)
        switch status {
        case errSecSuccess:
            // The Keychain holds keys: remember it (so an ad-hoc build later
            // refuses to make a second set), even for keys created by an
            // older build that wrote no marker.
            guard writeMarker() else { throw Failure.status(errSecIO) }
            // An interrupted migration may have left the file behind.
            if let data, account != LocalKeyStore.wrapAccount,
               try LocalKeyStore.existsIfSupported(account) {
                try reconcile(account, keychain: data)
            }
            return data
        case errSecItemNotFound:
            // Keys an earlier ad-hoc run left in files: move them over once.
            if account != LocalKeyStore.wrapAccount, try LocalKeyStore.existsIfSupported(account) {
                return try migrate(account)
            }
            return nil
        case errSecMissingEntitlement:
            switch choice(status: status) {
            case .fallback:
                // Keychain-only secrets read as "not stored" (sync stays off).
                return LocalKeyStore.supports(account) ? try LocalKeyStore.load(account) : nil
            case .refuse(let r): throw Failure.refused(r)
            default: throw Failure.status(status)
            }
        default: throw Failure.status(status)
        }
    }

    /// Both stores have `account`: equal -> the file is stale, delete it;
    /// different -> refuse (never guess which key is the real one).
    private static func reconcile(_ account: String, keychain: Data) throws {
        guard let file = try LocalKeyStore.load(account, prompt: true) else { return }
        guard file == keychain else { throw Failure.conflict(account) }
        try LocalKeyStore.delete(account)
        try LocalKeyStore.removeWrapIfAlone()
    }

    /// Fallback file -> Keychain: read (may prompt), add, verify by reading
    /// back, then delete the file. A failure leaves the file in place.
    private static func migrate(_ account: String) throws -> Data? {
        guard let data = try LocalKeyStore.load(account, prompt: true) else { return nil }
        var query = base(account)
        query[kSecValueData as String] = data
        query[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        var status = SecItemAdd(query as CFDictionary, nil)
        if status == errSecDuplicateItem { status = errSecSuccess }
        guard status == errSecSuccess, writeMarker() else { throw Failure.status(status) }
        guard copy(account).1 == data else { throw Failure.status(errSecInternalError) }
        try LocalKeyStore.delete(account)
        // The wrap key goes once nothing else is left in the directory.
        try LocalKeyStore.removeWrapIfAlone()
        return data
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
        if status == errSecMissingEntitlement {
            switch choice(status: status) {
            case .fallback:
                guard LocalKeyStore.supports(account) else { throw Failure.status(status) }
                guard (try? LocalKeyStore.add(account, data)) == true
                else { throw Failure.status(errSecDuplicateItem) }
                return
            case .refuse(let r): throw Failure.refused(r)
            default: throw Failure.status(status)
            }
        }
        guard status == errSecSuccess else { throw Failure.status(status) }
        // Remember that signed-build keys exist, so an ad-hoc build later
        // refuses instead of creating a second set. No marker, no key.
        guard writeMarker() else {
            SecItemDelete(base(account) as CFDictionary)
            throw Failure.status(errSecIO)
        }
    }

    /// Adds `data`, or replaces the existing item's data in place
    /// (`SecItemUpdate`), so there's never a moment without an item. Only
    /// for replaceable secrets (the sync key), never for key blobs.
    /// Keychain-only: never falls back to a file.
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
        guard status == errSecSuccess else {
            if status == errSecMissingEntitlement { unsigned = unsigned || fallbackAllowed }
            throw Failure.status(status)
        }
        _ = writeMarker()
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
        if status == errSecMissingEntitlement {
            if case .fallback = choice(status: status) {
                try? LocalKeyStore.delete(account)
                return
            }
            throw Failure.status(status)
        }
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
