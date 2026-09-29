import CryptoKit
import Foundation

/// Key storage for unsigned (ad-hoc) builds, where the data protection
/// Keychain refuses every call (`errSecMissingEntitlement`: no
/// `keychain-access-groups` without a provisioning profile). Used by
/// `Keychain` only after such a refusal; design §5.2 "Unsigned builds".
///
/// Security model kept: private keys never leave the Secure Enclave.
///
/// - Secure Enclave key blobs (`p256-*`) and the fingerprint-set marker are
///   stored as they are: a `dataRepresentation` is an enclave-wrapped blob
///   that only this Mac's Secure Enclave can use, so a stolen file is
///   useless elsewhere. Files are 0600 in a 0700 directory.
/// - The two software secrets the core keeps (Noise static key, cache
///   integrity key) are sealed with ChaChaPoly under a key derived by ECDH
///   between an ephemeral key and a Secure Enclave key agreement key
///   (`p256-local-wrap`): opening them needs this Mac's enclave, exactly
///   like a Keychain item bound to this device.
/// - Everything else (sync key, sudo passwords) is Keychain-only: no plain
///   file ever holds them. Those features report "needs a signed build".
enum LocalKeyStore {
    private static let wrapAccount = "p256-local-wrap"
    private static let sealed: Set<String> = ["noise-static", "cache-integrity"]
    private static let info = Data("dev.fleet.Fleet.local-keystore.v1".utf8)

    enum Failure: Error { case notSupported, unavailable, corrupt }

    /// Accounts that may live outside the Keychain.
    static func supports(_ account: String) -> Bool {
        account.hasPrefix("p256-") || account == "root-biometry-state" || sealed.contains(account)
    }

    private static func dir() throws -> URL {
        let d = try AppPaths.dataDir().appendingPathComponent("keystore", isDirectory: true)
        try FileManager.default.createDirectory(
            at: d, withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700])
        return d
    }

    private static func url(_ account: String) throws -> URL {
        guard supports(account), !account.contains("/") else { throw Failure.notSupported }
        return try dir().appendingPathComponent(account)
    }

    static func load(_ account: String) throws -> Data? {
        let u = try url(account)
        guard let raw = try? Data(contentsOf: u) else { return nil }
        return sealed.contains(account) ? try open(raw, account) : raw
    }

    /// Never overwrites (like `SecItemAdd`); returns false when present.
    @discardableResult
    static func add(_ account: String, _ data: Data) throws -> Bool {
        let u = try url(account)
        if FileManager.default.fileExists(atPath: u.path) { return false }
        let out = sealed.contains(account) ? try seal(data, account) : data
        guard FileManager.default.createFile(
            atPath: u.path, contents: out, attributes: [.posixPermissions: 0o600])
        else { throw Failure.unavailable }
        return true
    }

    static func delete(_ account: String) throws {
        try? FileManager.default.removeItem(at: try url(account))
    }

    // MARK: sealing

    private static func wrapKey() throws -> SecureEnclave.P256.KeyAgreement.PrivateKey {
        guard SecureEnclave.isAvailable else { throw Failure.unavailable }
        if let blob = try load(wrapAccount) {
            return try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: blob)
        }
        var err: Unmanaged<CFError>?
        guard let ac = SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, [.privateKeyUsage], &err)
        else { throw Failure.unavailable }
        let k = try SecureEnclave.P256.KeyAgreement.PrivateKey(
            compactRepresentable: false, accessControl: ac)
        guard try add(wrapAccount, k.dataRepresentation) else {
            // Lost a race: use the stored one.
            guard let blob = try load(wrapAccount) else { throw Failure.unavailable }
            return try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: blob)
        }
        return k
    }

    private static func symmetric(_ shared: SharedSecret, _ account: String) -> SymmetricKey {
        shared.hkdfDerivedSymmetricKey(
            using: SHA256.self, salt: Data(), sharedInfo: info + Data(account.utf8),
            outputByteCount: 32)
    }

    private static func seal(_ data: Data, _ account: String) throws -> Data {
        let wk = try wrapKey()
        let eph = P256.KeyAgreement.PrivateKey()
        let key = symmetric(try eph.sharedSecretFromKeyAgreement(with: wk.publicKey), account)
        let box = try ChaChaPoly.seal(data, using: key, authenticating: Data(account.utf8))
        return eph.publicKey.x963Representation + box.combined
    }

    private static func open(_ raw: Data, _ account: String) throws -> Data {
        guard raw.count > 65 else { throw Failure.corrupt }
        let peer = try P256.KeyAgreement.PublicKey(x963Representation: raw.prefix(65))
        let key = symmetric(try wrapKey().sharedSecretFromKeyAgreement(with: peer), account)
        let box = try ChaChaPoly.SealedBox(combined: raw.dropFirst(65))
        return try ChaChaPoly.open(box, using: key, authenticating: Data(account.utf8))
    }
}
