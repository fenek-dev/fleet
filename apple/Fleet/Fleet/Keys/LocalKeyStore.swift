import CryptoKit
import Foundation
import LocalAuthentication
import Synchronization

/// Key storage for ad-hoc signed builds, where the data protection Keychain
/// refuses every call (`errSecMissingEntitlement`: no
/// `keychain-access-groups` without a provisioning profile). Used by
/// `Keychain` only when `Keychain.fallbackAllowed` (ad-hoc code signature
/// and the `FLEET_ADHOC_KEYSTORE` build flag) and only after such a
/// refusal; design §5.2 "Unsigned builds".
///
/// Security model kept: private keys never leave the Secure Enclave.
///
/// - Secure Enclave key blobs (`p256-*`) and the fingerprint-set marker are
///   stored as they are: a `dataRepresentation` is an enclave-wrapped blob
///   that only this Mac's Secure Enclave can use, so a stolen file is
///   useless elsewhere.
/// - The two software secrets the core keeps (Noise static key, cache
///   integrity key) are sealed with ChaChaPoly under a key derived by ECDH
///   between an ephemeral key and a Secure Enclave key-agreement key
///   (`p256-local-wrap`) whose ACL requires user presence. They are opened
///   ONCE per app run, at the Touch ID app unlock, with the unlock
///   `LAContext` (`unlockSecrets`), and then held in memory. Until then
///   `load` throws `.locked`, so the core opens only after the first unlock.
/// - Everything else (sync key, sudo passwords) is Keychain-only: no plain
///   file ever holds them. Those features report "needs a signed build".
///
/// Files: created with `O_CREAT|O_EXCL|O_NOFOLLOW`, mode 0600, in a 0700
/// directory owned by this user with no symlink component; reads check the
/// same on the opened descriptor.
enum LocalKeyStore {
    static let wrapAccount = "p256-local-wrap"
    private static let sealed: Set<String> = ["noise-static", "cache-integrity"]
    private static let info = Data("dev.fleet.Fleet.local-keystore.v1".utf8)
    private static let maxFile = 8192

    enum Failure: Error { case notSupported, unavailable, corrupt, locked, unsafe }

    /// Serializes creation and the first-use init of the wrap key.
    private static let ioLock = NSLock()
    /// Sealed secrets opened at unlock (plaintext, this process only).
    private static let secrets = Mutex<[String: Data]>([:])

    /// Accounts that may live outside the Keychain.
    static func supports(_ account: String) -> Bool {
        account.hasPrefix("p256-") || account == "root-biometry-state" || sealed.contains(account)
    }

    static func isSealed(_ account: String) -> Bool { sealed.contains(account) }

    // MARK: files

    private static func lstatMode(_ path: String) -> (mode: mode_t, uid: uid_t)? {
        var st = stat()
        guard lstat(path, &st) == 0 else { return nil }
        return (st.st_mode, st.st_uid)
    }

    /// The validated key directory (created 0700 when missing).
    private static func dir(create: Bool = true) throws -> String {
        let base = try AppPaths.dataDir()
        let path = base.appendingPathComponent("keystore", isDirectory: true).path
        // No symlink anywhere on the path.
        var walk = ""
        for c in URL(fileURLWithPath: path).pathComponents where c != "/" {
            walk += "/" + c
            if walk == path { break }
            guard let m = lstatMode(walk), m.mode & S_IFMT != S_IFLNK else { throw Failure.unsafe }
        }
        if create {
            if mkdir(path, 0o700) != 0 && errno != EEXIST { throw Failure.unavailable }
        } else if lstatMode(path) == nil {
            throw Failure.unavailable  // read-only probes never create it
        }
        guard let m = lstatMode(path), m.mode & S_IFMT == S_IFDIR,
              m.uid == getuid(), m.mode & 0o777 == 0o700
        else { throw Failure.unsafe }
        return path
    }

    private static func path(_ account: String, create: Bool = true) throws -> String {
        guard supports(account), !account.contains("/"), !account.contains("..") else {
            throw Failure.notSupported
        }
        return try dir(create: create) + "/" + account
    }

    static func exists(_ account: String) -> Bool {
        guard let p = try? path(account, create: false) else { return false }
        return lstatMode(p) != nil
    }

    /// True when any key file is present (a signed build should migrate).
    static func hasFiles() -> Bool {
        guard let d = try? dir(create: false), let names = try? FileManager.default.contentsOfDirectory(atPath: d)
        else { return false }
        return !names.isEmpty
    }

    /// After a migration: delete the wrap key when it is the last file.
    static func removeWrapIfAlone() {
        guard let d = try? dir(create: false), let names = try? FileManager.default.contentsOfDirectory(atPath: d),
              names == [wrapAccount]
        else { return }
        try? delete(wrapAccount)
    }

    private static func readFile(_ p: String) throws -> Data? {
        let fd = open(p, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        if fd < 0 {
            if errno == ENOENT { return nil }
            throw Failure.unsafe
        }
        let h = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        var st = stat()
        guard fstat(fd, &st) == 0, st.st_mode & S_IFMT == S_IFREG, st.st_uid == getuid(),
              st.st_mode & 0o077 == 0, st.st_size <= maxFile
        else { throw Failure.unsafe }
        return try h.readToEnd() ?? Data()
    }

    /// Exclusive create; false when the file exists.
    private static func createFile(_ p: String, _ data: Data) throws -> Bool {
        let fd = open(p, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        if fd < 0 { if errno == EEXIST { return false } else { throw Failure.unavailable } }
        let h = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        do {
            try h.write(contentsOf: data)
            try h.synchronize()
        } catch {
            unlink(p)
            throw Failure.unavailable
        }
        return true
    }

    // MARK: API

    /// Raw files load directly. Sealed secrets come from memory (opened at
    /// unlock); a sealed file not yet opened throws `.locked`, unless
    /// `prompt` (key migration, which may show Touch ID itself).
    static func load(_ account: String, prompt: Bool = false) throws -> Data? {
        if sealed.contains(account), let s = secrets.withLock({ $0[account] }) { return s }
        let raw = try readFile(try path(account))
        guard let raw else { return nil }
        guard sealed.contains(account) else { return raw }
        guard prompt else { throw Failure.locked }
        let ctx = LAContext()
        ctx.localizedReason = "move Fleet keys to the Keychain"
        return try unseal(raw, account, context: ctx)
    }

    /// Never overwrites (like `SecItemAdd`); false when present.
    @discardableResult
    static func add(_ account: String, _ data: Data) throws -> Bool {
        ioLock.lock()
        defer { ioLock.unlock() }
        let p = try path(account)
        let out = sealed.contains(account) ? try seal(data, account) : data
        guard try createFile(p, out) else { return false }
        if sealed.contains(account) { secrets.withLock { $0[account] = data } }
        return true
    }

    static func delete(_ account: String) throws {
        ioLock.lock()
        defer { ioLock.unlock() }
        unlink(try path(account))
        secrets.withLock { $0[account] = nil }
    }

    /// Opens every sealed secret with the app-unlock context (one Touch ID
    /// for the whole run) and keeps the plaintext in memory.
    static func unlockSecrets(context: LAContext) throws {
        for account in sealed {
            if secrets.withLock({ $0[account] != nil }) { continue }
            guard let raw = try readFile(try path(account)) else { continue }
            let v = try unseal(raw, account, context: context)
            secrets.withLock { $0[account] = v }
        }
    }

    // MARK: sealing

    /// The wrap key (created with the user-presence ACL on first use).
    /// Sealing needs only its public key; opening needs `context`.
    private static func wrapKey(context: LAContext?) throws -> SecureEnclave.P256.KeyAgreement.PrivateKey {
        guard SecureEnclave.isAvailable else { throw Failure.unavailable }
        let p = try path(wrapAccount)
        if let blob = try readFile(p) {
            return try SecureEnclave.P256.KeyAgreement.PrivateKey(
                dataRepresentation: blob, authenticationContext: context)
        }
        var err: Unmanaged<CFError>?
        guard let ac = SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage, .userPresence], &err)
        else { throw Failure.unavailable }
        let k = try SecureEnclave.P256.KeyAgreement.PrivateKey(
            compactRepresentable: false, accessControl: ac, authenticationContext: context)
        guard try createFile(p, k.dataRepresentation) else {
            guard let blob = try readFile(p) else { throw Failure.unavailable }
            return try SecureEnclave.P256.KeyAgreement.PrivateKey(
                dataRepresentation: blob, authenticationContext: context)
        }
        return k
    }

    private static func symmetric(_ shared: SharedSecret, _ account: String) -> SymmetricKey {
        shared.hkdfDerivedSymmetricKey(
            using: SHA256.self, salt: Data(), sharedInfo: info + Data(account.utf8),
            outputByteCount: 32)
    }

    private static func seal(_ data: Data, _ account: String) throws -> Data {
        let wk = try wrapKey(context: nil)
        let eph = P256.KeyAgreement.PrivateKey()
        let key = symmetric(try eph.sharedSecretFromKeyAgreement(with: wk.publicKey), account)
        let box = try ChaChaPoly.seal(data, using: key, authenticating: Data(account.utf8))
        return eph.publicKey.x963Representation + box.combined
    }

    private static func unseal(_ raw: Data, _ account: String, context: LAContext) throws -> Data {
        guard raw.count > 65 else { throw Failure.corrupt }
        let peer = try P256.KeyAgreement.PublicKey(x963Representation: raw.prefix(65))
        let key = symmetric(try wrapKey(context: context).sharedSecretFromKeyAgreement(with: peer), account)
        let box = try ChaChaPoly.SealedBox(combined: raw.dropFirst(65))
        return try ChaChaPoly.open(box, using: key, authenticating: Data(account.utf8))
    }
}
