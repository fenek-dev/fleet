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

    enum Failure: Error {
        case notSupported, unavailable, corrupt, locked, unsafe
        /// The directory does not exist (only for read-only probes).
        case missing
        /// A system call failed for a reason other than "does not exist".
        case io(Int32)
    }

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

    /// nil only for ENOENT; every other failure propagates.
    private static func lstatMode(_ path: String) throws -> (mode: mode_t, uid: uid_t)? {
        var st = stat()
        guard lstat(path, &st) == 0 else {
            if errno == ENOENT { return nil }
            throw Failure.io(errno)
        }
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
            guard let m = try lstatMode(walk), m.mode & S_IFMT != S_IFLNK else { throw Failure.unsafe }
        }
        if create {
            if mkdir(path, 0o700) != 0 && errno != EEXIST { throw Failure.unavailable }
        } else if try lstatMode(path) == nil {
            throw Failure.missing  // read-only probes never create it
        }
        guard let m = try lstatMode(path), m.mode & S_IFMT == S_IFDIR,
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

    /// Whether the account's file exists. A missing directory or file is
    /// `false`; validation and I/O errors propagate.
    static func exists(_ account: String) throws -> Bool {
        let p: String
        do { p = try path(account, create: false) } catch Failure.missing { return false }
        return try lstatMode(p) != nil
    }

    /// True when any key file is present (a signed build should migrate).
    static func hasFiles() throws -> Bool {
        let d: String
        do { d = try dir(create: false) } catch Failure.missing { return false }
        return !(try FileManager.default.contentsOfDirectory(atPath: d)).isEmpty
    }

    /// After a migration: delete the wrap key when it is the last file.
    static func removeWrapIfAlone() throws {
        let d: String
        do { d = try dir(create: false) } catch Failure.missing { return }
        if try FileManager.default.contentsOfDirectory(atPath: d) == [wrapAccount] {
            try delete(wrapAccount)
        }
    }

    private static func readFile(_ p: String) throws -> Data? {
        let fd = open(p, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        if fd < 0 {
            if errno == ENOENT { return nil }
            throw errno == ELOOP ? Failure.unsafe : Failure.io(errno)
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
        if fd < 0 { if errno == EEXIST { return false } else { throw Failure.io(errno) } }
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
        try upgradeLegacyWrap()
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

    // MARK: legacy wrap key

    /// A wrap key made before the user-presence ACL (no ACL at all) can be
    /// used by any same-user process without a prompt: usable with a
    /// context that forbids interaction.
    private static func isLegacyWrap(_ blob: Data) -> Bool {
        let ctx = LAContext()
        ctx.interactionNotAllowed = true
        guard let k = try? SecureEnclave.P256.KeyAgreement.PrivateKey(
            dataRepresentation: blob, authenticationContext: ctx)
        else { return false }
        let probe = P256.KeyAgreement.PrivateKey()
        return (try? k.sharedSecretFromKeyAgreement(with: probe.publicKey)) != nil
    }

    /// Replaces a legacy wrap key: seal every secret to a new
    /// `.userPresence` key, then swap. Crash-safe by ordering: the new wrap
    /// key blob is written first as `p256-local-wrap.new` and renamed over
    /// the old one LAST, after every `<secret>.new` has been renamed into
    /// place, so an interrupted run is rolled forward here on the next
    /// start (the presence of `p256-local-wrap.new` means "sealed files
    /// named `.new` are valid").
    static func upgradeLegacyWrap() throws {
        ioLock.lock()
        defer { ioLock.unlock() }
        let wp = try path(wrapAccount)
        let np = wp + ".new"
        if try readFile(np) != nil {
            try finishWrapUpgrade(wp, np)
            return
        }
        guard let blob = try readFile(wp), isLegacyWrap(blob) else { return }
        let legacy = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: blob)
        // 1. Plaintext of everything sealed, opened with the legacy key.
        var plain: [String: Data] = [:]
        for a in sealed {
            let f = try path(a)
            unlink(f + ".new")  // debris of a run that died before np existed
            guard let raw = try readFile(f) else { continue }
            guard raw.count > 65 else { throw Failure.corrupt }
            let peer = try P256.KeyAgreement.PublicKey(x963Representation: raw.prefix(65))
            let key = symmetric(try legacy.sharedSecretFromKeyAgreement(with: peer), a)
            let box = try ChaChaPoly.SealedBox(combined: raw.dropFirst(65))
            plain[a] = try ChaChaPoly.open(box, using: key, authenticating: Data(a.utf8))
        }
        // 2. New wrap key (user presence), sealed copies next to the old.
        var err: Unmanaged<CFError>?
        guard let ac = SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage, .userPresence], &err)
        else { throw Failure.unavailable }
        let fresh = try SecureEnclave.P256.KeyAgreement.PrivateKey(
            compactRepresentable: false, accessControl: ac)
        for (a, d) in plain {
            guard try createFile(try path(a) + ".new", try seal(d, a, to: fresh.publicKey)) else {
                throw Failure.unavailable
            }
        }
        // np goes last: it is what marks the `.new` files valid.
        guard try createFile(np, fresh.dataRepresentation) else { throw Failure.unavailable }
        try finishWrapUpgrade(wp, np)
    }

    private static func finishWrapUpgrade(_ wp: String, _ np: String) throws {
        for a in sealed {
            let f = try path(a)
            if try readFile(f + ".new") != nil {
                guard rename(f + ".new", f) == 0 else { throw Failure.io(errno) }
            }
        }
        guard rename(np, wp) == 0 else { throw Failure.io(errno) }
        let fd = open((wp as NSString).deletingLastPathComponent, O_RDONLY | O_CLOEXEC)
        if fd >= 0 { fsync(fd); close(fd) }
    }

    private static func symmetric(_ shared: SharedSecret, _ account: String) -> SymmetricKey {
        shared.hkdfDerivedSymmetricKey(
            using: SHA256.self, salt: Data(), sharedInfo: info + Data(account.utf8),
            outputByteCount: 32)
    }

    private static func seal(_ data: Data, _ account: String) throws -> Data {
        try seal(data, account, to: try wrapKey(context: nil).publicKey)
    }

    private static func seal(
        _ data: Data, _ account: String, to pub: P256.KeyAgreement.PublicKey
    ) throws -> Data {
        let eph = P256.KeyAgreement.PrivateKey()
        let key = symmetric(try eph.sharedSecretFromKeyAgreement(with: pub), account)
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
