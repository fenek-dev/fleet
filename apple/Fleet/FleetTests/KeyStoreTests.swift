import Foundation
import Testing
@testable import Fleet

/// Decision logic for where keys live (Keychain vs the ad-hoc file store)
/// and for trusting the embedded fleetctl. The store itself needs an
/// unsigned/signed app and a Secure Enclave, so only the decisions are
/// unit-tested.
struct KeyStoreTests {
    private func decide(usable: Bool, allowed: Bool, files: Bool, marker: Bool) -> KeyStoreChoice {
        KeyStoreChoice.decide(
            keychainUsable: usable, fallbackAllowed: allowed, fileKeysExist: files,
            keychainMarker: marker)
    }

    @Test func signedKeychainWorks() {
        #expect(decide(usable: true, allowed: false, files: false, marker: false) == .keychain)
        #expect(decide(usable: true, allowed: false, files: false, marker: true) == .keychain)
    }

    /// Ad-hoc run first, team-signed later: migrate files into the Keychain.
    @Test func fallbackFilesMigrateWhenKeychainAppears() {
        #expect(decide(usable: true, allowed: false, files: true, marker: false) == .migrateThenKeychain)
        #expect(decide(usable: true, allowed: true, files: true, marker: false) == .migrateThenKeychain)
    }

    @Test func adHocUsesFallbackOnFreshMac() {
        #expect(decide(usable: false, allowed: true, files: false, marker: false) == .fallback)
        #expect(decide(usable: false, allowed: true, files: true, marker: false) == .fallback)
    }

    /// Team-signed then ad hoc: the Keychain keys can't be read; never make
    /// a second set.
    @Test func adHocAfterSignedKeysIsBlocked() {
        #expect(decide(usable: false, allowed: true, files: false, marker: true)
                == .refuse(.signedKeysExist))
        #expect(decide(usable: false, allowed: true, files: true, marker: true)
                == .refuse(.signedKeysExist))
    }

    /// A team-signed (or flag-less) build fails closed on a Keychain refusal.
    @Test func signedBuildNeverFallsBack() {
        for files in [false, true] {
            for marker in [false, true] {
                #expect(decide(usable: false, allowed: false, files: files, marker: marker)
                        == .refuse(.notAdHoc))
            }
        }
    }

    /// The peer check validates a running SecCode against `cdhash H"..."`;
    /// a running process never satisfies a cdhash it doesn't have.
    @Test func cdhashRequirementRejectsOtherHash() {
        var me: SecCode?
        #expect(SecCodeCopySelf([], &me) == errSecSuccess)
        var req: SecRequirement?
        let bogus = String(repeating: "ab", count: 20)
        #expect(SecRequirementCreateWithString("cdhash H\"\(bogus)\"" as CFString, [], &req)
            == errSecSuccess)
        guard let me, let req else { return }
        #expect(SecCodeCheckValidity(me, [], req) != errSecSuccess)
    }

    /// Signed builds probe the fallback files for every account, including
    /// Keychain-only ones ("sync-key"): that must be false, never a throw.
    @Test func signedModeFileProbeForKeychainOnlyAccount() throws {
        #expect(!LocalKeyStore.supports("sync-key"))
        #expect(try !LocalKeyStore.existsIfSupported("sync-key"))
    }

    @Test func keyDirAllowsSymlinkedAncestorRejectsSymlinkedKeystore() throws {
        let fm = FileManager.default
        let root = "/tmp/flks-\(UUID().uuidString.prefix(8))"  // /tmp -> /private/tmp
        defer { try? fm.removeItem(atPath: root) }
        try fm.createDirectory(atPath: root + "/data", withIntermediateDirectories: true,
                               attributes: [.posixPermissions: 0o700])
        let base = URL(fileURLWithPath: root + "/data")
        // Symlinked ancestor: passes; no directory yet -> `missing`, not unsafe.
        #expect(throws: LocalKeyStore.Failure.self) {
            _ = try LocalKeyStore.keyDir(base: base, create: false)
        }
        let made = try LocalKeyStore.keyDir(base: base, create: true)
        #expect(made.hasSuffix("/keystore"))
        #expect(try LocalKeyStore.keyDir(base: base, create: false) == made)
        // The keystore directory itself a symlink: rejected.
        try fm.removeItem(atPath: made)
        try fm.createDirectory(atPath: root + "/elsewhere", withIntermediateDirectories: true,
                               attributes: [.posixPermissions: 0o700])
        try fm.createSymbolicLink(atPath: made, withDestinationPath: root + "/elsewhere")
        do {
            _ = try LocalKeyStore.keyDir(base: base, create: false)
            Issue.record("symlinked keystore accepted")
        } catch LocalKeyStore.Failure.unsafe {
        }
    }

    @Test func cdhashDecision() {
        #expect(McpSocketServer.cdhashAccepted(actual: "ab12", pinned: "AB12"))
        #expect(!McpSocketServer.cdhashAccepted(actual: "ab13", pinned: "ab12"))
        #expect(!McpSocketServer.cdhashAccepted(actual: nil, pinned: "ab12"))
    }
}
