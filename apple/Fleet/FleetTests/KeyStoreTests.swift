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

    @Test func cdhashDecision() {
        #expect(McpSocketServer.cdhashAccepted(actual: "ab12", pinned: "AB12"))
        #expect(!McpSocketServer.cdhashAccepted(actual: "ab13", pinned: "ab12"))
        #expect(!McpSocketServer.cdhashAccepted(actual: nil, pinned: "ab12"))
    }
}
