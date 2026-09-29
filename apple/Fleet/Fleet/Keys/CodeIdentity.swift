import Foundation
import Security

/// How this executable is signed, read from its own code signature.
enum CodeIdentity {
    /// Signed ad hoc (`codesign -s -`): the ad-hoc flag set and no team
    /// identifier. Team-signed, Developer ID and unsigned code are not.
    static let isAdHoc: Bool = {
        var me: SecCode?
        var stat: SecStaticCode?
        var info: CFDictionary?
        guard SecCodeCopySelf([], &me) == errSecSuccess, let me,
              SecCodeCopyStaticCode(me, [], &stat) == errSecSuccess, let stat,
              SecCodeCopySigningInformation(
                stat, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess,
              let dict = info as? [String: Any]
        else { return false }
        let flags = (dict[kSecCodeInfoFlags as String] as? UInt32) ?? 0
        let team = dict[kSecCodeInfoTeamIdentifier as String] as? String
        return flags & SecCodeSignatureFlags.adhoc.rawValue != 0 && (team ?? "").isEmpty
    }()
}
