import Foundation
import Testing
@testable import Fleet

struct FleetTests {
    @Test func healthSortsWorstFirst() {
        let order: [ConnState] = [.ready, .offline, .connecting, .degraded]
        let sorted = order.sorted { $0.rank < $1.rank }
        #expect(sorted == [.offline, .degraded, .connecting, .ready])
    }

    @Test func formatsUptime() {
        #expect(Format.uptime(nil) == "–")
        #expect(Format.uptime(59 * 60) == "59 min")
        #expect(Format.uptime(3 * 3600) == "3 h")
        #expect(Format.uptime(12 * 86_400 + 5) == "12 d")
    }

    /// Device and SSH keys refuse to sign while locked, before touching the
    /// Keychain or the enclave.
    @Test func lockedGateRefusesDeviceAndSsh() throws {
        let gate = KeyGate()
        let keys = try SecureEnclaveKeys(gate: gate, environment: ["FLEET_SOFTWARE_KEYS": "1"])
        #expect(throws: SignerError.Unavailable) { try keys.sign(role: .device, msg: Data("m".utf8)) }
        #expect(throws: SignerError.Unavailable) { try keys.sign(role: .ssh, msg: Data("m".utf8)) }
    }
}
