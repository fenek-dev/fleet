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

    @Test func chartMetricsFromRawSeries() {
        let v: [String: Double] = [
            "cpu.busy": 12, "mem.used": 1, "mem.total": 4, "disk.used:/": 40,
            "net.rx:eth0": 100, "net.rx:other": 50, "net.tx:eth0": 7,
        ]
        #expect(ChartMetric.cpu.value(v) == 12)
        #expect(ChartMetric.memory.value(v) == 25)
        #expect(ChartMetric.disk.value(v) == 40)
        #expect(ChartMetric.netRx.value(v) == 150)
        #expect(ChartMetric.netTx.value(v) == 7)
        #expect(ChartMetric.memory.value(["mem.used": 1, "mem.total": 0]) == nil)
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
