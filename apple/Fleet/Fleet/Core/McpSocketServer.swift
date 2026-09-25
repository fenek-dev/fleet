import Darwin
import Foundation
import Security

/// The MCP socket (design §5.10): `~/Library/Application Support/Fleet/mcp.sock`,
/// mode 0600, served by the app.
///
/// Per connection: the peer must be our own signed `fleetctl`, checked by
/// code signature from the socket's audit token (`LOCAL_PEERTOKEN`, no pid
/// race). The code signature of `fleetctl`'s parent process (the MCP
/// client) is read too and becomes part of the pairing identity; pairing,
/// pause, lock, rate limits and approvals are enforced in Rust
/// (`fleet_core::mcp_host`). Frames are a 4-byte big-endian length and a
/// JSON body; each body goes to `McpConnection.handle`.
///
/// Blocking I/O on one thread per connection (a handful of MCP clients).
final class McpSocketServer: @unchecked Sendable {
    enum SocketError: Error {
        case pathTooLong
        case posix(String, Int32)
    }

    /// Identifier `fleetctl` is signed with in release builds.
    static let fleetctlIdentifier = "dev.fleet.fleetctl"

    let path: String
    private let connect: @Sendable (McpPeerRow) -> McpConnection
    private let lock = NSLock()
    private var listenFd: Int32 = -1

    init(path: String, connect: @escaping @Sendable (McpPeerRow) -> McpConnection) {
        self.path = path
        self.connect = connect
    }

    static func defaultPath() throws -> String {
        let dir = try FileManager.default.url(
            for: .applicationSupportDirectory, in: .userDomainMask,
            appropriateFor: nil, create: true
        ).appendingPathComponent("Fleet", isDirectory: true)
        try FileManager.default.createDirectory(
            at: dir, withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700])
        return dir.appendingPathComponent("mcp.sock").path
    }

    func start() throws {
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw SocketError.posix("socket", errno) }
        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let bytes = Array(path.utf8)
        guard bytes.count < MemoryLayout.size(ofValue: addr.sun_path) else {
            close(fd)
            throw SocketError.pathTooLong
        }
        withUnsafeMutableBytes(of: &addr.sun_path) { buf in
            buf.copyBytes(from: bytes)
            buf[bytes.count] = 0
        }
        addr.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        unlink(path)
        // Created 0600 from the start (no window with a wider mode).
        let oldMask = umask(0o177)
        let rc = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        umask(oldMask)
        guard rc == 0 else {
            let e = errno
            close(fd)
            throw SocketError.posix("bind", e)
        }
        chmod(path, 0o600)
        guard listen(fd, 8) == 0 else {
            let e = errno
            close(fd)
            throw SocketError.posix("listen", e)
        }
        lock.withLock { listenFd = fd }
        let thread = Thread { [self] in acceptLoop(fd) }
        thread.name = "fleet-mcp-accept"
        thread.start()
    }

    func stop() {
        let fd = lock.withLock { () -> Int32 in
            let fd = listenFd
            listenFd = -1
            return fd
        }
        if fd >= 0 {
            close(fd)
            unlink(path)
        }
    }

    private func acceptLoop(_ fd: Int32) {
        while true {
            let client = accept(fd, nil, nil)
            if client < 0 {
                if errno == EINTR { continue }
                return
            }
            var one: Int32 = 1
            setsockopt(client, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size))
            guard let peer = Self.verifyPeer(client) else {
                close(client)
                continue
            }
            let conn = connect(peer)
            let t = Thread { Self.serve(client, conn) }
            t.name = "fleet-mcp-conn"
            t.start()
        }
    }

    // MARK: peer checks

    private static let solLocal: Int32 = 0          // SOL_LOCAL
    private static let localPeerPid: Int32 = 0x002  // LOCAL_PEERPID
    private static let localPeerToken: Int32 = 0x006 // LOCAL_PEERTOKEN

    /// The peer is our `fleetctl`; returns its parent's signature.
    static func verifyPeer(_ fd: Int32) -> McpPeerRow? {
        var token = audit_token_t()
        var len = socklen_t(MemoryLayout<audit_token_t>.size)
        guard getsockopt(fd, solLocal, localPeerToken, &token, &len) == 0 else { return nil }
        let tokenData = withUnsafeBytes(of: &token) { Data($0) }
        var code: SecCode?
        let attrs = [kSecGuestAttributeAudit: tokenData] as CFDictionary
        guard SecCodeCopyGuestWithAttributes(nil, attrs, [], &code) == errSecSuccess,
              let code, isOurFleetctl(code)
        else { return nil }

        var pid: pid_t = 0
        var plen = socklen_t(MemoryLayout<pid_t>.size)
        guard getsockopt(fd, solLocal, localPeerPid, &pid, &plen) == 0,
              let ppid = parentPid(of: pid)
        else { return nil }
        let (team, ident) = signature(ofPid: ppid)
        return McpPeerRow(parentTeam: team, parentSigningId: ident)
    }

    private static func teamId(_ code: SecStaticCode) -> String? {
        var info: CFDictionary?
        guard SecCodeCopySigningInformation(
            code, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess,
            let dict = info as? [String: Any]
        else { return nil }
        return dict[kSecCodeInfoTeamIdentifier as String] as? String
    }

    private static func ownTeam() -> String? {
        var me: SecCode?
        var stat: SecStaticCode?
        guard SecCodeCopySelf([], &me) == errSecSuccess, let me,
              SecCodeCopyStaticCode(me, [], &stat) == errSecSuccess, let stat
        else { return nil }
        return teamId(stat)
    }

    /// Signed by our team as `dev.fleet.fleetctl`. Unsigned development
    /// builds (no team) accept only the `fleetctl` inside this app bundle.
    private static func isOurFleetctl(_ code: SecCode) -> Bool {
        if let team = ownTeam() {
            let req = "anchor apple generic and identifier \"\(fleetctlIdentifier)\" "
                + "and certificate leaf[subject.OU] = \"\(team)\""
            var requirement: SecRequirement?
            guard SecRequirementCreateWithString(req as CFString, [], &requirement) == errSecSuccess,
                  let requirement
            else { return false }
            return SecCodeCheckValidity(code, [], requirement) == errSecSuccess
        }
        #if DEBUG
        var stat: SecStaticCode?
        var url: CFURL?
        guard SecCodeCopyStaticCode(code, [], &stat) == errSecSuccess, let stat,
              SecCodeCopyPath(stat, [], &url) == errSecSuccess, let url
        else { return false }
        let bundled = Bundle.main.bundleURL
            .appendingPathComponent("Contents/MacOS/fleetctl").resolvingSymlinksInPath()
        return (url as URL).resolvingSymlinksInPath() == bundled
        #else
        return false
        #endif
    }

    private static func parentPid(of pid: pid_t) -> pid_t? {
        var info = kinfo_proc()
        var size = MemoryLayout<kinfo_proc>.stride
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, pid]
        guard sysctl(&mib, 4, &info, &size, nil, 0) == 0, size > 0 else { return nil }
        let ppid = info.kp_eproc.e_ppid
        return ppid > 1 ? ppid : nil
    }

    /// Team id and signing identifier ("" / executable name if unsigned).
    /// By pid: the parent can't hand us an audit token (pid reuse between
    /// the lookup and here is possible but only mislabels the pairing).
    private static func signature(ofPid pid: pid_t) -> (String, String) {
        var code: SecCode?
        var stat: SecStaticCode?
        let attrs = [kSecGuestAttributePid: pid] as CFDictionary
        guard SecCodeCopyGuestWithAttributes(nil, attrs, [], &code) == errSecSuccess, let code,
              SecCodeCopyStaticCode(code, [], &stat) == errSecSuccess, let stat
        else { return ("", "unknown") }
        var info: CFDictionary?
        _ = SecCodeCopySigningInformation(
            stat, SecCSFlags(rawValue: kSecCSSigningInformation), &info)
        let dict = (info as? [String: Any]) ?? [:]
        let team = dict[kSecCodeInfoTeamIdentifier as String] as? String ?? ""
        var ident = dict[kSecCodeInfoIdentifier as String] as? String ?? ""
        if ident.isEmpty {
            var url: CFURL?
            if SecCodeCopyPath(stat, [], &url) == errSecSuccess, let url {
                ident = (url as URL).lastPathComponent
            }
        }
        return (team, ident.isEmpty ? "unknown" : ident)
    }

    // MARK: frames

    private final class Box: @unchecked Sendable {
        var data = Data()
    }

    private static func serve(_ fd: Int32, _ conn: McpConnection) {
        defer { close(fd) }
        let maxFrame = Int(mcpMaxFrame())
        while true {
            guard let header = readExact(fd, 4) else { return }
            let n = header.reduce(0) { ($0 << 8) | Int($1) }
            guard n > 0, n <= maxFrame, let body = readExact(fd, n) else { return }
            let box = Box()
            let done = DispatchSemaphore(value: 0)
            Task.detached {
                box.data = await conn.handle(body: body)
                done.signal()
            }
            done.wait()
            guard writeAll(fd, box.data) else { return }
        }
    }

    private static func readExact(_ fd: Int32, _ n: Int) -> Data? {
        var out = Data(count: n)
        var got = 0
        while got < n {
            let r = out.withUnsafeMutableBytes { buf in
                read(fd, buf.baseAddress! + got, n - got)
            }
            if r < 0 && errno == EINTR { continue }
            if r <= 0 { return nil }
            got += r
        }
        return out
    }

    private static func writeAll(_ fd: Int32, _ data: Data) -> Bool {
        var sent = 0
        while sent < data.count {
            let r = data.withUnsafeBytes { buf in
                write(fd, buf.baseAddress! + sent, data.count - sent)
            }
            if r < 0 && errno == EINTR { continue }
            if r <= 0 { return false }
            sent += r
        }
        return true
    }
}
