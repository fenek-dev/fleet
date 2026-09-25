import CloudKit
import Foundation
import Observation
import Security

/// iCloud transport for end-to-end encrypted sync (design §7.6).
///
/// Swift only moves opaque blobs: Rust seals every record (AES-256-GCM
/// under the sync key), names it (a keyed hash, so names look random),
/// merges and verifies. Records live in a custom zone of the CloudKit
/// **private** database; each is one `FleetBlob` with a `blob` field
/// (also in `encryptedValues`, so Advanced Data Protection adds Apple's
/// layer on top of ours).
///
/// **Runtime requirements:** a team-signed build with the iCloud (CloudKit)
/// capability and container `iCloud.dev.fleet.Fleet` (entitlements in
/// `Fleet-iCloud.entitlements`; unsigned/ad-hoc builds lack them) and a
/// signed-in iCloud account. Without the entitlement, `CKContainer` would
/// trap, so everything here checks `CloudAvailability.enabled` first and
/// sync stays local-only.
enum CloudAvailability {
    static let enabled: Bool = {
        guard let task = SecTaskCreateFromSelf(nil) else { return false }
        let v = SecTaskCopyValueForEntitlement(
            task, "com.apple.developer.icloud-services" as CFString, nil)
        return v != nil
    }()
}

enum CloudError: Error {
    case unavailable
}

actor CloudStore {
    static let containerId = "iCloud.dev.fleet.Fleet"
    static let zoneID = CKRecordZone.ID(zoneName: "FleetSync", ownerName: CKCurrentUserDefaultName)
    static let recordType = "FleetBlob"
    private static let field = "blob"

    private let db: CKDatabase
    private var zoneReady = false

    init() throws {
        guard CloudAvailability.enabled else { throw CloudError.unavailable }
        db = CKContainer(identifier: Self.containerId).privateCloudDatabase
    }

    func ensureZone() async throws {
        if zoneReady { return }
        _ = try await db.modifyRecordZones(saving: [CKRecordZone(zoneID: Self.zoneID)], deleting: [])
        zoneReady = true
    }

    private static func row(_ r: CKRecord) -> CloudRecordRow? {
        let data = (r.encryptedValues[field] as? Data) ?? (r[field] as? Data)
        guard let data else { return nil }
        return CloudRecordRow(name: r.recordID.recordName, data: data)
    }

    private static func id(_ name: String) -> CKRecord.ID {
        CKRecord.ID(recordName: name, zoneID: zoneID)
    }

    /// Changes since `token` (all records for `nil`), following `moreComing`.
    func changes(since token: CKServerChangeToken?) async throws
        -> (records: [CloudRecordRow], deleted: [String], token: CKServerChangeToken?)
    {
        try await ensureZone()
        var token = token
        var records: [CloudRecordRow] = []
        var deleted: [String] = []
        while true {
            let res = try await db.recordZoneChanges(inZoneWith: Self.zoneID, since: token)
            for (_, r) in res.modificationResultsByID {
                if case .success(let m) = r, let row = Self.row(m.record) { records.append(row) }
            }
            deleted += res.deletions.map(\.recordID.recordName)
            token = res.changeToken
            if !res.moreComing { break }
        }
        return (records, deleted, token)
    }

    func fetch(_ names: [String]) async throws -> [CloudRecordRow] {
        try await ensureZone()
        guard !names.isEmpty else { return [] }
        let res = try await db.records(for: names.map(Self.id))
        return res.values.compactMap { r in
            if case .success(let rec) = r { return Self.row(rec) }
            return nil
        }
    }

    /// Upserts; returns the names saved.
    func save(_ rows: [CloudRecordRow]) async throws -> [String] {
        try await ensureZone()
        var saved: [String] = []
        for chunk in stride(from: 0, to: rows.count, by: 200).map({ Array(rows[$0..<min($0 + 200, rows.count)]) }) {
            let records = chunk.map { r -> CKRecord in
                let rec = CKRecord(recordType: Self.recordType, recordID: Self.id(r.name))
                rec.encryptedValues[Self.field] = r.data
                return rec
            }
            let res = try await db.modifyRecords(saving: records, deleting: [], savePolicy: .allKeys)
            for (id, r) in res.saveResults {
                if case .success = r { saved.append(id.recordName) }
            }
        }
        return saved
    }

    func delete(_ names: [String]) async throws -> [String] {
        try await ensureZone()
        guard !names.isEmpty else { return [] }
        let res = try await db.modifyRecords(saving: [], deleting: names.map(Self.id))
        return res.deleteResults.compactMap { id, r in
            switch r {
            case .success: return id.recordName
            case .failure(let e as CKError) where e.code == .unknownItem: return id.recordName
            case .failure: return nil
            }
        }
    }
}

/// Runs sync cycles: deletions → fetch changes → merge → upload.
@Observable
@MainActor
final class SyncCoordinator {
    private(set) var lastSync: Date?
    private(set) var lastError: String?
    private(set) var running = false
    var available: Bool { CloudAvailability.enabled }

    @ObservationIgnored private let store: CloudStore?
    @ObservationIgnored private weak var bridge: CoreBridge?
    @ObservationIgnored private var timer: Task<Void, Never>?
    private static let tokenKey = "sync.changeToken"

    init(bridge: CoreBridge) {
        self.bridge = bridge
        store = try? CloudStore()
    }

    /// The zone, for pairing and recovery flows.
    var cloud: CloudStore? { store }

    func start() {
        guard timer == nil else { return }
        timer = Task { [weak self] in
            while !Task.isCancelled {
                await self?.cycle()
                try? await Task.sleep(for: .seconds(60))
            }
        }
    }

    func stop() {
        timer?.cancel()
        timer = nil
    }

    private var token: CKServerChangeToken? {
        get {
            guard let d = UserDefaults.standard.data(forKey: Self.tokenKey) else { return nil }
            return try? NSKeyedUnarchiver.unarchivedObject(ofClass: CKServerChangeToken.self, from: d)
        }
        set {
            if let t = newValue,
               let d = try? NSKeyedArchiver.archivedData(withRootObject: t, requiringSecureCoding: true)
            {
                UserDefaults.standard.set(d, forKey: Self.tokenKey)
            } else {
                UserDefaults.standard.removeObject(forKey: Self.tokenKey)
            }
        }
    }

    /// Uploads records a flow produced (key boxes, escrow, pairing answer).
    func upload(_ rows: [CloudRecordRow], delete: [String] = []) async {
        guard let store, let core = bridge?.api else { return }
        do {
            if !delete.isEmpty {
                let gone = try await store.delete(delete)
                core.syncMarkDeleted(names: gone)
            }
            if !rows.isEmpty {
                let saved = try await store.save(rows)
                try core.syncMarkPushed(names: saved)
            }
        } catch {
            lastError = error.localizedDescription
        }
    }

    func cycle() async {
        guard !running, let core = bridge?.api else { return }
        running = true
        defer { running = false }
        do {
            if !core.syncReady() {
                _ = try core.syncSetup()
            }
            guard let store else {
                // No iCloud entitlement: local store only.
                lastError = nil
                return
            }
            let gone = try await store.delete(core.syncDeletions())
            core.syncMarkDeleted(names: gone)
            let (records, _, newToken) = try await store.changes(since: token)
            if !records.isEmpty {
                let report = try await Task.detached { try core.syncIngest(records: records) }.value
                if report.needsKey {
                    let name = try core.syncKeyboxRecordName()
                    if let kb = try await store.fetch([name]).first {
                        try core.syncAcceptKeybox(keybox: kb)
                        let all = try await store.changes(since: nil)
                        _ = try await Task.detached { try core.syncIngest(records: all.records) }.value
                    }
                }
            }
            token = newToken
            let out = try core.syncOutgoing()
            if !out.isEmpty {
                let saved = try await store.save(out)
                try core.syncMarkPushed(names: saved)
            }
            lastSync = Date()
            lastError = nil
        } catch FleetError.Sync(let reason) {
            lastError = reason
        } catch {
            lastError = error.localizedDescription
        }
    }
}
