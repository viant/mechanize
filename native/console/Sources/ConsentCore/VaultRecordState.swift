import Foundation

/// UI admission state contains only public status; no secret form data.
public struct VaultRecordState: Equatable, Sendable {
    public enum Completion: Equatable, Sendable {
        case saved, deleted, cancelled, operationUnconfirmed, cleanupUnconfirmed, guardUnavailable
        case entryUnavailable, entryStartFailed
        case savedCleanupUnconfirmed, deletedCleanupUnconfirmed, operationAndCleanupUnconfirmed
    }
    public var keyReady: Bool?
    public var busy = false
    public private(set) var entryOpen = false
    public private(set) var cleanupRequired = false
    public private(set) var outcomeUnconfirmed = false
    public private(set) var guardUnavailable = false
    public init() {}
    public var canEdit: Bool { keyReady == true && !busy && !entryOpen && !cleanupRequired && !outcomeUnconfirmed && !guardUnavailable }
    public var blocksOtherEntry: Bool { busy || entryOpen || cleanupRequired || guardUnavailable }
    public mutating func beginEntry() -> Bool {
        guard canEdit else { return false }; entryOpen = true; return true
    }
    public mutating func refreshed(ready: Bool) {
        keyReady = ready
        // Readiness and inventory do not establish whether an unacknowledged
        // mutation committed. Preserve that barrier until an operation-specific
        // reconciliation protocol can establish its outcome.
    }
    public mutating func restoreGuard(_ status: VaultRecordGuardStatus) {
        cleanupRequired = cleanupRequired || status.protection
        outcomeUnconfirmed = outcomeUnconfirmed || status.mutation
    }
    public mutating func guardFailed() { guardUnavailable = true; keyReady = nil }
    public mutating func recovered() { cleanupRequired = false }
    public mutating func recoveryFailed() { cleanupRequired = true }
    public mutating func finish(_ result: Completion) {
        entryOpen = false
        switch result {
        case .saved, .deleted, .cancelled: break
        case .entryUnavailable: keyReady = nil
        case .entryStartFailed: cleanupRequired = true
        case .guardUnavailable: guardFailed()
        case .operationUnconfirmed: outcomeUnconfirmed = true; keyReady = nil
        case .cleanupUnconfirmed, .savedCleanupUnconfirmed, .deletedCleanupUnconfirmed: cleanupRequired = true
        case .operationAndCleanupUnconfirmed: outcomeUnconfirmed = true; keyReady = nil; cleanupRequired = true
        }
    }
}
