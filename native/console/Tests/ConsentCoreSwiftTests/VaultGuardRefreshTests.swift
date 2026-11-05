import Foundation
import Testing
import Darwin
@testable import ConsentCore

struct VaultGuardRefreshTests {
    @Test func repairedDirectoryCanBeRecheckedWithoutRestartOrMarkerReset() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: root) }
        let guardStore = VaultRecordGuard(parent: root)
        let generation = try guardStore.beginProtection()
        try guardStore.acknowledgeProtection(generation: generation)
        #expect(chmod(root.path, 0o755) == 0)
        #expect(throws: VaultRecordGuardError.self) { try guardStore.status() }
        var state = VaultRecordState(); state.guardFailed(); state.refreshed(ready: true)
        #expect(!state.canEdit)
        #expect(chmod(root.path, 0o700) == 0)
        state.guardRechecked(try guardStore.status())
        #expect(!state.guardUnavailable && state.canEdit)
        #expect(try FileManager.default.contentsOfDirectory(atPath: root.appendingPathComponent("console-native-record-guard").path) == ["lock"])
    }
    @Test func freshGuardReadPreservesUnconfirmedMutationAndProtection() {
        var state = VaultRecordState()
        state.guardFailed(); state.refreshed(ready: true)
        state.guardRechecked(.init(protection: true, mutation: true, generation: "retained"))
        #expect(!state.guardUnavailable && state.cleanupRequired && state.outcomeUnconfirmed && !state.canEdit)
        state.guardRechecked(.init())
        #expect(state.cleanupRequired && state.outcomeUnconfirmed && !state.canEdit)
        state.recovered()
        state.guardRechecked(.init())
        #expect(state.outcomeUnconfirmed && !state.canEdit)
    }
    @Test func readinessOrRecoveryAloneDoesNotClearUnavailableGuard() {
        var state = VaultRecordState()
        state.guardFailed(); state.refreshed(ready: true); state.recovered()
        #expect(state.guardUnavailable && !state.canEdit)
    }
}
