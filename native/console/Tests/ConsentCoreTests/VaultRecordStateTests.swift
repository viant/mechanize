import XCTest
@testable import ConsentCore

final class VaultRecordStateTests: XCTestCase {
    func testUnavailableBusyAndDuplicateEntryAreRefused() {
        var state = VaultRecordState()
        XCTAssertFalse(state.beginEntry())
        state.refreshed(ready: true); state.busy = true
        XCTAssertFalse(state.beginEntry())
        state.busy = false; XCTAssertTrue(state.beginEntry())
        XCTAssertTrue(state.blocksOtherEntry); XCTAssertFalse(state.beginEntry())
        state.finish(.cancelled); XCTAssertTrue(state.canEdit)
    }
    func testUnknownOperationAndCleanupHaveIndependentBarriers() {
        var state = VaultRecordState(); state.refreshed(ready: true)
        XCTAssertTrue(state.beginEntry()); state.finish(.operationAndCleanupUnconfirmed)
        XCTAssertFalse(state.canEdit); XCTAssertFalse(state.entryOpen)
        state.refreshed(ready: true)
        XCTAssertTrue(state.cleanupRequired); XCTAssertTrue(state.outcomeUnconfirmed); XCTAssertFalse(state.canEdit)
        state.recovered(); XCTAssertFalse(state.canEdit)
    }
    func testRecoveryDoesNotClaimUnknownOperationSucceeded() {
        var state = VaultRecordState(); state.refreshed(ready: true)
        _ = state.beginEntry(); state.finish(.operationAndCleanupUnconfirmed)
        state.recovered(); XCTAssertTrue(state.outcomeUnconfirmed); XCTAssertFalse(state.canEdit)
        state.refreshed(ready: true); XCTAssertFalse(state.canEdit)
    }
    func testReadinessRefreshCannotClearUnknownMutation() {
        var state = VaultRecordState(); state.refreshed(ready: true)
        _ = state.beginEntry(); state.finish(.operationUnconfirmed)
        state.refreshed(ready: false)
        XCTAssertTrue(state.outcomeUnconfirmed); XCTAssertFalse(state.canEdit)
        state.refreshed(ready: true); XCTAssertTrue(state.outcomeUnconfirmed); XCTAssertFalse(state.canEdit)
    }
    func testAcknowledgedMutationWithFailedCleanupKeepsBarrier() {
        for result: VaultRecordState.Completion in [.savedCleanupUnconfirmed, .deletedCleanupUnconfirmed] {
            var state = VaultRecordState(); state.refreshed(ready: true)
            _ = state.beginEntry(); state.finish(result)
            XCTAssertFalse(state.outcomeUnconfirmed); XCTAssertTrue(state.cleanupRequired)
            state.refreshed(ready: true); XCTAssertFalse(state.canEdit)
            state.recovered(); XCTAssertTrue(state.canEdit)
        }
    }
    func testRestartedMutationGuardSurvivesRefreshAndProtectionRecovery() {
        var state = VaultRecordState()
        state.restoreGuard(.init(protection: true, mutation: true, generation: "public-generation"))
        state.refreshed(ready: true); state.recovered()
        XCTAssertTrue(state.outcomeUnconfirmed); XCTAssertFalse(state.cleanupRequired)
        XCTAssertFalse(state.canEdit)
    }
    func testGuardFailureRemainsBlockedAfterRefreshAndRecovery() {
        var state = VaultRecordState()
        state.guardFailed(); state.refreshed(ready: true); state.recovered()
        XCTAssertTrue(state.guardUnavailable); XCTAssertFalse(state.canEdit)
        XCTAssertTrue(state.blocksOtherEntry)
    }

    func testReadinessFailureDoesNotInventProtectionLease() {
        var state = VaultRecordState(); state.refreshed(ready: true)
        XCTAssertTrue(state.beginEntry())
        state.finish(.entryUnavailable)
        XCTAssertFalse(state.entryOpen); XCTAssertFalse(state.cleanupRequired)
        XCTAssertNil(state.keyReady); XCTAssertFalse(state.canEdit)
        state.refreshed(ready: true)
        XCTAssertTrue(state.canEdit)
    }
    func testUnconfirmedEntryStartRequiresRecoveryButNotMutationReconciliation() {
        var state = VaultRecordState(); state.refreshed(ready: true)
        XCTAssertTrue(state.beginEntry())
        state.finish(.entryStartFailed)
        XCTAssertFalse(state.entryOpen); XCTAssertTrue(state.cleanupRequired)
        XCTAssertFalse(state.outcomeUnconfirmed); XCTAssertFalse(state.canEdit)
        state.refreshed(ready: true)
        XCTAssertFalse(state.canEdit)
        state.recovered()
        XCTAssertTrue(state.canEdit)
    }
}
