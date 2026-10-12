import XCTest
@testable import ConsentCore

private final class InstallerFixture: MigrationInstallerSession {
    var executionMayHaveDispatched = false
    var canReconcile = false
    var events: [String] = []
    var executeStatus = "verified", finalizeStatus = "verified"
    var failExecute = false
    let transition: String
    init(_ transition: String) { self.transition = transition }
    func execute() throws -> MigrationInstallerReply {
        events.append("execute"); executionMayHaveDispatched = true
        if failExecute { throw MigrationConsoleError.unavailable }
        canReconcile = executeStatus == "unknown"
        return MigrationInstallerReply(status:executeStatus,transitionID:transition,scope:"custody-broker-config")
    }
    func reconcile() throws -> MigrationInstallerReply {
        events.append("reconcile"); canReconcile = false
        return MigrationInstallerReply(status:"verified",transitionID:transition,scope:"custody-broker-config")
    }
    func finalize() throws -> MigrationInstallerReply {
        events.append("finalize")
        return MigrationInstallerReply(status:finalizeStatus,transitionID:transition,scope:"runtime-artifacts",runtime:try MigrationInstallerRuntime(brokerPID:123,brokerStartToken:"123:456"))
    }
    func cancel() { events.append("cancel"); canReconcile = false }
}
private final class UpgradeProvider: MigrationUpgradePreparationProvider {
    let prepared: MigrationNativePreparation
    var events: [String] = []
    var failReadiness = false
    var failQuiescence = false
    var prepareError: Error?
    var lifecycleMayHaveChanged = false
    init(_ prepared: MigrationNativePreparation) { self.prepared = prepared }
    func prepare(_ intent: MigrationUpgradeIntent) async throws -> MigrationNativePreparation {
        events.append("prepare")
        if let prepareError { throw prepareError }
        return prepared
    }
    func quiesce(_ preparation: MigrationNativePreparation) async throws {
        events.append("quiesce")
        if failQuiescence { throw MigrationUpgradeError.recoveryRequired }
    }
    func restartAndVerifyRuntime(_ preparation: MigrationNativePreparation, terminal: MigrationInstallerReply) async throws {
        events.append("readiness")
        if failReadiness { throw MigrationConsoleError.unavailable }
    }
    func cancel(_ preparation: MigrationNativePreparation?) async { events.append("cancel") }
}
final class MigrationUpgradeCoordinatorTests: XCTestCase {
    @MainActor func testOnlyClosedPreparationFailureReachesUIWithoutStartingInstaller() async throws {
        for known in [true, false] {
            let (intent, prepared) = try fixture(), provider = UpgradeProvider(prepared)
            provider.prepareError = known ? MigrationObserverReadinessError.loadedPath : NSError(domain:"private-resource-canary",code:1)
            var launches = 0
            let coordinator = MigrationUpgradeCoordinator(backend:provider) { _,_ in
                launches += 1
                return InstallerFixture(prepared.preparation.transitionID)
            }
            do { try await coordinator.startApprovedUpgrade(intent); XCTFail("Expected preparation failure") } catch {}
            XCTAssertEqual(launches,0)
            XCTAssertEqual(coordinator.failureCode,known ? "loadedPath" : nil)
            XCTAssertEqual(UserDefaults.standard.string(forKey:"MechanizeRuntimeUpgradeFailureCode"),known ? "loadedPath" : nil)
            XCTAssertFalse(coordinator.canInspectRecovery)
        }
    }
    func fixture() throws -> (MigrationUpgradeIntent, MigrationNativePreparation) {
        let fixtures = MigrationNativePreparationTests()
        let intent = try fixtures.intent()
        return (intent, try MigrationNativePreparation.decode(fixtures.packet(intent),intent:intent,requestID:fixtures.hex("1"),validUntil:Date().addingTimeInterval(60)))
    }
    @MainActor func testUnavailableWithoutProductionProvider() { XCTAssertEqual(MigrationUpgradeCoordinator().state,.unavailable) }
    @MainActor func testSingleExecuteFinalizeAndIndependentReadiness() async throws {
        let (intent,prepared) = try fixture(), provider = UpgradeProvider(prepared), worker = InstallerFixture(prepared.preparation.transitionID)
        let coordinator = MigrationUpgradeCoordinator(backend:provider) { _, actual in
            XCTAssertEqual(actual.itemIdentity,prepared.itemIdentity); return worker
        }
        try await coordinator.startApprovedUpgrade(intent)
        XCTAssertEqual(coordinator.state,.complete); XCTAssertEqual(worker.events,["execute","finalize"])
        XCTAssertEqual(provider.events,["prepare","quiesce","readiness"])
        do { try await coordinator.startApprovedUpgrade(intent); XCTFail("replayed") } catch { }
        XCTAssertEqual(worker.events,["execute","finalize"])
    }
    @MainActor func testUnknownReconcilesSameSessionWithoutReplay() async throws {
        let (intent,prepared) = try fixture(), provider = UpgradeProvider(prepared), worker = InstallerFixture(prepared.preparation.transitionID)
        worker.executeStatus = "unknown"
        var launches = 0
        let coordinator = MigrationUpgradeCoordinator(backend:provider) { _,_ in launches += 1; return worker }
        try await coordinator.startApprovedUpgrade(intent)
        XCTAssertEqual(coordinator.state,.recoveryRequired); XCTAssertTrue(coordinator.canInspectRecovery)
        try await coordinator.inspectRecovery()
        XCTAssertEqual(coordinator.state,.complete); XCTAssertEqual(launches,1)
        XCTAssertEqual(worker.events,["execute","reconcile","finalize"])
    }
    @MainActor func testLostExecuteCannotReplayOrReconcile() async throws {
        let (intent,prepared) = try fixture(), provider = UpgradeProvider(prepared), worker = InstallerFixture(prepared.preparation.transitionID)
        worker.failExecute = true
        let coordinator = MigrationUpgradeCoordinator(backend:provider) { _,_ in worker }
        do { try await coordinator.startApprovedUpgrade(intent); XCTFail("lost reply") } catch { }
        XCTAssertEqual(coordinator.state,.recoveryRequired); XCTAssertFalse(coordinator.canInspectRecovery)
        XCTAssertEqual(worker.events,["execute","cancel"]); XCTAssertFalse(provider.events.contains("readiness"))
    }
    @MainActor func testFinalizationUnknownNeverRestartsOrRetries() async throws {
        let (intent,prepared) = try fixture(), provider = UpgradeProvider(prepared), worker = InstallerFixture(prepared.preparation.transitionID)
        worker.finalizeStatus = "unknown"
        let coordinator = MigrationUpgradeCoordinator(backend:provider) { _,_ in worker }
        do { try await coordinator.startApprovedUpgrade(intent); XCTFail("unknown") } catch { }
        XCTAssertEqual(coordinator.state,.recoveryRequired); XCTAssertFalse(coordinator.canInspectRecovery)
        XCTAssertFalse(provider.events.contains("readiness")); XCTAssertEqual(worker.events,["execute","finalize","cancel"])
    }
    @MainActor func testReadinessFailureIsNotCompletion() async throws {
        let (intent,prepared) = try fixture(), provider = UpgradeProvider(prepared), worker = InstallerFixture(prepared.preparation.transitionID)
        provider.failReadiness = true
        let coordinator = MigrationUpgradeCoordinator(backend:provider) { _,_ in worker }
        do { try await coordinator.startApprovedUpgrade(intent); XCTFail("readiness") } catch { }
        XCTAssertEqual(coordinator.state,.recoveryRequired); XCTAssertFalse(coordinator.canInspectRecovery)
    }
    @MainActor func testQuiescenceFailureNeverLaunchesInstallerAndRetainsLifecycleUncertainty() async throws {
        for changed in [false, true] {
            let (intent, prepared) = try fixture(), provider = UpgradeProvider(prepared)
            provider.failQuiescence = true; provider.lifecycleMayHaveChanged = changed
            var launches = 0
            let coordinator = MigrationUpgradeCoordinator(backend: provider) { _, _ in launches += 1; throw MigrationUpgradeError.unavailable }
            do { try await coordinator.startApprovedUpgrade(intent); XCTFail("quiescence failure continued") } catch {}
            XCTAssertEqual(launches, 0)
            XCTAssertEqual(coordinator.state, changed ? .recoveryRequired : .failed)
            do { try await coordinator.startApprovedUpgrade(intent); XCTFail("shutdown replayed") } catch {}
            XCTAssertEqual(provider.events.filter { $0 == "quiesce" }.count, 1)
        }
    }

}
