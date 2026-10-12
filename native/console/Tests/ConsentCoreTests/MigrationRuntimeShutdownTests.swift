import XCTest
@testable import ConsentCore

private final class ShutdownFixtureRoute: MigrationBrokerLifecycleRoute {
    var helpers: [MigrationShutdownIdentity] = []
    var events: [String] = []
    var unsupported = false, cleanupUnknown = false, stopUnknown = false
    var onStop: (() -> Void)?
    func qualify(broker: MigrationShutdownIdentity, helperPins: [String: String], deadline: Date) throws -> [MigrationShutdownIdentity] {
        events.append("qualify")
        if unsupported { throw MigrationUpgradeError.unavailable }
        return helpers
    }
    func stop(deadline: Date, willDispatch: () throws -> Void) throws {
        try willDispatch(); events.append("stop"); onStop?()
        if stopUnknown || cleanupUnknown { throw MigrationUpgradeError.recoveryRequired }
    }
    func verifyStopped(deadline: Date) throws { events.append("verify") }
}
final class MigrationRuntimeShutdownTests: XCTestCase {
    let binding = String(repeating: "a", count: 64)
    func identity(_ pid: Int32, _ name: String) -> MigrationShutdownIdentity {
        MigrationShutdownIdentity(pid: pid, uid: getuid(), birth: "1790000000:\(pid)", executable: "/private/fixture/\(name)", requirement: "fixture-\(name)")
    }
    func testMissingCanonicalRouteCannotQuitOrSignalAnything() throws {
        var actions = 0
        let runtime = MigrationShutdownRuntime(now: Date.init, inspect: { _ in actions += 1; return .same }, quitChrome: { _, _, _ in actions += 1; return true }, wait: { _ in }, requireStopped: { _ in actions += 1 }, console: {})
        let stage = try MigrationRuntimeShutdown(intentBinding: binding, broker: identity(41,"broker"), chrome: identity(42,"Chrome"), helperPins: ["/private/fixture/helper":"fixture-helper"], capturedAt: Date(), route: nil, runtime: runtime)
        XCTAssertThrowsError(try stage.quiesce(intentBinding: binding, preparationDeadline: Date().addingTimeInterval(30)))
        XCTAssertEqual(actions, 0); XCTAssertFalse(stage.mayHaveChanged)
    }
    func testNormalQuitAndOwnedLifecycleStopAreSingleUse() throws {
        let broker=identity(41,"broker"), chrome=identity(42,"Chrome"), helper=identity(43,"helper")
        let route=ShutdownFixtureRoute();route.helpers=[helper]
        var present: Set<Int32>=[41,42,43], quits=0, allStopped=0
        route.onStop={present.remove(41);present.remove(43)}
        let runtime=MigrationShutdownRuntime(now:Date.init,inspect:{present.contains($0.pid) ? .same:.gone},quitChrome:{id,_,dispatch in
            XCTAssertEqual(route.events,["qualify","stop","verify"]);try dispatch();quits+=1;present.remove(id.pid);return true
        },wait:{_ in XCTFail("immediate fixture exit should not wait")},requireStopped:{paths in XCTAssertEqual(paths.sorted(),[broker.executable,chrome.executable,helper.executable].sorted());allStopped+=1},console:{})
        let stage=try MigrationRuntimeShutdown(intentBinding:binding,broker:broker,chrome:chrome,helperPins:[helper.executable:helper.requirement],capturedAt:Date(),route:route,runtime:runtime)
        try stage.quiesce(intentBinding:binding,preparationDeadline:Date().addingTimeInterval(30))
        XCTAssertEqual(quits,1);XCTAssertEqual(allStopped,1);XCTAssertEqual(route.events,["qualify","stop","verify","verify"])
        XCTAssertTrue(stage.mayHaveChanged)
        XCTAssertThrowsError(try stage.quiesce(intentBinding:binding,preparationDeadline:Date().addingTimeInterval(30)))
        stage.cancel();XCTAssertEqual(quits,1);XCTAssertEqual(route.events.filter{$0=="stop"}.count,1)
    }
    func testUnsavedDialogUnknownCleanupRecycledPIDAndCancellationCannotContinue() throws {
        for mode in ["unsaved", "unknown cleanup", "recycled", "cancel", "unknown stop", "unavailable probe"] {
            let broker=identity(41,"broker"),chrome=identity(42,"Chrome"),helper=identity(43,"helper"),route=ShutdownFixtureRoute();route.helpers=[helper]
            var now=Date(),quits=0,postQuit=false, brokerGone=false
            route.onStop={brokerGone=true}
            var stage:MigrationRuntimeShutdown!
            route.cleanupUnknown=mode=="unknown cleanup";route.stopUnknown=mode=="unknown stop"
            let runtime=MigrationShutdownRuntime(now:{now},inspect:{id in
                if brokerGone && id.pid != 42 { return .gone }
                if id.pid==42 && postQuit {
                    if mode=="recycled" {return .replaced}
                    if mode=="unavailable probe" {return .unavailable}
                    if mode=="unknown stop" {return .gone}
                }
                return .same
            },quitChrome:{_,_,dispatch in try dispatch();quits+=1;postQuit=true;if mode=="cancel"{stage.cancel()};return true},wait:{now=now.addingTimeInterval($0)},requireStopped:{_ in XCTFail("uncertain shutdown reached proof")},console:{})
            stage=try MigrationRuntimeShutdown(intentBinding:binding,broker:broker,chrome:chrome,helperPins:[helper.executable:helper.requirement],capturedAt:now,route:route,runtime:runtime)
            XCTAssertThrowsError(try stage.quiesce(intentBinding:binding,preparationDeadline:now.addingTimeInterval(30)),mode)
            XCTAssertTrue(stage.mayHaveChanged,mode)
            XCTAssertEqual(quits,["unknown cleanup","unknown stop"].contains(mode) ? 0:1)
            XCTAssertEqual(route.events.filter{$0=="stop"}.count,1)
            XCTAssertThrowsError(try stage.quiesce(intentBinding:binding,preparationDeadline:now.addingTimeInterval(30)))
        }
    }
    func testExpiredEvidenceOrForeignOwnedHelperCannotStartShutdown() throws {
        for mode in ["expired", "foreign helper", "recycled initial", "unsupported lifecycle"] {
            let broker=identity(41,"broker"),chrome=identity(42,"Chrome"),helper=identity(43,"helper"),route=ShutdownFixtureRoute()
            route.helpers=mode=="foreign helper" ? [identity(44,"unrelated")]:[helper]
            route.unsupported=mode=="unsupported lifecycle"
            let runtime=MigrationShutdownRuntime(now:Date.init,inspect:{_ in mode=="recycled initial" ? .replaced:.same},quitChrome:{_,_,_ in XCTFail("unqualified quit");return false},wait:{_ in},requireStopped:{_ in XCTFail("unqualified proof")},console:{})
            let stage=try MigrationRuntimeShutdown(intentBinding:binding,broker:broker,chrome:chrome,helperPins:[helper.executable:helper.requirement],capturedAt:Date().addingTimeInterval(mode=="expired" ? -31:0),route:route,runtime:runtime)
            XCTAssertThrowsError(try stage.quiesce(intentBinding:binding,preparationDeadline:Date().addingTimeInterval(30)))
            XCTAssertFalse(stage.mayHaveChanged);XCTAssertFalse(route.events.contains("stop"))
        }
    }
    func testPreparationDeadlineCannotExtendOriginalEvidenceFreshness() throws {
        var now = Date(), quits = 0
        let initial = now, route = ShutdownFixtureRoute(), broker = identity(41,"broker"), chrome = identity(42,"Chrome"), helper = identity(43,"helper")
        route.helpers = [helper]
        var stopped = false; route.onStop = { stopped = true }
        let runtime = MigrationShutdownRuntime(now: { now }, inspect: { identity in stopped && identity.pid != 42 ? .gone : .same }, quitChrome: { _, _, dispatch in
            try dispatch(); quits += 1; return true
        }, wait: { now = now.addingTimeInterval($0) }, requireStopped: { _ in XCTFail("expired evidence accepted") }, console: {})
        let stage = try MigrationRuntimeShutdown(intentBinding: binding, broker: broker, chrome: chrome, helperPins: [helper.executable:helper.requirement], capturedAt: now.addingTimeInterval(-29.99), route: route, runtime: runtime)
        XCTAssertThrowsError(try stage.quiesce(intentBinding: binding, preparationDeadline: now.addingTimeInterval(240)))
        XCTAssertEqual(quits, 1); XCTAssertTrue(stage.mayHaveChanged)
        XCTAssertLessThanOrEqual(now.timeIntervalSince(initial), 0.03)
        XCTAssertEqual(route.events.filter { $0 == "stop" }.count, 1)
    }

}
