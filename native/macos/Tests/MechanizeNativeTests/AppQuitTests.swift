import XCTest
@testable import MechanizeNative
import MechanizeNativeCore

final class AppQuitTests: XCTestCase {
    let params: [String: Any] = ["expectedApp": "com.fixture.app", "pid": 42, "launchTime": "kernel:1790000000:1", "startToken": "1790000000:1"]
    func entry(owner: UInt32? = 501, token: String = "1790000000:1") -> ApplicationInventoryEntry {
        ApplicationInventoryEntry(pid: 42, bundleID: "com.fixture.app", name: "Fixture", owner: owner, launchTime: nil, startToken: token, active: false, terminated: false)
    }
    func testAcceptedQuitRequiresIndependentExitAndNeverReplays() throws {
        for status: Bool? in [true, false, nil] {
            var submissions = 0, reservations = 0, reads = 0
            let runtime = ApplicationQuitRuntime(list: { _ in [self.entry()] }, terminate: { _, dispatch in
                try dispatch(); submissions += 1; return true
            }, exited: { _ in reads += 1; return status }, wait: { _ in })
            let reply = try quitApplication(params, Budget(milliseconds: 1000), runtime: runtime, uid: 501) { reservations += 1 }
            XCTAssertEqual(submissions, 1); XCTAssertEqual(reservations, 1); XCTAssertGreaterThan(reads, 0)
            XCTAssertEqual(reply.dispatchState, status == true ? "dispatched" : "unknown")
            XCTAssertEqual(reply.result["exitConfirmed"] as? Bool, status == true)
            XCTAssertEqual(reply.failure == nil, status == true)
        }
    }
    func testIdentityAndAuthorityFailuresDoNotSubmit() throws {
        for entries in [[], [entry(token: "1790000000:2")], [entry(owner: 502)], [entry(), entry()]] {
            var submissions = 0, reservations = 0
            let runtime = ApplicationQuitRuntime(list: { _ in entries }, terminate: { _, dispatch in try dispatch(); submissions += 1; return true }, exited: { _ in true }, wait: { _ in })
            XCTAssertThrowsError(try quitApplication(params, Budget(milliseconds: 1000), runtime: runtime, uid: 501) { reservations += 1 })
            XCTAssertEqual(submissions, 0); XCTAssertEqual(reservations, 0)
        }
        var submissions = 0
        let runtime = ApplicationQuitRuntime(list: { _ in [self.entry()] }, terminate: { _, dispatch in try dispatch(); submissions += 1; return true }, exited: { _ in true }, wait: { _ in })
        XCTAssertThrowsError(try quitApplication(params, Budget(milliseconds: 1000), runtime: runtime, uid: 501) { throw NativeFailure("staleLease", "fixture") })
        XCTAssertEqual(submissions, 0)
        var invalid = params; invalid["force"] = true
        XCTAssertThrowsError(try quitApplication(invalid, Budget(milliseconds: 1000), runtime: runtime, uid: 501) {})
        invalid = params; invalid["pid"] = true
        XCTAssertThrowsError(try ApplicationQuitIdentity(invalid))
    }
    func testRejectionAndPostSubmissionErrorsKeepUncertainty() throws {
        for throwsAfter in [false, true] {
            var submissions = 0
            let runtime = ApplicationQuitRuntime(list: { _ in [self.entry()] }, terminate: { _, dispatch in
                try dispatch(); submissions += 1
                if throwsAfter { throw NativeFailure("fixture", "after submit") }
                return false
            }, exited: { _ in false }, wait: { _ in })
            let reply = try quitApplication(params, Budget(milliseconds: 1000), runtime: runtime, uid: 501) {}
            XCTAssertEqual(reply.dispatchState, "unknown"); XCTAssertEqual(submissions, 1)
        }
    }
    func testReadOnlyExitStatusPreservesUnknownAndExactIdentity() throws {
        for status: Bool? in [true, false, nil] {
            let result = try applicationExitStatus(params, exited: { identity in
                XCTAssertEqual(identity.pid, 42); XCTAssertEqual(identity.token, "1790000000:1")
                return status
            })
            XCTAssertEqual(result["exitConfirmed"] as? Bool, status == true)
            XCTAssertEqual(result["observationAvailable"] as? Bool, status != nil)
        }
    }
    func testDeadlineAfterSubmissionIsUnknown() throws {
        var submissions = 0
        let runtime = ApplicationQuitRuntime(list: { _ in [self.entry()] }, terminate: { _, dispatch in try dispatch(); submissions += 1; Thread.sleep(forTimeInterval: 0.01); return true }, exited: { _ in true }, wait: { _ in })
        let reply = try quitApplication(params, Budget(milliseconds: 5), runtime: runtime, uid: 501) {}
        XCTAssertEqual(reply.dispatchState, "unknown"); XCTAssertEqual(submissions, 1)
    }
    func testDelayedExitBeyondOneSecondWithinFiveSecondBound() throws {
        var requestedWait: TimeInterval = 0, submissions = 0
        let runtime = ApplicationQuitRuntime(list: { _ in [self.entry()] }, terminate: { _, dispatch in
            try dispatch(); submissions += 1; return true
        }, exited: { _ in requestedWait >= 2 }, wait: { requestedWait += $0 })
        let reply = try quitApplication(params, Budget(milliseconds: 10000), runtime: runtime, uid: 501) {}
        XCTAssertEqual(reply.dispatchState, "dispatched"); XCTAssertEqual(submissions, 1)
        XCTAssertGreaterThanOrEqual(requestedWait, 2); XCTAssertLessThanOrEqual(requestedWait, 5)
    }
    func testUnsavedDialogExhaustsBoundWithoutReplayingAndLaterReadCanConfirm() throws {
        var requestedWait: TimeInterval = 0, submissions = 0, exited = false
        let runtime = ApplicationQuitRuntime(list: { _ in [self.entry()] }, terminate: { _, dispatch in
            try dispatch(); submissions += 1; return true
        }, exited: { _ in exited }, wait: { requestedWait += $0 })
        let reply = try quitApplication(params, Budget(milliseconds: 10000), runtime: runtime, uid: 501) {}
        XCTAssertEqual(reply.dispatchState, "unknown"); XCTAssertEqual(submissions, 1)
        XCTAssertGreaterThan(requestedWait, 4.9); XCTAssertLessThanOrEqual(requestedWait, 5.001)
        XCTAssertEqual(try applicationExitStatus(params, exited: runtime.exited)["exitConfirmed"] as? Bool, false)
        exited = true
        XCTAssertEqual(try applicationExitStatus(params, exited: runtime.exited)["exitConfirmed"] as? Bool, true)
        XCTAssertEqual(submissions, 1)
    }

    func testShortCallerDeadlineBoundsExitObservation() throws {
        var waited: TimeInterval = 0, submissions = 0, reads = 0
        let runtime = ApplicationQuitRuntime(list: { _ in [self.entry()] }, terminate: { _, dispatch in
            try dispatch(); submissions += 1; return true
        }, exited: { _ in reads += 1; return false }, wait: { interval in
            waited += interval; Thread.sleep(forTimeInterval: interval)
        })
        let reply = try quitApplication(params, Budget(milliseconds: 15), runtime: runtime, uid: 501) {}
        XCTAssertEqual(reply.dispatchState, "unknown"); XCTAssertEqual(submissions, 1)
        XCTAssertLessThanOrEqual(waited, 0.03); XCTAssertLessThanOrEqual(reads, 2)
    }

}
