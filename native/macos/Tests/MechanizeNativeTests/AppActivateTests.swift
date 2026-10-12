import XCTest
import AppKit
import MechanizeNativeCore
@testable import MechanizeNative
final class AppActivateTests: XCTestCase {
    func entry(bundle: String = "com.fixture.app", owner: uid_t? = 501, token: String? = "1790000000:1", active: Bool = false) -> ApplicationInventoryEntry {
        ApplicationInventoryEntry(pid: 42, bundleID: bundle, name: "fixture", owner: owner, launchTime: "launch", startToken: token, active: active, terminated: false)
    }
    func testScopedInventoryKeepsUnknownTargetFailClosed() throws {
        let target = entry(), unrelated = entry(bundle: "com.other.app", owner: nil)
        let runtime = ApplicationControlRuntime(list: { expected in expected == nil ? [target, unrelated] : [target] }, activate: { _ in XCTFail("inventory dispatched"); return false })
        XCTAssertEqual(try applicationInventory([:], runtime: runtime, uid: 501)["complete"] as? Bool, false)
        XCTAssertEqual(try applicationInventory(["expectedApp": "com.fixture.app"], runtime: runtime, uid: 501)["complete"] as? Bool, true)
        for invalid in [entry(owner: nil), entry(token: nil)] {
            let scoped = ApplicationControlRuntime(list: { _ in [target, invalid] }, activate: { _ in false })
            XCTAssertEqual(try applicationInventory(["expectedApp": "com.fixture.app"], runtime: scoped, uid: 501)["complete"] as? Bool, false)
        }
    }
    func testKernelBirthInventoryWithoutCocoaLaunchDate() throws {
        let missingDate = ApplicationInventoryEntry(pid: 42, bundleID: "com.fixture.app", name: "shell-launched", owner: 501, launchTime: nil, startToken: "1790000000:1", active: false, terminated: false)
        let changedDate = ApplicationInventoryEntry(pid: 42, bundleID: "com.fixture.app", name: "shell-launched", owner: 501, launchTime: "2026-10-02T00:00:00Z", startToken: "1790000000:1", active: false, terminated: false)
        XCTAssertEqual(missingDate.birthIdentity, changedDate.birthIdentity)
        for entry in [missingDate, changedDate] {
            let runtime = ApplicationControlRuntime(list: { _ in [entry] }, activate: { app in XCTAssertEqual(app.pid, 42); return true }, foreground: { _, _ in true })
            let inventory = try applicationInventory(["expectedApp": "com.fixture.app"], runtime: runtime, uid: 501)
            XCTAssertEqual(inventory["complete"] as? Bool, true)
            let apps = inventory["apps"] as? [[String: Any]]
            XCTAssertEqual(apps?.first?["launchTime"] as? String, "kernel:1790000000:1")
            let result = try activateApplication(["expectedApp": "com.fixture.app", "pid": 42, "launchTime": "kernel:1790000000:1", "startToken": "1790000000:1"], Budget(milliseconds: 1000), runtime: runtime, uid: 501) {}
            XCTAssertEqual(result.dispatchState, "dispatched")
        }
        let reused = ApplicationInventoryEntry(pid: 42, bundleID: "com.fixture.app", name: "shell-launched", owner: 501, launchTime: nil, startToken: "1790000000:2", active: false, terminated: false)
        let runtime = ApplicationControlRuntime(list: { _ in [reused] }, activate: { _ in XCTFail("reused PID activated"); return true }, foreground: { _, _ in true })
        XCTAssertThrowsError(try activateApplication(["expectedApp": "com.fixture.app", "pid": 42, "launchTime": "kernel:1790000000:1", "startToken": "1790000000:1"], Budget(milliseconds: 1000), runtime: runtime, uid: 501) {})
    }
    func testExactInstanceAmongSameBundleProcesses() throws {
        let other = ApplicationInventoryEntry(pid: 43, bundleID: "com.fixture.app", name: "other", owner: 501, launchTime: "other-launch", startToken: "1790000000:2", active: false, terminated: false)
        let runtime = ApplicationControlRuntime(list: { _ in [other, self.entry()] }, activate: { app in XCTAssertEqual(app.pid, 42); return true }, foreground: { _, _ in true })
        let result = try activateApplication(["expectedApp": "com.fixture.app", "pid": 42, "launchTime": "kernel:1790000000:1", "startToken": "1790000000:1"], Budget(milliseconds: 1000), runtime: runtime, uid: 501) {}
        XCTAssertEqual(result.dispatchState, "dispatched")
    }
    func testExactIdentityReserveAndDuplicates() throws {
        let params: [String: Any] = ["expectedApp": "com.fixture.app", "pid": 42, "launchTime": "kernel:1790000000:1", "startToken": "1790000000:1"]
        var dispatched = 0, reserved = false
        let runtime = ApplicationControlRuntime(list: { _ in [self.entry()] }, activate: { _ in XCTAssertTrue(reserved); dispatched += 1; return true }, foreground: { _, _ in true })
        let reply = try activateApplication(params, Budget(milliseconds: 1000), runtime: runtime, uid: 501) { reserved = true }
        XCTAssertEqual(reply.dispatchState, "dispatched"); XCTAssertEqual(dispatched, 1)
        for entries in [[entry(), entry()], [entry(owner: nil)], [entry(token: "1790000000:2")]] {
            let invalid = ApplicationControlRuntime(list: { _ in entries }, activate: { _ in XCTFail("invalid identity dispatched"); return true }, foreground: { _, _ in true })
            XCTAssertThrowsError(try activateApplication(params, Budget(milliseconds: 1000), runtime: invalid, uid: 501) {})
        }
        XCTAssertThrowsError(try activateApplication(params, Budget(milliseconds: 1000), runtime: runtime, uid: 501) { throw NativeFailure("denied", "fixture") })
        XCTAssertEqual(dispatched, 1)
    }
    func testDelayedForegroundConfirmationDispatchesOnlyOnce() throws {
        var dispatches = 0, observations = 0, waits = 0
        let runtime = ApplicationControlRuntime(list: { _ in [self.entry()] }, activate: { _ in dispatches += 1; return true }, foreground: { identity, _ in
            XCTAssertEqual(identity.startToken, "1790000000:1")
            observations += 1
            return observations == 3
        }, wait: { _ in waits += 1 })
        let reply = try activateApplication(params, Budget(milliseconds: 1000), runtime: runtime, uid: 501) {}
        XCTAssertNil(reply.failure); XCTAssertEqual(reply.result["foregroundConfirmed"] as? Bool, true)
        XCTAssertEqual(dispatches, 1); XCTAssertEqual(observations, 3); XCTAssertEqual(waits, 2)
    }
    var params: [String: Any] { ["expectedApp": "com.fixture.app", "pid": 42, "launchTime": "kernel:1790000000:1", "startToken": "1790000000:1"] }
    func testUnconfirmedOrConflictingForegroundRetainsUnknown() throws {
        for mode in ["inactive", "staleReference", "foregroundCorroborationConflict", "deadlineExceeded"] {
            var dispatches = 0, observations = 0
            let runtime = ApplicationControlRuntime(list: { _ in [self.entry()] }, activate: { _ in dispatches += 1; return true }, foreground: { _, _ in
                observations += 1
                if mode != "inactive" { throw NativeFailure(mode, "fixture") }
                return false
            }, wait: { _ in })
            let reply = try activateApplication(params, Budget(milliseconds: 1000), runtime: runtime, uid: 501) {}
            XCTAssertEqual(reply.dispatchState, "unknown"); XCTAssertEqual(reply.failure?.code, "activationPostconditionUnknown")
            XCTAssertNil(reply.result["foregroundConfirmed"]); XCTAssertEqual(dispatches, 1)
            XCTAssertEqual(observations, mode == "inactive" ? 40 : 1)
        }
    }
    func testDeadlineAfterDispatchRemainsUnknown() throws {
        var dispatches = 0
        let runtime = ApplicationControlRuntime(list: { _ in [self.entry()] }, activate: { _ in
            dispatches += 1
            Thread.sleep(forTimeInterval: 0.01)
            return true
        }, foreground: { _, _ in XCTFail("expired activation observed"); return true })
        let reply = try activateApplication(params, Budget(milliseconds: 5), runtime: runtime, uid: 501) {}
        XCTAssertEqual(reply.dispatchState, "unknown")
        XCTAssertEqual(reply.failure?.code, "activationPostconditionUnknown")
        XCTAssertEqual(dispatches, 1)
    }
    func testActivationFalseNeverClaimsForegroundOrRepeats() throws {
        var dispatches = 0
        let runtime = ApplicationControlRuntime(list: { _ in [self.entry()] }, activate: { _ in dispatches += 1; return false }, foreground: { _, _ in XCTFail("unaccepted activation observed"); return true })
        let reply = try activateApplication(params, Budget(milliseconds: 1000), runtime: runtime, uid: 501) {}
        XCTAssertEqual(reply.dispatchState, "unknown"); XCTAssertEqual(dispatches, 1)
    }
}
