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
            let runtime = ApplicationControlRuntime(list: { _ in [entry] }, activate: { app in XCTAssertEqual(app.pid, 42); return true })
            let inventory = try applicationInventory(["expectedApp": "com.fixture.app"], runtime: runtime, uid: 501)
            XCTAssertEqual(inventory["complete"] as? Bool, true)
            let apps = inventory["apps"] as? [[String: Any]]
            XCTAssertEqual(apps?.first?["launchTime"] as? String, "kernel:1790000000:1")
            let result = try activateApplication(["expectedApp": "com.fixture.app", "pid": 42, "launchTime": "kernel:1790000000:1", "startToken": "1790000000:1"], Budget(milliseconds: 1000), runtime: runtime, uid: 501) {}
            XCTAssertEqual(result.dispatchState, "dispatched")
        }
        let reused = ApplicationInventoryEntry(pid: 42, bundleID: "com.fixture.app", name: "shell-launched", owner: 501, launchTime: nil, startToken: "1790000000:2", active: false, terminated: false)
        let runtime = ApplicationControlRuntime(list: { _ in [reused] }, activate: { _ in XCTFail("reused PID activated"); return true })
        XCTAssertThrowsError(try activateApplication(["expectedApp": "com.fixture.app", "pid": 42, "launchTime": "kernel:1790000000:1", "startToken": "1790000000:1"], Budget(milliseconds: 1000), runtime: runtime, uid: 501) {})
    }
    func testExactInstanceAmongSameBundleProcesses() throws {
        let other = ApplicationInventoryEntry(pid: 43, bundleID: "com.fixture.app", name: "other", owner: 501, launchTime: "other-launch", startToken: "1790000000:2", active: false, terminated: false)
        let runtime = ApplicationControlRuntime(list: { _ in [other, self.entry()] }, activate: { app in XCTAssertEqual(app.pid, 42); return true })
        let result = try activateApplication(["expectedApp": "com.fixture.app", "pid": 42, "launchTime": "kernel:1790000000:1", "startToken": "1790000000:1"], Budget(milliseconds: 1000), runtime: runtime, uid: 501) {}
        XCTAssertEqual(result.dispatchState, "dispatched")
    }
    func testExactIdentityReserveAndDuplicates() throws {
        let params: [String: Any] = ["expectedApp": "com.fixture.app", "pid": 42, "launchTime": "kernel:1790000000:1", "startToken": "1790000000:1"]
        var dispatched = 0, reserved = false
        let runtime = ApplicationControlRuntime(list: { _ in [self.entry()] }, activate: { _ in XCTAssertTrue(reserved); dispatched += 1; return true })
        let reply = try activateApplication(params, Budget(milliseconds: 1000), runtime: runtime, uid: 501) { reserved = true }
        XCTAssertEqual(reply.dispatchState, "dispatched"); XCTAssertEqual(dispatched, 1)
        for entries in [[entry(), entry()], [entry(owner: nil)], [entry(token: "1790000000:2")]] {
            let invalid = ApplicationControlRuntime(list: { _ in entries }, activate: { _ in XCTFail("invalid identity dispatched"); return true })
            XCTAssertThrowsError(try activateApplication(params, Budget(milliseconds: 1000), runtime: invalid, uid: 501) {})
        }
        XCTAssertThrowsError(try activateApplication(params, Budget(milliseconds: 1000), runtime: runtime, uid: 501) { throw NativeFailure("denied", "fixture") })
        XCTAssertEqual(dispatched, 1)
    }
}
