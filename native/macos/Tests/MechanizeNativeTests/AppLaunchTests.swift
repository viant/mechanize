import XCTest
import AppKit
import MechanizeNativeCore
@testable import MechanizeNative

final class AppLaunchTests: XCTestCase {
    let bundle = "com.fixture.app"
    let url = URL(fileURLWithPath: "/fixture/Application.app")
    func identity(bundle: String = "com.fixture.app", pid: pid_t = 42) -> ApplicationLaunchIdentity {
        ApplicationLaunchIdentity(bundleID: bundle, applicationURL: url, pid: pid, launchDate: Date(), startToken: "1790000000:1", active: false, terminated: false)
    }
    func testOneExactLaunchWithoutFocusOrBusinessSuccess() async throws {
        var dispatched = 0
        let runtime = ApplicationLaunchRuntime(resolve: { requested in XCTAssertEqual(requested, self.bundle); return self.url }, bundleIdentifier: { _ in self.bundle }, open: { application, options, callback in
            dispatched += 1
            XCTAssertEqual(application, self.url)
            XCTAssertFalse(options.activates)
            XCTAssertFalse(options.createsNewApplicationInstance)
            XCTAssertFalse(options.promptsUserIfNeeded)
            XCTAssertFalse(options.addsToRecentItems)
            callback(self.identity(), nil)
        })
        var reserved = false
        let reply = try await launchApplication(["expectedApp": bundle], Budget(milliseconds: 1000), runtime: runtime) { reserved = true }
        XCTAssertTrue(reserved)
        XCTAssertEqual(dispatched, 1)
        XCTAssertEqual(reply.dispatchState, "dispatched")
        XCTAssertEqual(reply.result["bundleID"] as? String, bundle)
        XCTAssertEqual(reply.result["businessSuccess"] as? Bool, false)
        XCTAssertEqual(reply.result["activationRequested"] as? Bool, false)
    }
    func testNilAndChangedCocoaDateKeepExactKernelBirthIdentity() async throws {
        for date in [nil, Date(timeIntervalSince1970: 1), Date(timeIntervalSince1970: 1790000000)] as [Date?] {
            let identity = ApplicationLaunchIdentity(bundleID: bundle, applicationURL: url, pid: 42, launchDate: date, startToken: "1790000000:1", active: false, terminated: false)
            let runtime = ApplicationLaunchRuntime(resolve: { _ in self.url }, bundleIdentifier: { _ in self.bundle }, open: { _, _, callback in callback(identity, nil) })
            let result = try await launchApplication(["expectedApp": bundle], Budget(milliseconds: 1000), runtime: runtime) {}
            XCTAssertEqual(result.dispatchState, "dispatched")
            XCTAssertEqual(result.result["launchTime"] as? String, "kernel:1790000000:1")
        }
        let invalid = ApplicationLaunchIdentity(bundleID: bundle, applicationURL: url, pid: 42, launchDate: nil, startToken: nil, active: false, terminated: false)
        let runtime = ApplicationLaunchRuntime(resolve: { _ in self.url }, bundleIdentifier: { _ in self.bundle }, open: { _, _, callback in callback(invalid, nil) })
        let result = try await launchApplication(["expectedApp": bundle], Budget(milliseconds: 1000), runtime: runtime) {}
        XCTAssertEqual(result.dispatchState, "unknown")
        XCTAssertTrue(result.result.isEmpty)
    }
    func testInvalidInputAndReservationCannotReachWorkspace() async throws {
        var dispatched = 0
        let runtime = ApplicationLaunchRuntime(resolve: { _ in self.url }, bundleIdentifier: { _ in self.bundle }, open: { _, _, _ in dispatched += 1 })
        for params: [String: Any] in [["expectedApp": "/Applications/Mail.app"], ["expectedApp": "file:///Applications/Mail.app"], ["expectedApp": bundle, "url": "mailto:someone@example.test"], ["expectedApp": bundle, "arguments": ["--anything"]]] {
            do { _ = try await launchApplication(params, Budget(milliseconds: 1000), runtime: runtime) {}; XCTFail("unsafe input accepted") } catch {}
        }
        do { _ = try await launchApplication(["expectedApp": bundle], Budget(milliseconds: 1000), runtime: runtime) { throw NativeFailure("leaseUnavailable", "fixture denied") }; XCTFail("denied reservation accepted") } catch {}
        XCTAssertEqual(dispatched, 0)
    }
    func testTimeoutAndLateCompletionNeverReplayOrChangeUnknown() async throws {
        var dispatched = 0
        var late: ((ApplicationLaunchIdentity?, Error?) -> Void)?
        let runtime = ApplicationLaunchRuntime(resolve: { _ in self.url }, bundleIdentifier: { _ in self.bundle }, open: { _, _, callback in dispatched += 1; late = callback })
        let reply = try await launchApplication(["expectedApp": bundle], Budget(milliseconds: 20), runtime: runtime) {}
        XCTAssertEqual(reply.dispatchState, "unknown")
        XCTAssertEqual(reply.failure?.code, "launchOutcomeUnknown")
        late?(identity(), nil)
        XCTAssertEqual(dispatched, 1)
        XCTAssertEqual(reply.dispatchState, "unknown")
        XCTAssertTrue(reply.result.isEmpty)
    }
    func testMismatchedPostlaunchIdentityIsUnknown() async throws {
        let runtime = ApplicationLaunchRuntime(resolve: { _ in self.url }, bundleIdentifier: { _ in self.bundle }, open: { _, _, callback in callback(self.identity(bundle: "com.other.app"), nil) })
        let reply = try await launchApplication(["expectedApp": bundle], Budget(milliseconds: 1000), runtime: runtime) {}
        XCTAssertEqual(reply.dispatchState, "unknown")
        XCTAssertTrue(reply.result.isEmpty)
    }
}
