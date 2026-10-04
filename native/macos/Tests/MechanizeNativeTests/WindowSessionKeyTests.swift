import XCTest
import CoreGraphics
import AppKit
@testable import MechanizeNative
import MechanizeNativeCore

final class WindowSessionKeyTests: XCTestCase {
    let bounds = CGRect(x: 100, y: 100, width: 600, height: 300)
    func window(_ id: UInt32 = 99, pid: pid_t = 42, layer: Int = 0, visible: Bool = true, alpha: Double = 1, bounds: CGRect? = nil) -> SessionKeyWindow {
        SessionKeyWindow(id: id, pid: pid, layer: layer, visible: visible, alpha: alpha, bounds: bounds ?? self.bounds)
    }
    func runtime(_ rows: [SessionKeyWindow]?, foreground: pid_t? = 42, session: Bool = true, secure: Bool = false, birth: String = "100:1", uid: uid_t = 501) -> WindowSessionKeyRuntime {
        WindowSessionKeyRuntime(process: { _ in (uid, birth, "com.fixture.app") }, foreground: { foreground }, windows: { rows }, session: { session }, secure: { secure })
    }
    func qualify(_ runtime: WindowSessionKeyRuntime, check: () throws -> Void = {}) throws {
        try qualifyWindowSessionKey(pid: 42, uid: 501, birth: "100:1", bundle: "com.fixture.app", windowID: 99, check: check, runtime: runtime)
    }
    func testFreshTopOwnedWindowUsesMetadataOnlyAndPermitsOneChord() throws {
        let runtime = runtime([window(10, pid: 77, layer: 24), window(), window(100)])
        let inputs = InputSafety(); inputs.enable(); var downs = 0, ups = 0
        try KeyboardPosting.press(inputs: inputs, token: "key:53", delivery: .session, preflight: { try self.qualify(runtime) }, down: { route in XCTAssertEqual(route, .session); downs += 1; return true }, up: { _ in ups += 1; return true })
        XCTAssertEqual(downs, 1); XCTAssertEqual(ups, 1); XCTAssertEqual(inputs.inhibitAndRelease().unknown, 0)
    }
    func testModalAndFloatingWindowsQualifyWithoutTargetingUnderlyingDocument() throws {
        for layer in [NSWindow.Level.normal.rawValue, NSWindow.Level.floating.rawValue, NSWindow.Level.modalPanel.rawValue] {
            try qualify(runtime([window(layer: layer), window(100)]))
            XCTAssertThrowsError(try qualify(runtime([window(100, layer: layer), window()])))
        }
        for layer in [NSWindow.Level.popUpMenu.rawValue, NSWindow.Level.statusBar.rawValue] {
            XCTAssertThrowsError(try qualify(runtime([window(100, layer: layer), window()])))
            XCTAssertThrowsError(try qualify(runtime([window(layer: layer)])))
        }
    }
    func testStaleForeignHiddenLayeredDuplicateBehindOrInvalidGeometryCannotPost() {
        let failures = [runtime(nil), runtime([]), runtime([window(100), window()]), runtime([window(pid: 77)]), runtime([window(layer: 1)]), runtime([window(visible: false)]), runtime([window(alpha: 0)]), runtime([window(), window()]), runtime([window(), window(pid: 77)]), runtime([window(bounds: CGRect(x: 0, y: 0, width: 0, height: 5))]), runtime([window(bounds: CGRect(x: Double.infinity, y: 0, width: 5, height: 5))]), runtime([window()], foreground: 77), runtime([window()], session: false), runtime([window()], secure: true), runtime([window()], birth: "100:2"), runtime([window()], uid: 502)]
        for runtime in failures {
            let inputs = InputSafety(); inputs.enable(); var downs = 0
            XCTAssertThrowsError(try KeyboardPosting.press(inputs: inputs, token: "key:53", delivery: .session, preflight: { try self.qualify(runtime) }, down: { _ in downs += 1; return true }, up: { _ in XCTFail("no release without a down"); return true }))
            XCTAssertEqual(downs, 0)
        }
    }
    func testChangingForegroundBirthOrDeadlineBeforeDownFailsClosed() {
        var reads = 0
        let runtime = WindowSessionKeyRuntime(process: { _ in reads += 1; return (501, reads == 1 ? "100:1" : "100:2", "com.fixture.app") }, foreground: { 42 }, windows: { [self.window()] }, session: { true }, secure: { false })
        XCTAssertThrowsError(try qualify(runtime))
        XCTAssertThrowsError(try qualify(self.runtime([window()]), check: { throw NativeFailure("deadlineExceeded", "fixture") }))
    }
    func testEscapeMayDestroyWindowButReleaseDoesNotRequalifyItOrRetryDown() throws {
        var rows: [SessionKeyWindow]? = [window()], sessionLive = true
        let runtime = WindowSessionKeyRuntime(process: { _ in (501, "100:1", "com.fixture.app") }, foreground: { 42 }, windows: { rows }, session: { sessionLive }, secure: { false })
        let inputs = InputSafety(); inputs.enable(); var downs = 0, ups = 0
        try KeyboardPosting.press(inputs: inputs, token: "key:53", delivery: .session, preflight: { try self.qualify(runtime) }, down: { _ in downs += 1; rows = []; return true }, up: { _ in guard sessionLive else { return false }; ups += 1; return true })
        XCTAssertEqual(downs, 1); XCTAssertEqual(ups, 1); XCTAssertTrue(rows!.isEmpty); XCTAssertEqual(inputs.inhibitAndRelease().unknown, 0)
        sessionLive = false
    }
    func testFailedReleaseRetainsCleanupAndNeverRepeatsDown() {
        let inputs = InputSafety(); inputs.enable(); var downs = 0, releases = 0
        XCTAssertThrowsError(try KeyboardPosting.press(inputs: inputs, token: "key:53", delivery: .session, preflight: {}, down: { _ in downs += 1; return true }, up: { _ in releases += 1; return false }))
        XCTAssertEqual(downs, 1); XCTAssertEqual(inputs.inhibitAndRelease().unknown, 1); XCTAssertEqual(downs, 1); XCTAssertEqual(releases, 2)
    }
}
