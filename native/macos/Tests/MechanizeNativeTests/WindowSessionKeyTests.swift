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
    func testFrameCaptureCanSelectExactWindowBehindOverlayButKeyboardCannot() throws {
        let r = runtime([window(100, layer: 103), window()], foreground: 77)
        try qualifyWindowFrameTarget(pid: 42, uid: 501, birth: "100:1", bundle: "com.fixture.app", windowID: 99, check: {}, runtime: r)
        XCTAssertThrowsError(try qualify(r))
        XCTAssertThrowsError(try qualifyWindowFrameTarget(pid: 42, uid: 501, birth: "100:1", bundle: "com.fixture.app", windowID: 100, check: {}, runtime: r))
        XCTAssertThrowsError(try qualifyWindowFrameTarget(pid: 42, uid: 501, birth: "100:2", bundle: "com.fixture.app", windowID: 99, check: {}, runtime: r))
        for layer in [NSWindow.Level.normal.rawValue, NSWindow.Level.floating.rawValue, NSWindow.Level.modalPanel.rawValue] {
            let covered = runtime([window(100, layer: layer), window()])
            try qualifyWindowFrameTarget(pid: 42, uid: 501, birth: "100:1", bundle: "com.fixture.app", windowID: 99, check: {}, runtime: covered)
            XCTAssertThrowsError(try qualify(covered))
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
    func testForegroundAndInventoryFailuresHaveStaticDiagnosticsAndNeverPost() {
        let cases: [(pid_t?, [SessionKeyWindow]?, String, Int)] = [
            (77, nil, "Foreground qualification failed (phase=initial, reason=mismatch, foregroundPid=77, foregroundBundle=unavailable, foregroundActive=true, frontWindowId=0, frontWindowPid=0)", 1),
            (nil, [window()], "Foreground qualification failed (phase=initial, reason=unavailable, foregroundPid=0, foregroundBundle=unavailable, foregroundActive=unavailable, frontWindowId=99, frontWindowPid=42)", 1),
            (42, nil, "Visible window inventory is unavailable or contains incomplete metadata", 1),
            (42, Array(repeating: window(), count: 1001), "Visible window inventory exceeds the bounded inspection limit", 1)
        ]
        for (foreground, rows, expected, expectedInventoryReads) in cases {
            var inventoryReads = 0, downs = 0, ups = 0
            let runtime = WindowSessionKeyRuntime(process: { _ in (501, "100:1", "com.fixture.app") },
                foreground: { foreground }, windows: { inventoryReads += 1; return rows }, session: { true }, secure: { false })
            let inputs = InputSafety(); inputs.enable()
            XCTAssertThrowsError(try KeyboardPosting.press(inputs: inputs, token: "key:53", delivery: .session,
                preflight: { try self.qualify(runtime) }, down: { _ in downs += 1; return true }, up: { _ in ups += 1; return true })) { error in
                XCTAssertEqual((error as? NativeFailure)?.code, "windowKeyboardUnqualified")
                XCTAssertEqual((error as? NativeFailure)?.message, expected)
            }
            XCTAssertEqual(inventoryReads, expectedInventoryReads)
            XCTAssertEqual(downs, 0); XCTAssertEqual(ups, 0)
            XCTAssertEqual(inputs.inhibitAndRelease().unknown, 0)
        }
    }
    func testChangingForegroundBirthOrDeadlineBeforeDownFailsClosed() {
        var reads = 0
        let runtime = WindowSessionKeyRuntime(process: { _ in reads += 1; return (501, reads == 1 ? "100:1" : "100:2", "com.fixture.app") }, foreground: { 42 }, windows: { [self.window()] }, session: { true }, secure: { false })
        XCTAssertThrowsError(try qualify(runtime))
        XCTAssertThrowsError(try qualify(self.runtime([window()]), check: { throw NativeFailure("deadlineExceeded", "fixture") }))
    }
    func testForegroundRefreshPrecedesBothObservationsAndNeverAdoptsAConflict() throws {
        var current: pid_t? = nil
        var refreshes = 0
        var r = WindowSessionKeyRuntime(process: { _ in (501, "100:1", "com.fixture.app") },
            foreground: { current }, windows: { [self.window()] }, session: { true }, secure: { false })
        r.refresh = { refreshes += 1; current = 42 }
        try qualify(r)
        XCTAssertEqual(refreshes, 2)
        refreshes = 0
        r.refresh = { refreshes += 1; current = refreshes == 1 ? 42 : 77 }
        XCTAssertThrowsError(try qualify(r))
        XCTAssertEqual(refreshes, 2)
        r.refresh = { throw NativeFailure("foregroundRefreshUnavailable", "fixture") }
        let inputs = InputSafety(); inputs.enable(); var downs = 0
        XCTAssertThrowsError(try KeyboardPosting.press(inputs: inputs, token: "key:53", delivery: .session,
            preflight: { try self.qualify(r) }, down: { _ in downs += 1; return true }, up: { _ in true }))
        XCTAssertEqual(downs, 0)
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
    func testForegroundFailureUsesExactFailedSampleAtBothPhasesWithoutPosting() {
        for phase in ["initial", "final"] {
            for reason in ["unavailable", "inactive", "mismatch"] {
                var reads = 0, inventoryReads = 0, downs = 0, ups = 0, refreshes = 0
                let r = WindowSessionKeyRuntime(process: { _ in (501, "100:1", "com.fixture.app") },
                    foreground: { XCTFail("must not resample through legacy seam"); return 42 },
                    windows: { inventoryReads += 1; return phase == "final" && inventoryReads == 1 ? [self.window()] : [self.window(123, pid: 77)] },
                    session: { true }, secure: { false }, refresh: { refreshes += 1 }, foregroundSample: {
                        reads += 1
                        if phase == "final" && reads == 1 { return SessionKeyForegroundSample(pid: 42, bundle: "com.fixture.app", active: true) }
                        if reason == "unavailable" { return nil }
                        return SessionKeyForegroundSample(pid: reason == "mismatch" ? 77 : 42, bundle: "com.fixture.foreground", active: reason != "inactive")
                    })
                let inputs = InputSafety(); inputs.enable()
                XCTAssertThrowsError(try KeyboardPosting.press(inputs: inputs, token: "key:53", delivery: .session,
                    preflight: { try self.qualify(r) }, down: { _ in downs += 1; return true }, up: { _ in ups += 1; return true })) { error in
                    let failure = error as? NativeFailure
                    XCTAssertEqual(failure?.code, "windowKeyboardUnqualified")
                    XCTAssertTrue(failure?.message.contains("phase=\(phase), reason=\(reason)") == true)
                    XCTAssertTrue(failure?.message.contains("frontWindowId=123, frontWindowPid=77") == true)
                    if reason != "unavailable" { XCTAssertTrue(failure?.message.contains("foregroundBundle=com.fixture.foreground") == true) }
                }
                XCTAssertEqual(reads, phase == "final" ? 2 : 1)
                XCTAssertEqual(refreshes, reads); XCTAssertEqual(inventoryReads, reads)
                XCTAssertEqual(downs, 0); XCTAssertEqual(ups, 0); XCTAssertEqual(inputs.inhibitAndRelease().unknown, 0)
            }
        }
    }
    func testForegroundFailureNeverEchoesMalformedBundleMetadata() {
        for bundle in ["private value\nhttps://example.invalid", String(repeating: "a", count: 256)+".app"] {
            var r = runtime([window()])
            r.foregroundSample = { SessionKeyForegroundSample(pid: 77, bundle: bundle, active: true) }
            XCTAssertThrowsError(try qualify(r)) { error in
                let failure = error as? NativeFailure
                XCTAssertTrue(failure?.message.contains("foregroundBundle=unavailable") == true)
                XCTAssertFalse(failure?.message.contains(bundle) == true)
            }
        }
    }

}
