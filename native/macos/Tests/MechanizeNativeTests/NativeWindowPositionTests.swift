import XCTest
import AppKit
import ApplicationServices
@testable import MechanizeNative
import MechanizeNativeCore

final class NativeWindowPositionTests: XCTestCase {
    let app = AXUIElementCreateApplication(42_000), window = AXUIElementCreateApplication(42_001)
    let pid: pid_t = 42_000, uid: uid_t = 501, birth = "100:1", bundle = "com.fixture.window"
    func owner(pid: pid_t = 42_000, uid: uid_t = 501, birth: String = "100:1") -> AXElementOwner {
        AXElementOwner(pid: pid, uid: uid, birth: birth, bundle: bundle, status: AXError.success.rawValue)
    }
    func point(_ x: CGFloat, _ y: CGFloat) -> AXValue { var value = CGPoint(x: x, y: y); return AXValueCreate(.cgPoint, &value)! }
    func run(_ runtime: NativeWindowPositionRuntime, revalidate: () throws -> Void = {}, willSet: () throws -> Void = {}) throws -> NativeWindowPositionOutcome {
        try positionExactNativeWindow(window, application: app, pid: pid, uid: uid, birth: birth, bundle: bundle,
            position: NativeWindowPosition(["x": 808, "y": 516]), revalidate: revalidate, willSet: willSet, runtime: runtime)
    }
    func testOneSemanticSetterAndIndependentReadbackVerifyExactWindowPosition() throws {
        var sets = 0, readbacks = 0, permits = 0
        let runtime = NativeWindowPositionRuntime(attribute: { element, name in
            switch name {
            case kAXRoleAttribute: XCTAssertTrue(CFEqual(element, self.window)); return (.success, kAXWindowRole as CFString)
            case kAXWindowsAttribute: XCTAssertTrue(CFEqual(element, self.app)); return (.success, [self.window] as CFArray)
            case kAXPositionAttribute: readbacks += 1; XCTAssertEqual(sets, 1); return (.success, self.point(808, 516))
            default: XCTFail("unexpected attribute"); return (.failure, nil)
            }
        }, owner: { _ in self.owner() }, settable: { _ in (.success, true) }, set: { element, position in
            sets += 1; XCTAssertEqual(permits, 1); XCTAssertTrue(CFEqual(element, self.window)); XCTAssertEqual(position, CGPoint(x: 808, y: 516)); return .success
        })
        let outcome = try run(runtime, willSet: { permits += 1 })
        XCTAssertTrue(outcome.verified); XCTAssertEqual(outcome.dispatchState, "dispatched"); XCTAssertEqual(outcome.actual, CGPoint(x: 808, y: 516)); XCTAssertEqual(sets, 1); XCTAssertEqual(readbacks, 1)
    }
    func testWrongRoleOwnerMissingMembershipOrUnsupportedPositionNeverWrites() {
        for condition in ["role", "pid", "uid", "birth", "absent", "duplicate", "settable", "malformedWindows"] {
            var sets = 0, permits = 0
            let runtime = NativeWindowPositionRuntime(attribute: { _, name in
                if name == kAXRoleAttribute { return (.success, (condition == "role" ? kAXButtonRole : kAXWindowRole) as CFString) }
                if name == kAXWindowsAttribute {
                    if condition == "malformedWindows" { return (.success, ["not-a-window"] as CFArray) }
                    return (.success, (condition == "absent" ? [] : condition == "duplicate" ? [self.window, self.window] : [self.window]) as CFArray)
                }
                XCTFail("preflight should not read position"); return (.failure, nil)
            }, owner: { _ in self.owner(pid: condition == "pid" ? 77 : self.pid, uid: condition == "uid" ? 502 : self.uid, birth: condition == "birth" ? "100:2" : self.birth) }, settable: { _ in (.success, condition != "settable") }, set: { _, _ in sets += 1; return .success })
            XCTAssertThrowsError(try run(runtime, willSet: { permits += 1 }))
            XCTAssertEqual(sets, 0); XCTAssertEqual(permits, 0)
        }
    }
    func testMismatchUnavailableMalformedAndSetterFailureRemainUnknownWithoutRetry() throws {
        for condition in ["mismatch", "halfPoint", "missing", "malformed", "setFailure"] {
            var sets = 0
            let runtime = NativeWindowPositionRuntime(attribute: { _, name in
                if name == kAXRoleAttribute { return (.success, kAXWindowRole as CFString) }
                if name == kAXWindowsAttribute { return (.success, [self.window] as CFArray) }
                if condition == "missing" { return (.cannotComplete, nil) }
                if condition == "malformed" { return (.success, "not-a-point" as CFString) }
                return (.success, self.point(condition == "mismatch" ? 858 : condition == "halfPoint" ? 808.5 : 808, 516))
            }, owner: { _ in self.owner() }, settable: { _ in (.success, true) }, set: { _, _ in sets += 1; return condition == "setFailure" ? .failure : .success })
            let outcome = try run(runtime)
            XCTAssertFalse(outcome.verified); XCTAssertEqual(outcome.dispatchState, "unknown"); XCTAssertEqual(outcome.failure?.code, "windowPositionUnconfirmed"); XCTAssertEqual(sets, 1)
        }
    }
    func testRevocationDeadlineOrChangedWindowAfterWriteCannotBecomeAbsenceOrVerified() throws {
        for condition in ["lease", "birth", "deadline", "removedAfterRead"] {
            var sets = 0, positionRead = false
            let runtime = NativeWindowPositionRuntime(attribute: { _, name in
                if name == kAXRoleAttribute { return (.success, kAXWindowRole as CFString) }
                if name == kAXWindowsAttribute { return (.success, (condition == "removedAfterRead" && positionRead ? [] : [self.window]) as CFArray) }
                positionRead = true; return (.success, self.point(808, 516))
            }, owner: { _ in self.owner() }, settable: { _ in (.success, true) }, set: { _, _ in sets += 1; return .success })
            let outcome = try run(runtime, revalidate: {
                if sets > 0 && condition != "removedAfterRead" { throw NativeFailure(condition == "lease" ? "staleLease" : condition == "deadline" ? "deadlineExceeded" : "staleReference", "fixture") }
            })
            XCTAssertEqual(sets, 1); XCTAssertFalse(outcome.verified); XCTAssertEqual(outcome.dispatchState, "unknown")
        }
    }
    func testPrewriteAuthorityFailureOrLedgerFailureNeverInvokesSetter() {
        var sets = 0
        let runtime = NativeWindowPositionRuntime(attribute: { _, name in name == kAXRoleAttribute ? (.success, kAXWindowRole as CFString) : (.success, [self.window] as CFArray) }, owner: { _ in self.owner() }, settable: { _ in (.success, true) }, set: { _, _ in sets += 1; return .success })
        XCTAssertThrowsError(try run(runtime, revalidate: { throw NativeFailure("staleLease", "fixture") }))
        XCTAssertThrowsError(try run(runtime, willSet: { throw NativeFailure("dedupeCapacity", "fixture") }))
        XCTAssertEqual(sets, 0)
    }
}

extension NativeWindowPositionTests {
    func testVerifiedReadbackWireUsesIntegerTokensAndFractionalMismatchIsNeverRounded() throws {
        let requested = try NativeWindowPosition(["x": 808, "y": 516])
        let verified = NativeWindowPositionOutcome(dispatchState: "dispatched", verified: true, actual: CGPoint(x: 808, y: 516), nativeCode: 0, failure: nil)
        let data = try JSONSerialization.data(withJSONObject: verified.positionFields(requested: requested)!, options: [.sortedKeys])
        XCTAssertEqual(String(data: data, encoding: .utf8), "{\"x\":808,\"y\":516}")
        let unknown = NativeWindowPositionOutcome(dispatchState: "unknown", verified: false, actual: CGPoint(x: 808.5, y: 516), nativeCode: 0, failure: NativeFailure("windowPositionUnconfirmed", "fixture"))
        let fractional = try JSONSerialization.data(withJSONObject: unknown.positionFields(requested: requested)!, options: [.sortedKeys])
        XCTAssertEqual(String(data: fractional, encoding: .utf8), "{\"x\":808.5,\"y\":516}")
        XCTAssertFalse(unknown.verified)
    }
}
