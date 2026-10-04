import XCTest
import AppKit
import ApplicationServices
@testable import MechanizeNative
import MechanizeNativeCore

final class ScopedWindowRootTests: XCTestCase {
    let pid: pid_t = 42000
    let uid: uid_t = 501
    func scope() throws -> NativeWindowScope { try XCTUnwrap(NativeWindowScope.requested(in: ["windowScope": ["title": "Save", "role": "AXWindow"]], method: "elements.snapshot")) }
    func owner() -> AXElementOwner { AXElementOwner(pid: pid, uid: uid, birth: "100:1", bundle: "fixture.app", status: AXError.success.rawValue) }
    func testExactWindowSelectsBeforeAnyUnrelatedChildrenAndRechecksContainment() throws {
        let app = AXUIElementCreateApplication(pid), writer = AXUIElementCreateApplication(42001), calc = AXUIElementCreateApplication(42002), save = AXUIElementCreateApplication(42003), child = AXUIElementCreateApplication(42004)
        var childrenReads = 0
        let runtime = ScopedNativeRootRuntime(attribute: { element, attribute in
            if attribute == kAXChildrenAttribute { childrenReads += 1; return (.success, Array(repeating: writer, count: 2000) as CFArray) }
            if CFEqual(element, app) { XCTAssertEqual(attribute, kAXWindowsAttribute); return (.success, [writer, calc, save] as CFArray) }
            if attribute == kAXRoleAttribute { return (.success, kAXWindowRole as CFString) }
            if attribute == kAXTitleAttribute { return (.success, (CFEqual(element, save) ? "Save" : "Other") as CFString) }
            if CFEqual(element, child), attribute == kAXParentAttribute { return (.success, save) }
            XCTFail("unexpected scope read"); return (.cannotComplete, nil)
        }, owner: { _ in self.owner() })
        let proof = try ScopedNativeRoot.resolveWindow(scope(), application: app, pid: pid, uid: uid, birth: "100:1", bundle: "fixture.app", check: {}, runtime: runtime)
        XCTAssertTrue(CFEqual(proof.element, save))
        try proof.validate(referenceElement: child, check: {}, runtime: runtime)
        XCTAssertEqual(childrenReads, 0)
    }
    func testAmbiguousUnavailableForeignAndChangedWindowReject() throws {
        let app = AXUIElementCreateApplication(pid), first = AXUIElementCreateApplication(42001), second = AXUIElementCreateApplication(42002)
        var windows = [first], incomplete = false, foreign = false
        let runtime = ScopedNativeRootRuntime(attribute: { element, attribute in
            if CFEqual(element, app) { return (.success, windows as CFArray) }
            if attribute == kAXRoleAttribute { return (.success, kAXWindowRole as CFString) }
            if incomplete { return (.cannotComplete, nil) }
            return (.success, "Save" as CFString)
        }, owner: { _ in foreign ? AXElementOwner(pid: 999, uid: self.uid, birth: "100:1", bundle: "fixture.app", status: AXError.success.rawValue) : self.owner() })
        let proof = try ScopedNativeRoot.resolveWindow(scope(), application: app, pid: pid, uid: uid, birth: "100:1", bundle: "fixture.app", check: {}, runtime: runtime)
        windows = [first, second]
        XCTAssertThrowsError(try proof.validate(check: {}, runtime: runtime))
        windows = [second]
        XCTAssertThrowsError(try proof.validate(check: {}, runtime: runtime))
        incomplete = true
        XCTAssertThrowsError(try ScopedNativeRoot.resolveWindow(scope(), application: app, pid: pid, uid: uid, birth: "100:1", bundle: "fixture.app", check: {}, runtime: runtime))
        incomplete = false; foreign = true
        XCTAssertThrowsError(try ScopedNativeRoot.resolveWindow(scope(), application: app, pid: pid, uid: uid, birth: "100:1", bundle: "fixture.app", check: {}, runtime: runtime))
    }
}
