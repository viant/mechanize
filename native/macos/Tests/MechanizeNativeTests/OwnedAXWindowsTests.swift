import XCTest
import AppKit
import ApplicationServices
@testable import MechanizeNative
import MechanizeNativeCore

final class OwnedAXWindowsTests: XCTestCase {
    let pid: pid_t = 42000
    let uid: uid_t = 501
    func owner() -> AXElementOwner { AXElementOwner(pid: pid, uid: uid, birth: "100:1", bundle: "fixture.app", status: AXError.success.rawValue) }
    func testOwnedScrollAreaExcludedBySharedFlatAndScopedEnumeration() throws {
        let app = AXUIElementCreateApplication(pid), scroll = AXUIElementCreateApplication(42001), window = AXUIElementCreateApplication(42002)
        var titleReads = 0
        let runtime = ScopedNativeRootRuntime(attribute: { element, attribute in
            if CFEqual(element, app) { XCTAssertEqual(attribute, kAXWindowsAttribute); return (.success, [scroll, window] as CFArray) }
            if attribute == kAXRoleAttribute { return (.success, (CFEqual(element, scroll) ? kAXScrollAreaRole : kAXWindowRole) as CFString) }
            XCTAssertTrue(CFEqual(element, window), "Excluded non-window must not be traversed or read as a title")
            XCTAssertEqual(attribute, kAXTitleAttribute); titleReads += 1
            return (.success, "Save" as CFString)
        }, owner: { _ in self.owner() })
        let windows = try OwnedAXWindows.enumerate(application: app, pid: pid, uid: uid, birth: "100:1", bundle: "fixture.app", check: {}, runtime: runtime)
        XCTAssertEqual(windows.count, 1); XCTAssertTrue(CFEqual(windows[0], window)); XCTAssertEqual(titleReads, 0)
        let scope = try XCTUnwrap(NativeWindowScope.requested(in: ["windowScope": ["title": "Save"]], method: "elements.snapshot"))
        let proof = try ScopedNativeRoot.resolveWindow(scope, application: app, pid: pid, uid: uid, birth: "100:1", bundle: "fixture.app", check: {}, runtime: runtime)
        XCTAssertTrue(CFEqual(proof.element, window)); try proof.validate(check: {}, runtime: runtime)
    }
    func testScrollAreaStillRequiresExactOwnerAndKnownRole() throws {
        let app = AXUIElementCreateApplication(pid), entry = AXUIElementCreateApplication(42001)
        for mode in ["roleError", "missingRole", "unknownRole", "unsupportedRole", "pid", "uid", "birth", "bundle", "tooMany"] {
            let runtime = ScopedNativeRootRuntime(attribute: { element, attribute in
                if CFEqual(element, app) { return (.success, Array(repeating: entry, count: mode == "tooMany" ? 257 : 1) as CFArray) }
                XCTAssertEqual(attribute, kAXRoleAttribute)
                if mode == "roleError" { return (.cannotComplete, nil) }
                if mode == "missingRole" { return (.success, nil) }
                if mode == "unknownRole" { return (.success, "PRIVATE_UNKNOWN_ROLE" as CFString) }
                return (.success, (mode == "unsupportedRole" ? kAXGroupRole : kAXScrollAreaRole) as CFString)
            }, owner: { _ in AXElementOwner(pid: mode == "pid" ? 999 : self.pid, uid: mode == "uid" ? 999 : self.uid, birth: mode == "birth" ? "100:2" : "100:1", bundle: mode == "bundle" ? "foreign.app" : "fixture.app", status: AXError.success.rawValue) })
            XCTAssertThrowsError(try OwnedAXWindows.enumerate(application: app, pid: pid, uid: uid, birth: "100:1", bundle: "fixture.app", check: {}, runtime: runtime)) { error in
                XCTAssertFalse(String(describing: error).contains("PRIVATE_UNKNOWN_ROLE"))
            }
        }
    }
}
