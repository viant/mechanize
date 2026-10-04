import XCTest
import AppKit
import ApplicationServices
@testable import MechanizeNative
import MechanizeNativeCore

final class ScopedNativeRootTests: XCTestCase {
    private let pid: pid_t = 42_000
    private let uid: uid_t = 501
    private let birth = "100:1"
    private let bundle = "com.fixture.editor"
    private func owner(_ pid: pid_t = 42_000, uid: uid_t = 501, birth: String = "100:1", bundle: String = "com.fixture.editor") -> AXElementOwner {
        AXElementOwner(pid: pid, uid: uid, birth: birth, bundle: bundle, status: AXError.success.rawValue)
    }
    func testMenuRootIsReadOnlyFromExactAppWithExplicitRoleAndOwner() throws {
        let app = AXUIElementCreateApplication(pid), menu = AXUIElementCreateApplication(42_001)
        var attributes: [String] = [], ownerReads = 0
        let runtime = ScopedNativeRootRuntime(attribute: { element, name in
            attributes.append(name)
            if CFEqual(element, app) { XCTAssertEqual(name, kAXMenuBarAttribute); return (.success, menu) }
            XCTAssertTrue(CFEqual(element, menu)); XCTAssertEqual(name, kAXRoleAttribute)
            return (.success, kAXMenuBarRole as CFString)
        }, owner: { element in ownerReads += 1; XCTAssertTrue(CFEqual(element, menu)); return self.owner() })
        let proof = try ScopedNativeRoot.resolve(.menuBar, application: app, pid: pid, uid: uid, birth: birth, bundle: bundle, check: {}, runtime: runtime)
        XCTAssertTrue(CFEqual(proof.element, menu)); XCTAssertEqual(attributes, [kAXMenuBarAttribute, kAXRoleAttribute]); XCTAssertEqual(ownerReads, 1)
    }
    func testFocusedRootNeverUsesGlobalFocusOrWindowFallback() throws {
        let app = AXUIElementCreateApplication(pid), focused = AXUIElementCreateApplication(42_001)
        var attributes: [String] = []
        let runtime = ScopedNativeRootRuntime(attribute: { element, name in
            XCTAssertTrue(CFEqual(element, app)); attributes.append(name); return (.success, focused)
        }, owner: { _ in self.owner() })
        let proof = try ScopedNativeRoot.resolve(.focusedElement, application: app, pid: pid, uid: uid, birth: birth, bundle: bundle, check: {}, runtime: runtime)
        XCTAssertTrue(CFEqual(proof.element, focused)); XCTAssertEqual(attributes, [kAXFocusedUIElementAttribute])
    }
    func testMissingMalformedAndWrongMenuRoleRootsFailClosed() {
        let app = AXUIElementCreateApplication(pid), root = AXUIElementCreateApplication(42_001)
        let missing: [(AXError, CFTypeRef?)] = [(.noValue, nil), (.attributeUnsupported, nil), (.cannotComplete, nil), (.success, "not-an-element" as CFString), (.success, NSNumber(value: 1))]
        for value in missing {
            let runtime = ScopedNativeRootRuntime(attribute: { _, _ in value }, owner: { _ in XCTFail("must not inspect malformed AX type"); return self.owner() })
            XCTAssertThrowsError(try ScopedNativeRoot.resolve(.focusedElement, application: app, pid: pid, uid: uid, birth: birth, bundle: bundle, check: {}, runtime: runtime)) { XCTAssertEqual(($0 as? NativeFailure)?.code, "rootUnavailable") }
        }
        let wrongRole = ScopedNativeRootRuntime(attribute: { _, name in name == kAXMenuBarAttribute ? (.success, root) : (.success, kAXWindowRole as CFString) }, owner: { _ in self.owner() })
        XCTAssertThrowsError(try ScopedNativeRoot.resolve(.menuBar, application: app, pid: pid, uid: uid, birth: birth, bundle: bundle, check: {}, runtime: wrongRole)) { XCTAssertEqual(($0 as? NativeFailure)?.code, "rootUnavailable") }
    }
    func testForeignMissingOrChangedOwnerCannotQualifyScopedRoot() {
        let app = AXUIElementCreateApplication(pid), root = AXUIElementCreateApplication(42_001)
        for facts in [owner(77), owner(uid: 502), owner(birth: "100:2"), owner(bundle: "com.fixture.foreign"), AXElementOwner(pid: nil, uid: nil, birth: nil, bundle: nil, status: AXError.cannotComplete.rawValue)] {
            let runtime = ScopedNativeRootRuntime(attribute: { _, _ in (.success, root) }, owner: { _ in facts })
            XCTAssertThrowsError(try ScopedNativeRoot.resolve(.focusedElement, application: app, pid: pid, uid: uid, birth: birth, bundle: bundle, check: {}, runtime: runtime)) { XCTAssertEqual(($0 as? NativeFailure)?.code, "rootOwnerMismatch") }
        }
    }
    func testFocusedRootChangeOrLossPreventsAnyInput() throws {
        let app = AXUIElementCreateApplication(pid), root = AXUIElementCreateApplication(42_001), changed = AXUIElementCreateApplication(42_002)
        var selected: AXUIElement? = root, inputs = 0
        let runtime = ScopedNativeRootRuntime(attribute: { _, _ in selected.map { (.success, $0 as CFTypeRef) } ?? (.noValue, nil) }, owner: { _ in self.owner() })
        let proof = try ScopedNativeRoot.resolve(.focusedElement, application: app, pid: pid, uid: uid, birth: birth, bundle: bundle, check: {}, runtime: runtime)
        try proof.validate(referenceElement: root, check: {}, runtime: runtime)
        for selection: AXUIElement? in [changed, nil] {
            selected = selection
            do { try proof.validate(referenceElement: root, check: {}, runtime: runtime); inputs += 1; XCTFail("changed focus admitted input") }
            catch let error as NativeFailure { XCTAssertEqual(error.code, "staleFocus") }
        }
        XCTAssertEqual(inputs, 0)
    }
    func testMenuRootIdentityAndDescendantOwnerRemainStableBeforeInput() throws {
        let app = AXUIElementCreateApplication(pid), root = AXUIElementCreateApplication(42_001), changed = AXUIElementCreateApplication(42_002), child = AXUIElementCreateApplication(42_003)
        var selected = root
        let runtime = ScopedNativeRootRuntime(attribute: { _, name in name == kAXMenuBarAttribute ? (.success, selected) : (.success, kAXMenuBarRole as CFString) }, owner: { element in CFEqual(element, child) ? self.owner(77) : self.owner() })
        let proof = try ScopedNativeRoot.resolve(.menuBar, application: app, pid: pid, uid: uid, birth: birth, bundle: bundle, check: {}, runtime: runtime)
        XCTAssertThrowsError(try proof.validate(referenceElement: child, check: {}, runtime: runtime)) { XCTAssertEqual(($0 as? NativeFailure)?.code, "rootOwnerMismatch") }
        selected = changed
        XCTAssertThrowsError(try proof.validate(check: {}, runtime: runtime)) { XCTAssertEqual(($0 as? NativeFailure)?.code, "staleReference") }
    }
    func testDeadlineFailureStopsRootLookupAndIsNotReclassifiedAsFocusChange() throws {
        let app = AXUIElementCreateApplication(pid), root = AXUIElementCreateApplication(42_001)
        var lookups = 0
        let runtime = ScopedNativeRootRuntime(attribute: { _, _ in lookups += 1; return (.success, root) }, owner: { _ in self.owner() })
        let proof = try ScopedNativeRoot.resolve(.focusedElement, application: app, pid: pid, uid: uid, birth: birth, bundle: bundle, check: {}, runtime: runtime)
        let before = lookups
        XCTAssertThrowsError(try proof.validate(check: { throw NativeFailure("deadlineExceeded", "fixture") }, runtime: runtime)) { XCTAssertEqual(($0 as? NativeFailure)?.code, "deadlineExceeded") }
        XCTAssertEqual(lookups, before)
    }
}

extension ScopedNativeRootTests {
    func testFreshParentChainProvesValidDescendantAndRejectsReparentOutsideRoot() throws {
        let app = AXUIElementCreateApplication(pid), root = AXUIElementCreateApplication(42_001)
        let child = AXUIElementCreateApplication(42_002), parent = AXUIElementCreateApplication(42_003)
        var moved = false, inputCount = 0
        let runtime = ScopedNativeRootRuntime(attribute: { element, name in
            if name == kAXFocusedUIElementAttribute { XCTAssertTrue(CFEqual(element, app)); return (.success, root) }
            XCTAssertEqual(name, kAXParentAttribute)
            if CFEqual(element, child) { return (.success, moved ? app : parent) }
            XCTAssertTrue(CFEqual(element, parent)); return (.success, root)
        }, owner: { _ in self.owner() })
        let proof = try ScopedNativeRoot.resolve(.focusedElement, application: app, pid: pid, uid: uid, birth: birth, bundle: bundle, check: {}, runtime: runtime)
        try proof.validate(referenceElement: child, check: {}, runtime: runtime)
        moved = true
        do { try proof.validate(referenceElement: child, check: {}, runtime: runtime); inputCount += 1; XCTFail("reparented target admitted") }
        catch let error as NativeFailure { XCTAssertEqual(error.code, "staleReference") }
        XCTAssertEqual(inputCount, 0)
    }
    func testAncestryCycleStopsAfterBoundedFreshReads() throws {
        let app = AXUIElementCreateApplication(pid), root = AXUIElementCreateApplication(42_001)
        let child = AXUIElementCreateApplication(42_002), parent = AXUIElementCreateApplication(42_003)
        var reads = 0
        let runtime = ScopedNativeRootRuntime(attribute: { element, name in
            if name == kAXFocusedUIElementAttribute { return (.success, root) }
            XCTAssertEqual(name, kAXParentAttribute); reads += 1
            return (.success, CFEqual(element, child) ? parent : child)
        }, owner: { _ in self.owner() })
        let proof = try ScopedNativeRoot.resolve(.focusedElement, application: app, pid: pid, uid: uid, birth: birth, bundle: bundle, check: {}, runtime: runtime)
        XCTAssertThrowsError(try proof.validate(referenceElement: child, check: {}, runtime: runtime)) { XCTAssertEqual(($0 as? NativeFailure)?.code, "staleReference") }
        XCTAssertEqual(reads, 2)
    }
    func testLostUnsupportedOrMalformedParentNeverFallsBackToApplication() throws {
        let app = AXUIElementCreateApplication(pid), root = AXUIElementCreateApplication(42_001), child = AXUIElementCreateApplication(42_002)
        for parent: (AXError, CFTypeRef?) in [(.noValue, nil), (.attributeUnsupported, nil), (.cannotComplete, nil), (.success, "not-a-parent" as CFString), (.success, NSNumber(value: 1))] {
            var parentReads = 0
            let runtime = ScopedNativeRootRuntime(attribute: { _, name in
                if name == kAXFocusedUIElementAttribute { return (.success, root) }
                XCTAssertEqual(name, kAXParentAttribute); parentReads += 1; return parent
            }, owner: { _ in self.owner() })
            let proof = try ScopedNativeRoot.resolve(.focusedElement, application: app, pid: pid, uid: uid, birth: birth, bundle: bundle, check: {}, runtime: runtime)
            XCTAssertThrowsError(try proof.validate(referenceElement: child, check: {}, runtime: runtime)) { XCTAssertEqual(($0 as? NativeFailure)?.code, "staleReference") }
            XCTAssertEqual(parentReads, 1)
        }
    }
    func testForeignAncestorRejectsContainmentEvenWhenRootAndTargetOwnerMatch() throws {
        let app = AXUIElementCreateApplication(pid), root = AXUIElementCreateApplication(42_001), child = AXUIElementCreateApplication(42_002), foreign = AXUIElementCreateApplication(42_003)
        let runtime = ScopedNativeRootRuntime(attribute: { _, name in name == kAXFocusedUIElementAttribute ? (.success, root) : (.success, foreign) }, owner: { element in CFEqual(element, foreign) ? self.owner(77) : self.owner() })
        let proof = try ScopedNativeRoot.resolve(.focusedElement, application: app, pid: pid, uid: uid, birth: birth, bundle: bundle, check: {}, runtime: runtime)
        XCTAssertThrowsError(try proof.validate(referenceElement: child, check: {}, runtime: runtime)) { XCTAssertEqual(($0 as? NativeFailure)?.code, "rootOwnerMismatch") }
    }
    func testAncestryDepthTwentyAllowedButTwentyOneRejectedWithoutExtraRead() throws {
        let app = AXUIElementCreateApplication(pid), root = AXUIElementCreateApplication(42_001)
        for depth in [20, 21] {
            let chain = (0..<depth).map { AXUIElementCreateApplication(pid_t(43_000 + $0)) }
            var reads = 0
            let runtime = ScopedNativeRootRuntime(attribute: { element, name in
                if name == kAXFocusedUIElementAttribute { return (.success, root) }
                XCTAssertEqual(name, kAXParentAttribute); reads += 1
                let index = chain.firstIndex(where: { CFEqual($0, element) })!
                return (.success, index + 1 < chain.count ? chain[index + 1] : root)
            }, owner: { _ in self.owner() })
            let proof = try ScopedNativeRoot.resolve(.focusedElement, application: app, pid: pid, uid: uid, birth: birth, bundle: bundle, check: {}, runtime: runtime)
            if depth == 20 { try proof.validate(referenceElement: chain[0], check: {}, runtime: runtime) }
            else { XCTAssertThrowsError(try proof.validate(referenceElement: chain[0], check: {}, runtime: runtime)) { XCTAssertEqual(($0 as? NativeFailure)?.code, "staleReference") } }
            XCTAssertEqual(reads, 20)
        }
    }
    func testExactRootNeedsNoParentLookupAndFocusCannotChangeDuringAncestryProof() throws {
        let app = AXUIElementCreateApplication(pid), root = AXUIElementCreateApplication(42_001), child = AXUIElementCreateApplication(42_002), changed = AXUIElementCreateApplication(42_003)
        var selected = root, parentReads = 0
        let runtime = ScopedNativeRootRuntime(attribute: { _, name in
            if name == kAXFocusedUIElementAttribute { return (.success, selected) }
            XCTAssertEqual(name, kAXParentAttribute); parentReads += 1; selected = changed; return (.success, root)
        }, owner: { _ in self.owner() })
        let proof = try ScopedNativeRoot.resolve(.focusedElement, application: app, pid: pid, uid: uid, birth: birth, bundle: bundle, check: {}, runtime: runtime)
        try proof.validate(referenceElement: root, check: {}, runtime: runtime)
        XCTAssertEqual(parentReads, 0)
        XCTAssertThrowsError(try proof.validate(referenceElement: child, check: {}, runtime: runtime)) { XCTAssertEqual(($0 as? NativeFailure)?.code, "staleFocus") }
        XCTAssertEqual(parentReads, 1)
    }
}
