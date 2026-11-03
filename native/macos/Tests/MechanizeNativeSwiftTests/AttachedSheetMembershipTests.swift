import Testing
import AppKit
import ApplicationServices
@testable import MechanizeNative
import MechanizeNativeCore

final class AttachedSheetMembershipTests {
    private let pid: pid_t = 42_000
    private let uid: uid_t = 501
    private let birth = "100:1"
    private let bundle = "com.fixture.editor"
    private func owner(_ pid: pid_t = 42_000, uid: uid_t = 501, birth: String = "100:1", bundle: String = "com.fixture.editor") -> AXElementOwner {
        AXElementOwner(pid: pid, uid: uid, birth: birth, bundle: bundle, status: AXError.success.rawValue)
    }
    @Test func testAppKitReverseParentRequiresFreshSameAppAttachedSheetMembership() throws {
        for mode in ["valid", "foreignTarget", "foreignSheet", "absent", "noSheet", "wrongHelper", "cycle", "changed", "incomplete", "roleChanged", "oversized", "foreignHelperUser"] {
            let app = AXUIElementCreateApplication(pid), root = AXUIElementCreateApplication(42_001)
            let sheet = AXUIElementCreateApplication(42_002), child = AXUIElementCreateApplication(42_003), helper = AXUIElementCreateApplication(42_004)
            let otherSheet = AXUIElementCreateApplication(42_005)
            var sheetReads = 0, sheetRoleReads = 0, helperChildrenRead = false, focusSheet = false, focusOtherSheet = false
            let runtime = ScopedNativeRootRuntime(attribute: { element, name in
                switch name {
                case kAXWindowsAttribute: return (.success, [root] as CFArray)
                case kAXTitleAttribute: return (.success, "Fixture" as CFString)
                case kAXWindowAttribute: return (.success, helper)
                case kAXFocusedWindowAttribute: return (.success, focusOtherSheet ? otherSheet : focusSheet ? sheet : root)
                case kAXRoleAttribute:
                    if CFEqual(element, otherSheet) { return (.success, kAXSheetRole as CFString) }
                    if CFEqual(element, sheet) {
                        sheetRoleReads += 1
                        if mode == "roleChanged" && sheetRoleReads > 1 { return (.success, kAXGroupRole as CFString) }
                    }
                    return (.success, (CFEqual(element, root) ? kAXWindowRole : CFEqual(element, sheet) && mode != "noSheet" ? kAXSheetRole : kAXButtonRole) as CFString)
                case kAXParentAttribute: return (.success, helper)
                default: Issue.record("Unexpected attribute read"); return (.noValue, nil)
                }
            }, owner: { element in
                if CFEqual(element, helper) {
                    return self.owner(77, uid: mode == "foreignHelperUser" ? 502 : self.uid, bundle: mode == "wrongHelper" ? "com.fixture.other" : "com.apple.appkit.xpc.openAndSavePanelService")
                }
                if mode == "foreignTarget" && CFEqual(element, child) || mode == "foreignSheet" && CFEqual(element, sheet) { return self.owner(78) }
                return self.owner()
            }, children: { element, check in
                try check()
                if CFEqual(element, helper) { helperChildrenRead = true }
                if CFEqual(element, root) { return BoundedSnapshotChildRead(elements: mode == "oversized" ? Array(repeating: sheet, count: 1001) : [sheet], complete: mode != "incomplete") }
                if CFEqual(element, sheet) {
                    sheetReads += 1
                    return BoundedSnapshotChildRead(elements: mode == "cycle" ? [root] : mode == "absent" || mode == "changed" && sheetReads > 1 ? [] : [child], complete: true)
                }
                return BoundedSnapshotChildRead(elements: [], complete: true)
            })
            let requested = try #require(try NativeWindowScope.requested(in: ["windowScope": ["title": "Fixture", "role": "AXWindow"]], method: "elements.snapshot"))
            let proof = try ScopedNativeRoot.resolveWindow(requested, application: app, pid: pid, uid: uid, birth: birth, bundle: bundle, check: {}, runtime: runtime)
            if mode == "valid" {
                try proof.validate(referenceElement: child, check: {}, runtime: runtime)
                #expect(throws: (any Error).self) {
                    try AXSemanticForegroundRecipient.bind(element: child, application: app, pid: pid, uid: uid, birth: birth, bundle: bundle, menuRoot: false, budget: Budget(milliseconds: 1000), runtime: runtime)
                }
                let recipient = try AXSemanticForegroundRecipient.bind(element: child, application: app, pid: pid, uid: uid, birth: birth, bundle: bundle, menuRoot: false, scopedWindow: proof, budget: Budget(milliseconds: 1000), runtime: runtime)
                #expect(try recipient.focused(Budget(milliseconds: 1000), runtime: runtime))
                #expect(CFEqual(try #require(recipient.window), root))
                focusSheet = true
                #expect(try recipient.focused(Budget(milliseconds: 1000), runtime: runtime))
                focusOtherSheet = true
                #expect(throws: (any Error).self) { try recipient.focused(Budget(milliseconds: 1000), runtime: runtime) }
            }
            else { #expect(throws: (any Error).self) { try proof.validate(referenceElement: child, check: {}, runtime: runtime) } }
            #expect(!helperChildrenRead, "Never inspect or authorize helper controls")
        }
    }
}
