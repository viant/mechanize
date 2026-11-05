import Testing
import ApplicationServices
import Foundation
import MechanizeNativeCore
@testable import MechanizeNative

struct PrivatePasteMenuTests {
    @Test func uniqueStandardPasteUsesOnlyOwnedCompleteMenuMetadata() throws {
        for mode in ["valid", "duplicate", "foreign", "incomplete", "disabled", "alternate", "cycle"] {
            let app = AXUIElementCreateApplication(42000), menu = AXUIElementCreateApplication(42001)
            let item = AXUIElementCreateApplication(42002), other = AXUIElementCreateApplication(42003)
            let read: (AXUIElement, String) -> (AXError, CFTypeRef?) = { element, name in
                if name == kAXMenuBarAttribute { return (.success, menu) }
                if name == kAXRoleAttribute { return (.success, (CFEqual(element, menu) ? kAXMenuBarRole : kAXMenuItemRole) as CFString) }
                if name == kAXChildrenAttribute {
                    if mode == "incomplete" { return (.cannotComplete, nil) }
                    if CFEqual(element, menu) { return (.success, (mode == "duplicate" ? [item, other] : [item]) as CFArray) }
                    return (.success, (mode == "cycle" ? [menu] : []) as CFArray)
                }
                if name == kAXMenuItemCmdCharAttribute { return (.success, "v" as CFString) }
                if name == kAXMenuItemCmdModifiersAttribute { return (.success, NSNumber(value: mode == "alternate" ? 1 : 0)) }
                if name == kAXEnabledAttribute { return (.success, NSNumber(value: mode != "disabled")) }
                Issue.record("Unexpected menu attribute"); return (.attributeUnsupported, nil)
            }
            do {
                let found = try privatePasteMenuItem(application: app, check: {}, ownerMatches: { _ in mode != "foreign" }, attribute: read)
                #expect(mode == "valid" && CFEqual(found, item))
            } catch let error as NativeFailure { #expect(mode != "valid" && error.code == "privatePasteMenuUnavailable") }
        }
    }
}
