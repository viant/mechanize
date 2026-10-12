import XCTest
import ApplicationServices
@testable import MechanizeNative

final class NativeCheckedReadTests: XCTestCase {
    func testRadioUsesSelectionOnlyWhenValueExplicitlyAbsent() throws {
        for status in [AXError.noValue, .attributeUnsupported] {
            XCTAssertTrue(try readCheckedState(role: "AXRadioButton", value: { (status, nil) }, selected: { (.success, NSNumber(value: true)) }))
            XCTAssertFalse(try readCheckedState(role: "AXRadioButton", value: { (status, nil) }, selected: { (.success, NSNumber(value: false)) }))
        }
    }
    func testTransportMixedAndUnrelatedRoleDoNotUseFallback() {
        for input in [(AXError.cannotComplete, nil as Any?), (.success, NSNumber(value: 2)), (.success, "true"), (.success, nil), (.noValue, NSNumber(value: true)), (.attributeUnsupported, NSNumber(value: true))] {
            var called = false
            XCTAssertThrowsError(try readCheckedState(role: "AXRadioButton", value: { input }, selected: { called = true; return (.success, NSNumber(value: true)) }))
            XCTAssertFalse(called)
        }
        for role in ["AXCheckBox", "AXGroup"] {
            var called = false
            XCTAssertThrowsError(try readCheckedState(role: role, value: { (.noValue, nil) }, selected: { called = true; return (.success, NSNumber(value: true)) }))
            XCTAssertFalse(called)
        }
    }
    func testPrimaryValueWinsAndMissingSelectionRemainsUnknown() throws {
        XCTAssertFalse(try readCheckedState(role: "AXRadioButton", value: { (.success, NSNumber(value: false)) }, selected: { XCTFail("unexpected fallback"); return (.success, NSNumber(value: true)) }))
        XCTAssertThrowsError(try readCheckedState(role: "AXRadioButton", value: { (.noValue, nil) }, selected: { (.noValue, nil) }))
        XCTAssertThrowsError(try readCheckedState(role: "AXRadioButton", value: { (.noValue, nil) }, selected: { (.success, NSNumber(value: 2)) }))
    }
}
