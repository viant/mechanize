import XCTest
@testable import MechanizeNativeCore

final class TextValueReadTests: XCTestCase {
    func testExactEnrolledTextAreaWithKnownAbsentSubrole() {
        XCTAssertTrue(TextValueRead.permitted(allowed: true, expectedIdentifier: "XLFormulaEditor",
            identifier: "XLFormulaEditor", role: "AXTextArea", subrole: nil, subroleKnown: true))
    }
    func testEnrolledComboBoxRequiresExactIdentityAndKnownNonsecureSubrole() {
        XCTAssertTrue(TextValueRead.permitted(allowed: true, expectedIdentifier: "NameBox",
            identifier: "NameBox", role: "AXComboBox", subrole: nil, subroleKnown: true))
        XCTAssertFalse(TextValueRead.permitted(allowed: false, expectedIdentifier: "NameBox",
            identifier: "NameBox", role: "AXComboBox", subrole: nil, subroleKnown: true))
        XCTAssertFalse(TextValueRead.permitted(allowed: true, expectedIdentifier: "NameBox",
            identifier: "other", role: "AXComboBox", subrole: nil, subroleKnown: true))
        XCTAssertFalse(TextValueRead.permitted(allowed: true, expectedIdentifier: "NameBox",
            identifier: "NameBox", role: "AXComboBox", subrole: "AXSecureTextField", subroleKnown: true))
        XCTAssertFalse(TextValueRead.permitted(allowed: true, expectedIdentifier: "NameBox",
            identifier: "NameBox", role: "AXComboBox", subrole: nil, subroleKnown: false))
    }
    func testSecureUnknownAndUnenrolledFieldsRemainBlocked() {
        XCTAssertFalse(TextValueRead.permitted(allowed: true, expectedIdentifier: "field", identifier: "field",
            role: "AXTextField", subrole: "AXSecureTextField", subroleKnown: true))
        XCTAssertFalse(TextValueRead.permitted(allowed: true, expectedIdentifier: "field", identifier: "field",
            role: "AXTextArea", subrole: nil, subroleKnown: false))
        XCTAssertFalse(TextValueRead.permitted(allowed: false, expectedIdentifier: "field", identifier: "field",
            role: "AXTextArea", subrole: nil, subroleKnown: true))
        XCTAssertFalse(TextValueRead.permitted(allowed: true, expectedIdentifier: "field", identifier: "other",
            role: "AXTextArea", subrole: nil, subroleKnown: true))
        XCTAssertFalse(TextValueRead.permitted(allowed: true, expectedIdentifier: "", identifier: "",
            role: "AXTextArea", subrole: nil, subroleKnown: true))
        XCTAssertFalse(TextValueRead.permitted(allowed: true, expectedIdentifier: "field", identifier: "field",
            role: "AXGroup", subrole: nil, subroleKnown: true))
    }
}
