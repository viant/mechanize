import XCTest
@testable import MechanizeNativeCore
final class SemanticAXActionTests: XCTestCase {
    func testMenuDisclosureNeverSubstitutesPressOrConfirm() throws {
        for role in ["AXMenuButton", "AXPopUpButton"] {
            XCTAssertEqual(try qualifiedSemanticAXAction(method: "elements.showMenu", role: role, advertised: ["AXPress", "AXConfirm", "AXShowMenu"]), "AXShowMenu")
            XCTAssertThrowsError(try qualifiedSemanticAXAction(method: "elements.showMenu", role: role, advertised: ["AXPress", "AXConfirm"]))
        }
        for role in ["AXButton", "AXTextField", "AXSecureTextField", ""] {
            XCTAssertThrowsError(try qualifiedSemanticAXAction(method: "elements.showMenu", role: role, advertised: ["AXShowMenu"]))
        }
        XCTAssertThrowsError(try qualifiedSemanticAXAction(method: "elements.showMenu", role: "AXMenuButton", advertised: ["AXShowMenu "]))
    }
    func testExistingActionsRetainTheirExactSemantics() throws {
        XCTAssertEqual(try qualifiedSemanticAXAction(method: "elements.press", role: "AXMenuButton", advertised: ["AXPress", "AXShowMenu"]), "AXPress")
        XCTAssertEqual(try qualifiedSemanticAXAction(method: "elements.submit", role: "AXTextField", advertised: ["AXConfirm"]), "AXConfirm")
        XCTAssertThrowsError(try qualifiedSemanticAXAction(method: "arbitrary", role: "AXMenuButton", advertised: ["AXShowMenu"]))
    }
}
