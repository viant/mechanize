import XCTest
@testable import MechanizeNativeCore
final class CheckedReadTests: XCTestCase {
    func testOnlyExactBooleanCheckboxAndRadioStates() throws {
        for role in ["AXCheckBox", "AXRadioButton"] {
            XCTAssertFalse(try CheckedRead.decode(role: role, value: NSNumber(value: 0)))
            XCTAssertTrue(try CheckedRead.decode(role: role, value: NSNumber(value: true)))
            for value in [nil, "true", NSNumber(value: 2), NSNumber(value: -1), NSNumber(value: 0.5), NSNumber(value: Double.nan)] as [Any?] {
                XCTAssertThrowsError(try CheckedRead.decode(role: role, value: value))
            }
        }
        XCTAssertThrowsError(try CheckedRead.decode(role: "AXTextField", value: NSNumber(value: 1)))
        XCTAssertThrowsError(try CheckedRead.decode(role: nil, value: NSNumber(value: 1)))
    }
}
