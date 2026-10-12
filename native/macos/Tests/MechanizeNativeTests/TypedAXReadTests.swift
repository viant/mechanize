import XCTest
import ApplicationServices
@testable import MechanizeNative

final class TypedAXReadTests: XCTestCase {
    func testStringsKeepMissingAndFailedReadsDistinct() {
        XCTAssertEqual(typedAXString(.success, "AXTextField").resolved, "AXTextField")
        XCTAssertFalse(typedAXString(.noValue, nil).failed)
        XCTAssertTrue(typedAXString(.noValue, "contradictory").failed)
        XCTAssertTrue(typedAXString(.cannotComplete, nil).failed)
        XCTAssertTrue(typedAXString(.success, nil).failed)
        XCTAssertTrue(typedAXString(.success, NSNumber(value: 1)).failed)
        XCTAssertTrue(typedAXString(.success, String(repeating: "x", count: 257)).failed)
    }
    func testBooleansRejectMixedStringAndNonfiniteStates() {
        XCTAssertEqual(typedAXBoolean(.success, NSNumber(value: true)).resolved, true)
        XCTAssertEqual(typedAXBoolean(.success, NSNumber(value: 0)).resolved, false)
        for value: Any in [NSNumber(value: 2), NSNumber(value: Double.nan), "true"] {
            XCTAssertTrue(typedAXBoolean(.success, value).failed)
        }
        XCTAssertTrue(typedAXBoolean(.attributeUnsupported, NSNumber(value: true)).failed)
        XCTAssertTrue(typedAXBoolean(.cannotComplete, NSNumber(value: true)).failed)
        XCTAssertFalse(typedAXBoolean(.attributeUnsupported, nil).failed)
    }
}
