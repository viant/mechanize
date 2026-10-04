import XCTest
@testable import MechanizeNative

final class ProcessIdentityTests: XCTestCase {
    func testCanonicalProcessToken() {
        XCTAssertTrue(validApplicationProcessStartToken("1790000000:0"))
        XCTAssertTrue(validApplicationProcessStartToken("1790000000:999999"))
        for token in ["fixture-start", "0:1", "1:01", "1:1000000", "1:1\n", "18446744073709551616:1", "-1:0"] {
            XCTAssertFalse(validApplicationProcessStartToken(token), token)
        }
    }
}
