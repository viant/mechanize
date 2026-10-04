import XCTest
@testable import MechanizeNativeCore

final class StaticTextReadTests: XCTestCase {
    func testExplicitNoneditableStaticTextWithoutIdentifier() throws {
        try StaticTextRead.authorize(allowed: true, role: "AXStaticText", subrole: nil, subroleKnown: true, valueSettable: false)
        XCTAssertEqual(try StaticTextRead.bounded("391"), "391")
    }
    func testClassificationFailsClosed() {
        for (allowed, role, subrole, known, settable) in [
            (false, "AXStaticText", nil as String?, true, false as Bool?),
            (true, "AXTextField", nil, true, false),
            (true, "AXTextArea", nil, true, false),
            (true, "AXStaticText", "AXSecureTextField", true, false),
            (true, "AXStaticText", nil, false, false),
            (true, "AXStaticText", nil, true, true),
            (true, "AXStaticText", nil, true, nil)
        ] {
            XCTAssertThrowsError(try StaticTextRead.authorize(allowed: allowed, role: role, subrole: subrole, subroleKnown: known, valueSettable: settable))
        }
    }
    func testBoundedUTF8AndNoTruncation() throws {
        XCTAssertEqual(try StaticTextRead.bounded(String(repeating: "a", count: 4096)).utf8.count, 4096)
        XCTAssertThrowsError(try StaticTextRead.bounded(String(repeating: "é", count: 2049)))
        XCTAssertThrowsError(try StaticTextRead.bounded("391\0secret"))
        XCTAssertThrowsError(try StaticTextRead.bounded(nil))
    }
}
