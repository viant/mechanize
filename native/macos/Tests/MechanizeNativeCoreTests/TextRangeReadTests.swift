import XCTest
@testable import MechanizeNativeCore

final class TextRangeReadTests: XCTestCase {
    func testCompleteUnicodeRangeAndExplicitEmptyValue() throws {
        for value in ["", "test", "a😀b"] {
            var validations = 0
            let result = try TextRangeRead.read(count: { value.utf16.count }, range: { count in
                XCTAssertEqual(count, value.utf16.count)
                return value
            }, revalidate: { validations += 1 })
            XCTAssertEqual(result, value)
            XCTAssertEqual(validations, 3)
        }
    }
    func testMissingTruncatedOversizedAndChangedRangesFail() {
        for length in [nil, -1, 65_537] as [Int?] {
            XCTAssertThrowsError(try TextRangeRead.read(count: { length }, range: { _ in
                XCTFail("invalid count must prevent range access"); return nil
            }, revalidate: {}))
        }
        for text in [nil, "x", "abc", "a\0"] as [String?] {
            XCTAssertThrowsError(try TextRangeRead.read(count: { 2 }, range: { _ in text }, revalidate: {}))
        }
        var reads = 0
        XCTAssertThrowsError(try TextRangeRead.read(count: { reads += 1; return reads }, range: { _ in "a" }, revalidate: {}))
        XCTAssertThrowsError(try TextRangeRead.read(count: { 40_000 }, range: { _ in String(repeating: "é", count: 40_000) }, revalidate: {}))
    }
    func testRevalidationFailurePropagatesWithoutReturningText() {
        struct Revoked: Error {}
        var calls = 0
        XCTAssertThrowsError(try TextRangeRead.read(count: { 1 }, range: { _ in "a" }, revalidate: {
            calls += 1
            if calls == 2 { throw Revoked() }
        }))
    }
}
