import XCTest
@testable import MechanizeNativeCore

final class NativeWindowPositionTests: XCTestCase {
    func testExactLogicalIntegerCoordinatesAndClosedShape() throws {
        for point in [["x": -32768, "y": 32767], ["x": 808, "y": 516]] {
            let position = try NativeWindowPosition(point)
            XCTAssertTrue(position.matches(x: Double(point["x"]!), y: Double(point["y"]!)))
            XCTAssertFalse(position.matches(x: Double(point["x"]!) + 0.5, y: Double(point["y"]!)))
        }
        for point: Any in [NSNull(), ["x": 0], ["x": 0, "y": 0, "width": 920], ["x": true, "y": 0], ["x": "808", "y": 516], ["x": 0.5, "y": 516], ["x": Double.infinity, "y": 0], ["x": Double.nan, "y": 0], ["x": -32769, "y": 0], ["x": 32768, "y": 0]] {
            XCTAssertThrowsError(try NativeWindowPosition(point)) { XCTAssertEqual(($0 as? NativeFailure)?.code, "invalidPosition") }
        }
    }
}
