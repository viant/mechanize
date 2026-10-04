import XCTest
@testable import MechanizeNativeCore

final class NativeWindowScopeTests: XCTestCase {
    func testClosedExactScopeAndExclusivity() throws {
        let result = try NativeWindowScope.requested(in: ["windowScope": ["title": "Save", "role": "window"]], method: "elements.snapshot")
        XCTAssertEqual(result?.metadata, ["title": "Save", "role": "window"])
        for params: [String: Any] in [["windowScope": ["title": ""]], ["windowScope": ["title": "Save", "extra": true]], ["windowScope": ["title": "Save", "role": "button"]], ["windowScope": ["title": "Save"], "rootScope": "menuBar"], ["windowScope": ["title": "Save"], "windowIndex": NSNull()], ["windowScope": ["title": "Save"], "windowRef": NSNull()]] {
            XCTAssertThrowsError(try NativeWindowScope.requested(in: params, method: "elements.snapshot"))
        }
        XCTAssertThrowsError(try NativeWindowScope.requested(in: ["windowScope": ["title": "Save"]], method: "windows.list"))
    }
}
