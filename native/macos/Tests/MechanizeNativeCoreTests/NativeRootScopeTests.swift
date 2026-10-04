import XCTest
@testable import MechanizeNativeCore

final class NativeRootScopeTests: XCTestCase {
    func testClosedRootsAreSnapshotOnlyAndExclusiveWithAnyWindowField() throws {
        for scope in NativeRootScope.allCases {
            XCTAssertEqual(try NativeRootScope.requested(in: ["rootScope": scope.rawValue], method: "elements.snapshot"), scope)
            for method in ["windows.list", "elements.read", "elements.press"] {
                XCTAssertThrowsError(try NativeRootScope.requested(in: ["rootScope": scope.rawValue], method: method))
            }
            for field in ["windowIndex", "windowRef"] {
                XCTAssertThrowsError(try NativeRootScope.requested(in: ["rootScope": scope.rawValue, field: NSNull()], method: "elements.snapshot"))
            }
        }
        for value: Any in ["", "application", "focusedWindow", "systemWide", 1, true, NSNull()] {
            XCTAssertThrowsError(try NativeRootScope.requested(in: ["rootScope": value], method: "elements.snapshot"))
        }
        XCTAssertNil(try NativeRootScope.requested(in: [:], method: "elements.snapshot"))
        XCTAssertNil(try NativeRootScope.requested(in: ["windowIndex": 0], method: "elements.snapshot"))
    }
}
