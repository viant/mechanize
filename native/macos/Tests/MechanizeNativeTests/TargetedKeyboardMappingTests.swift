import XCTest
import Carbon
@testable import MechanizeNative
final class TargetedKeyboardMappingTests: XCTestCase {
    func testLayoutIndependentNavigationKeys() throws {
        XCTAssertEqual(try targetedKeyCode("Space"),49)
        XCTAssertEqual(try targetedKeyCode("Tab"),48)
        XCTAssertEqual(try targetedKeyCode("Return"),36)
        XCTAssertEqual(try targetedKeyCode("Escape"),53)
    }

    func testFunctionKeysUseCarbonKeyCodes() throws {
        let expected: [(String, CGKeyCode)] = [
            ("F1", CGKeyCode(kVK_F1)), ("F2", CGKeyCode(kVK_F2)), ("F3", CGKeyCode(kVK_F3)), ("F4", CGKeyCode(kVK_F4)),
            ("F5", CGKeyCode(kVK_F5)), ("F6", CGKeyCode(kVK_F6)), ("F7", CGKeyCode(kVK_F7)), ("F8", CGKeyCode(kVK_F8)),
            ("F9", CGKeyCode(kVK_F9)), ("F10", CGKeyCode(kVK_F10)), ("F11", CGKeyCode(kVK_F11)), ("F12", CGKeyCode(kVK_F12)),
            ("F13", CGKeyCode(kVK_F13)), ("F14", CGKeyCode(kVK_F14)), ("F15", CGKeyCode(kVK_F15)), ("F16", CGKeyCode(kVK_F16)),
            ("F17", CGKeyCode(kVK_F17)), ("F18", CGKeyCode(kVK_F18)), ("F19", CGKeyCode(kVK_F19)), ("F20", CGKeyCode(kVK_F20))
        ]
        for (name, code) in expected { XCTAssertEqual(try targetedKeyCode(name), code, name) }
    }
}
