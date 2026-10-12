import XCTest
import AppKit
import Carbon
@testable import MechanizeNative

final class NamedKeyEventsTests: XCTestCase {
    func unicode(_ event: CGEvent) -> String {
        var count = 0; var text = [UniChar](repeating: 0, count: 8)
        event.keyboardGetUnicodeString(maxStringLength: text.count, actualStringLength: &count, unicodeString: &text)
        return String(utf16CodeUnits: text, count: count)
    }
    func testShiftPrintableUpdatesBothPayloadsWithoutPosting() throws {
        let (down, up) = try namedWindowKeyEvents(key: "S", keyCode: CGKeyCode(kVK_ANSI_S), modifiers: ["Shift"], translateShift: { code in
            XCTAssertEqual(code, CGKeyCode(kVK_ANSI_S)); return Array("S".utf16)
        })
        try validateNamedWindowKeyText(down, key: "S", keyCode: CGKeyCode(kVK_ANSI_S), modifiers: ["Shift"], translateShift: { _ in Array("S".utf16) })
        XCTAssertThrowsError(try validateNamedWindowKeyText(down, key: "S", keyCode: CGKeyCode(kVK_ANSI_S), modifiers: ["Shift"], translateShift: { _ in Array("T".utf16) }))
        XCTAssertEqual(unicode(down), "S"); XCTAssertEqual(unicode(up), "S")
        XCTAssertTrue(down.flags.contains(.maskShift)); XCTAssertTrue(up.flags.isEmpty)
        XCTAssertEqual(down.getIntegerValueField(.keyboardEventKeycode), Int64(kVK_ANSI_S))
    }
    func testShortcutsAndNamedKeysKeepTheirOriginalRoute() throws {
        for (key, modifiers) in [("S", ["Command", "Shift"]), ("S", ["Control"]), ("S", ["Option"]), ("S", []), ("Tab", ["Shift"])] {
            _ = try namedWindowKeyEvents(key: key, keyCode: 1, modifiers: modifiers, translateShift: { _ in XCTFail("shortcut translated as text"); return [] })
        }
        XCTAssertThrowsError(try namedWindowKeyEvents(key: "S", keyCode: 1, modifiers: ["bogus"]))
        XCTAssertThrowsError(try namedWindowKeyEvents(key: "S", keyCode: 1, modifiers: ["Shift"], translateShift: { _ in [] }))
    }
}
