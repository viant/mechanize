import XCTest
@testable import MechanizeNativeCore
final class TargetedKeyboardTests: XCTestCase {
    func testClosedKeysAndChooserChord() throws {
        for key in ["Space","Tab","Return","Escape","ArrowLeft","PageDown"] { XCTAssertEqual(try TargetedKeyChord(key).key,key) }
        for index in 1...20 { XCTAssertEqual(try TargetedKeyChord("F\(index)").key,"F\(index)") }
        let chord = try TargetedKeyChord("Cmd+Shift+G")
        XCTAssertEqual(chord.key,"G"); XCTAssertEqual(chord.modifiers,["Command","Shift"])
        let functionChord = try TargetedKeyChord("Cmd+Shift+F2")
        XCTAssertEqual(functionChord.key,"F2"); XCTAssertEqual(functionChord.modifiers,["Command","Shift"])
        XCTAssertEqual(try TargetedKeyChord("Enter").key,"Return")
    }
    func testRejectsRawCodesTextSequencesAndAmbiguousModifiers() {
        for key in ["", "49", "F0", "F01", "F21", "F0001", "0x7A", "Space Space", "Command+Command+G", "Cmd+Command+G", "Alt+G", "+G", "Command+", "g", "Cmd+Shift+G+Space", String(repeating:"X",count:65)] { XCTAssertThrowsError(try TargetedKeyChord(key)) }
    }
    func testPreflightRevocationIsInsideInhibitionLockBeforeAnyEvent() {
        let input = InputSafety(); input.enable(); var events:[String]=[]
        XCTAssertThrowsError(try input.press(token:"key",preflight:{throw NativeFailure("staleFocus","focus or birth changed")},down:{events.append("down");return true},up:{events.append("up");return true}))
        XCTAssertTrue(events.isEmpty); XCTAssertEqual(input.inhibitAndRelease().released,0)
    }
    func testLostKeyupRetainsCleanupAndNeverRepeatsKeydown() throws {
        let input = InputSafety(); input.enable(); var downs=0, ups=0;var processSame=false
        XCTAssertThrowsError(try input.press(token:"key",down:{downs+=1;return true},up:{ups+=1;return processSame}))
        XCTAssertEqual(input.inhibitAndRelease().unknown,1)
        XCTAssertThrowsError(try input.press(token:"key",down:{downs+=1;return true},up:{true}))
        processSame=true;XCTAssertEqual(input.inhibitAndRelease().released,1)
        XCTAssertEqual(downs,1);XCTAssertEqual(ups,3)
    }
}
