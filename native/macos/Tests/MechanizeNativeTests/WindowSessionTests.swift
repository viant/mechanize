import XCTest
import CoreGraphics
@testable import MechanizeNative

final class WindowSessionTests: XCTestCase {
    private func session(_ uid: Any = NSNumber(value: 501)) -> [String: Any] {
        [kCGSessionOnConsoleKey: NSNumber(value: true), kCGSessionLoginDoneKey: NSNumber(value: true), kCGSessionUserIDKey: uid]
    }
    func testUnavailableSessionDoesNotInferOwnership() {
        let value = windowSessionState(nil)
        XCTAssertEqual(value["available"] as? Bool, false)
        XCTAssertTrue(value["uid"] is NSNull)
        XCTAssertNil(value["unlocked"])
    }
    func testPublicOwnershipFactsDoNotClaimUnlocked() {
        let value = windowSessionState(session())
        XCTAssertEqual(value["available"] as? Bool, true)
        XCTAssertEqual(value["onConsole"] as? Bool, true)
        XCTAssertEqual(value["loginDone"] as? Bool, true)
        XCTAssertEqual(value["uid"] as? UInt32, 501)
        XCTAssertNil(value["unlocked"])
    }
    func testLoginAndConsoleFalseRemainObservedFacts() {
        var dictionary = session()
        dictionary[kCGSessionOnConsoleKey] = NSNumber(value: false)
        dictionary[kCGSessionLoginDoneKey] = NSNumber(value: false)
        let value = windowSessionState(dictionary)
        XCTAssertEqual(value["available"] as? Bool, true)
        XCTAssertEqual(value["onConsole"] as? Bool, false)
        XCTAssertEqual(value["loginDone"] as? Bool, false)
    }
    func testIncompleteAndWrongTypesFailClosed() {
        var dictionary = session()
        dictionary.removeValue(forKey: kCGSessionLoginDoneKey)
        XCTAssertEqual(windowSessionState(dictionary)["available"] as? Bool, false)
        dictionary = session()
        dictionary[kCGSessionOnConsoleKey] = NSNumber(value: 1)
        XCTAssertEqual(windowSessionState(dictionary)["available"] as? Bool, false)
        for uid in [NSNumber(value: -1), NSNumber(value: Double(UInt32.max)+1), NSNumber(value: 501.5), NSNumber(value: true)] {
            let value = windowSessionState(session(uid))
            XCTAssertEqual(value["available"] as? Bool, false)
            XCTAssertTrue(value["uid"] is NSNull)
        }
    }
}
