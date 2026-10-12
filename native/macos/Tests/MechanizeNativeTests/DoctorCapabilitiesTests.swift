import XCTest
@testable import MechanizeNative

final class DoctorCapabilitiesTests: XCTestCase {
    func testActualDoctorRetainsTextAlongsideCaptureWithoutGrantingInput() async throws {
        let helper = Helper(brokerAuthenticated: false)
        XCTAssertNil(helper.watchdog, "Unauthenticated helpers must not consume arbitrary inherited descriptors")
        let reply = await helper.handle(["protocolVersion": 1, "requestId": "capability-regression", "method": "doctor", "deadlineRemainingMs": 3000, "params": [:]])
        XCTAssertNil(reply["error"])
        let doctor = try XCTUnwrap(reply["result"] as? [String: Any])
        let actions = try XCTUnwrap(doctor["nativeWindowActions"] as? [String])
        for action in ["typeText", "pressSessionKey", "captureFrame", "clickFrame", "setPosition"] {
            XCTAssertTrue(actions.contains(action), "Doctor dropped \(action)")
        }
        XCTAssertEqual(actions.count, Set(actions).count)
        let methods = try XCTUnwrap(doctor["supportedMethods"] as? [String])
        XCTAssertTrue(methods.contains("windows.typeText"))
        XCTAssertTrue(methods.contains("app.quit"))
        XCTAssertTrue(methods.contains("app.exitStatus"))
        XCTAssertEqual(doctor["quitEnabled"] as? Bool, false)
        XCTAssertEqual(doctor["sessionTextEnabled"] as? Bool, false)
        XCTAssertEqual(doctor["semanticEnabled"] as? Bool, false)
    }
}
