import XCTest
@testable import MechanizeNativeCore
final class InputSafetyTests: XCTestCase {
    func testDefaultInhibitedAndSuccessfulRelease() throws {
        let state = InputSafety(); var events: [String] = []
        XCTAssertThrowsError(try state.press(token: "key", down: { events.append("down"); return true }, up: { events.append("up"); return true }))
        XCTAssertTrue(events.isEmpty)
        state.enable()
        try state.press(token: "key", down: { events.append("down"); return true }, up: { events.append("up"); return true })
        XCTAssertEqual(events, ["down", "up"])
        XCTAssertEqual(state.inhibitAndRelease().released, 0)
        XCTAssertThrowsError(try state.press(token: "key", down: { true }, up: { true }))
    }
    func testUnknownDownPreservesCleanup() throws {
        let state = InputSafety(); var released = 0; state.enable()
        XCTAssertThrowsError(try state.press(token: "key", down: { false }, up: { released += 1; return true }))
        let result = state.inhibitAndRelease()
        XCTAssertEqual(released, 1); XCTAssertEqual(result.released, 1); XCTAssertEqual(result.unknown, 0)
    }
    func testUnknownCleanupReported() throws {
        let state = InputSafety(); state.enable()
        XCTAssertThrowsError(try state.press(token: "button", down: { true }, up: { false }))
        XCTAssertEqual(state.inhibitAndRelease().unknown, 1)
    }
    func testBusinessUncertaintyDoesNotInventHeldInputs() {
        let state = InputSafety()
        let outcome = state.cleanupOutcome(businessOutcomeUnknown: true)
        XCTAssertEqual(outcome.releasesDispatched, 0)
        XCTAssertEqual(outcome.unknownReleases, 0)
        XCTAssertTrue(outcome.businessOutcomeUnknown)
        XCTAssertThrowsError(try state.press(token: "key", down: { XCTFail("down must remain inhibited"); return true }, up: { true }))
    }
    func testUnconfirmedReleaseSurvivesRepeatedCleanup() throws {
        let state = InputSafety(); state.enable(); var confirmed = false
        XCTAssertThrowsError(try state.press(token: "button", down: { true }, up: { confirmed }))
        XCTAssertEqual(state.inhibitAndRelease().unknown, 1)
        XCTAssertEqual(state.inhibitAndRelease().unknown, 1)
        confirmed = true
        XCTAssertEqual(state.inhibitAndRelease().released, 1)
        XCTAssertEqual(state.inhibitAndRelease().unknown, 0)
    }
}
