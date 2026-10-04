import XCTest
@testable import MechanizeNativeCore
final class VideoRecordingTests: XCTestCase {
    func authority(_ mode: String = "record") -> VideoRecordingAuthority { VideoRecordingAuthority(namespace: String(repeating: "a", count: 64), clientID: "client", sessionID: "session", grantID: "grant", mode: mode) }
    func testExplicitModeOwnerAndScopeRequired() throws {
        XCTAssertThrowsError(try VideoRecordingBudget(authority: authority("observe"), scope: .desktop, durationMs: 1000, maximumBytes: 100))
        XCTAssertThrowsError(try VideoRecordingBudget(authority: authority(), scope: .window(bundleID: "com.example.App", windowID: 0), durationMs: 1000, maximumBytes: 100))
        XCTAssertFalse(VideoRecordingAuthority(namespace: String(repeating: "a", count: 64), clientID: "", sessionID: "s", grantID: "g", mode: "record").valid)
        XCTAssertTrue(VideoRecordingScope.desktop.valid)
        XCTAssertTrue(VideoRecordingScope.application(bundleID: "com.example.App").valid)
    }
    func testCrossDisplayBudgetAndTimestampCorrelation() throws {
        var clock: UInt64 = 500
        let budget = try VideoRecordingBudget(authority: authority(), scope: .desktop, durationMs: 1000, maximumBytes: 10, maximumFrames: 3, wallTime: Date(timeIntervalSince1970: 1800000000), now: { clock })
        clock += 1000000
        let first = try XCTUnwrap(budget.accept(sizeBytes: 4, displayID: 1))
        XCTAssertEqual(first.sequence, 1); XCTAssertEqual(first.timestampUnixMs, 1800000000001)
        clock += 1000000
        XCTAssertEqual(budget.accept(sizeBytes: 6, displayID: 2)?.sequence, 2)
        XCTAssertNil(budget.accept(sizeBytes: 1, displayID: 2)); XCTAssertEqual(budget.snapshot.reason, "videoCapacity")
        XCTAssertEqual(budget.snapshot.bytes, 10)
        budget.stop(confirmed: false); XCTAssertEqual(budget.snapshot.state, "stopUnconfirmed")
    }
    func testPauseRevokeAndDurationAreTerminal() throws {
        var clock: UInt64 = 100
        let budget = try VideoRecordingBudget(authority: authority(), scope: .desktop, durationMs: 1000, maximumBytes: 100, now: { clock })
        clock += 1000000000
        XCTAssertNil(budget.accept(sizeBytes: 1, displayID: 1)); XCTAssertEqual(budget.snapshot.reason, "durationExpired")
        let revoked = try VideoRecordingBudget(authority: authority(), scope: .desktop, durationMs: 1000, maximumBytes: 100)
        revoked.pause(reason: "consentWithdrawn"); XCTAssertNil(revoked.accept(sizeBytes: 1, displayID: 1))
        revoked.stop(confirmed: true); XCTAssertEqual(revoked.snapshot.reason, "consentWithdrawn")
    }
}
