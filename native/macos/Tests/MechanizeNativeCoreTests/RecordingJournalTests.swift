import XCTest
@testable import MechanizeNativeCore

final class RecordingJournalTests: XCTestCase {
    let time = Date(timeIntervalSince1970: 1_800_000_000)
    func identity(_ bundle: String = "com.example.Mail", uid: UInt32 = 501, window: String? = "42") -> NativeRecordingIdentity {
        NativeRecordingIdentity(uid: uid, bundleID: bundle, pid: 123, startToken: "1790000000:1", windowID: window)
    }
    func testCrossApplicationIdentityOrderingAndWithheldIntent() throws {
        let journal = try RecordingJournal(recordingID: "desktop-demo", expectedUID: 501, now: time)
        let safe = NativeRecordingTarget(role: "AXButton", identifier: "save-button", identifierQualified: true)
        XCTAssertTrue(try journal.append(kind: "press", identity: identity(), target: safe, trusted: true, now: time))
        XCTAssertTrue(try journal.append(kind: "fill", identity: identity("com.example.Editor"), target: NativeRecordingTarget(role: "AXTextField", identifierDigest: String(repeating: "a", count: 64)), now: time))
        journal.stop(now: time)
        let batch = try journal.poll(after: 0)
        XCTAssertEqual(batch.events.map(\.sequence), [1,2,3,4])
        XCTAssertEqual(batch.events[1].nativeIdentity?.bundleID, "com.example.Mail")
        XCTAssertEqual(batch.events[2].nativeIdentity?.bundleID, "com.example.Editor")
        XCTAssertTrue(batch.events[2].redacted)
        XCTAssertTrue(batch.events[2].parameterRequired)
        XCTAssertEqual(batch.events[2].reason, "valueWithheld")
        XCTAssertEqual(batch.events[2].selectorConfidence, "unresolved")
        XCTAssertEqual(batch.state, "stopped")
        let data = try JSONEncoder().encode(batch)
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        for event in try XCTUnwrap(object["events"] as? [[String: Any]]) {
            XCTAssertNil(event["value"]); XCTAssertNil(event["text"]); XCTAssertNil(event["clipboard"])
        }
    }
    func testSaturationIsAnExplicitBoundedGapNotSilentEviction() throws {
        let journal = try RecordingJournal(recordingID: "bounded", expectedUID: 501, capacity: 4, now: time)
        let target = NativeRecordingTarget(role: "AXButton")
        XCTAssertTrue(try journal.append(kind: "press", identity: identity(), target: target, now: time))
        XCTAssertTrue(try journal.append(kind: "press", identity: identity(), target: target, now: time))
        XCTAssertFalse(try journal.append(kind: "press", identity: identity(), target: target, now: time))
        let batch = try journal.poll(after: 0)
        XCTAssertEqual(batch.events.count, 4); XCTAssertEqual(batch.state, "paused"); XCTAssertTrue(batch.truncated)
        XCTAssertEqual(batch.gaps.first?.reason, "journalCapacity"); XCTAssertTrue(batch.gaps.first?.unknownExtent == true)
        XCTAssertEqual(try journal.poll(after: 1, limit: 1).events.first?.sequence, 2)
        XCTAssertThrowsError(try journal.poll(after: 99)); XCTAssertThrowsError(try journal.poll(after: 0, limit: 65))
    }
    func testUnsafeMetadataForeignUserAndUnknownWindowNeverBecomeExact() throws {
        let journal = try RecordingJournal(recordingID: "scoped", expectedUID: 501, now: time)
        XCTAssertThrowsError(try journal.append(kind: "press", identity: identity(uid: 502), target: NativeRecordingTarget(role: "AXButton"), now: time))
        XCTAssertThrowsError(try journal.append(kind: "press", identity: identity(), target: NativeRecordingTarget(role: "AXButton", identifier: "private-secret"), now: time))
        XCTAssertThrowsError(try journal.append(kind: "press", identity: identity(), target: NativeRecordingTarget(role: "private title"), now: time))
        XCTAssertTrue(try journal.append(kind: "press", identity: identity(window: nil), target: NativeRecordingTarget(role: "AXButton"), now: time))
        XCTAssertEqual(try journal.poll(after: 1).events.first?.reason, "windowUnresolved")
        XCTAssertFalse(try journal.poll(after: 1).events.first!.trusted)
    }
    func testGapCoalescingPreservesLaterApplicationActionsAndStopUncertainty() throws {
        let journal = try RecordingJournal(recordingID: "gaps", expectedUID: 501, now: time)
        for _ in 0..<100 { journal.gap(reason: "unsupportedInput", now: time) }
        XCTAssertEqual(try journal.poll(after: 0).events.count, 2)
        XCTAssertTrue(try journal.append(kind: "press", identity: identity("com.example.Editor"), target: NativeRecordingTarget(role: "AXButton"), now: time))
        journal.pause(reason: "secureInput", now: time)
        XCTAssertFalse(try journal.append(kind: "press", identity: identity(), target: NativeRecordingTarget(role: "AXButton"), now: time))
        journal.stop(confirmed: false, now: time)
        XCTAssertEqual(try journal.poll(after: 0).state, "stopUnconfirmed")
        XCTAssertEqual(try journal.poll(after: 0).gaps.last?.reason, "secureInput")
    }
    func testMonotonicDurationCannotBeExtendedByWallClockRollback() throws {
        var uptime: UInt64 = 100
        let journal = try RecordingJournal(recordingID: "monotonic", expectedUID: 501, durationMs: 1000, now: time, monotonicNow: { uptime })
        uptime += 1_000_000_000
        let batch = try journal.poll(after: 0)
        XCTAssertEqual(batch.state, "paused")
        XCTAssertEqual(batch.gaps.first?.reason, "durationExpired")
    }
    func testDurationAndInvalidClockBounds() throws {
        XCTAssertThrowsError(try RecordingJournal(recordingID: "bad", expectedUID: 501, now: Date(timeIntervalSince1970: .infinity)))
        let journal = try RecordingJournal(recordingID: "duration", expectedUID: 501, durationMs: 1000, now: time)
        XCTAssertFalse(try journal.append(kind: "press", identity: identity(), target: NativeRecordingTarget(role: "AXButton"), now: time.addingTimeInterval(1)))
        XCTAssertEqual(try journal.poll(after: 0).gaps.first?.reason, "durationExpired")
    }
}
