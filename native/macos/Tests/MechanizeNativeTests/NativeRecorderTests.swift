import XCTest
import Darwin
import MechanizeNativeCore
@testable import MechanizeNative

private final class RecordingFixture {
    let lock = NSLock()
    let time = Date(timeIntervalSince1970: 1_800_000_000)
    var secure = false
    var ax = true
    var listen = true
    var authorized = true
    var watchdog = true
    var identityUID: UInt32 = 501
    var installs = 0
    var closes = 0
    var reads = 0
    var closeConfirmed = true
    var gate: DispatchSemaphore?
    var callback: ((NativeRecordingSignal) -> Void)?
    func update(_ body: () -> Void) { lock.lock(); body(); lock.unlock() }
    func count(_ key: KeyPath<RecordingFixture, Int>) -> Int { lock.lock(); defer { lock.unlock() }; return self[keyPath: key] }
    func send(_ signal: NativeRecordingSignal) { lock.lock(); let receive = callback; lock.unlock(); receive?(signal) }
    func runtime() -> NativeRecordingRuntime {
        NativeRecordingRuntime(currentUID: { 501 }, permissions: {
            self.lock.lock(); defer { self.lock.unlock() }
            return NativeRecordingPermissions(accessibility: self.ax, listening: self.listen, secureInput: self.secure)
        }, authorizedLive: { self.lock.lock(); defer { self.lock.unlock() }; return self.authorized }, watchdogLive: {
            self.lock.lock(); defer { self.lock.unlock() }; return self.watchdog
        }, now: { self.time }, resolve: { signal, _ in
            self.lock.lock(); self.reads += 1; let uid = self.identityUID; let gate = self.gate; self.lock.unlock()
            if let gate { _ = gate.wait(timeout: .now()+2) }
            let pid = signal.pid ?? 1001
            let identity = NativeRecordingIdentity(uid: uid, bundleID: pid == 1001 ? "com.example.Mail" : "com.example.Editor", pid: pid, startToken: "1790000000:\(pid)", windowID: "\(pid)")
            let target = signal.kind == .activation ? nil : NativeRecordingTarget(role: signal.kind == .textEdit ? "AXTextField" : "AXButton", identifier: "machine-control", identifierQualified: true)
            return NativeRecordingResolution(identity: identity, target: target, secure: false)
        }, install: { receive in
            self.lock.lock(); self.installs += 1; self.callback = receive; self.lock.unlock()
            return { self.lock.lock(); defer { self.lock.unlock() }; self.closes += 1; return self.closeConfirmed }
        })
    }
}

final class NativeRecorderTests: XCTestCase {
    func options(_ id: String = "fixture-recording") -> NativeRecordingOptions { NativeRecordingOptions(recordingID: id, expectedUID: 501, maxEvents: 128, durationMs: 60_000) }
    func waitUntil(_ condition: () throws -> Bool, file: StaticString = #filePath, line: UInt = #line) throws {
        let end = Date().addingTimeInterval(2)
        while Date() < end { if try condition() { return }; Thread.sleep(forTimeInterval: 0.005) }
        XCTFail("Injected recording operation did not complete", file: file, line: line)
    }
    func testDormantProducerThenCrossAppRecordingWithoutRawText() throws {
        let fixture = RecordingFixture(); let recorder = NativeRecorder(runtime: fixture.runtime())
        XCTAssertEqual(fixture.count(\.installs), 0)
        _ = try recorder.start(options())
        fixture.send(NativeRecordingSignal(.activation, timestamp: fixture.time, pid: 1001, trusted: true))
        fixture.send(NativeRecordingSignal(.primaryClick, timestamp: fixture.time, pid: 1001, trusted: true))
        fixture.send(NativeRecordingSignal(.textEdit, timestamp: fixture.time, pid: 1002, trusted: true))
        try waitUntil { try recorder.poll(after: 0).events.count == 4 }
        let batch = try recorder.stop()
        XCTAssertEqual(batch.state, "stopped")
        XCTAssertEqual(batch.events.compactMap { $0.nativeIdentity?.bundleID }, ["com.example.Mail", "com.example.Mail", "com.example.Editor"])
        let fill = try XCTUnwrap(batch.events.first { $0.kind == "fill" })
        XCTAssertTrue(fill.parameterRequired); XCTAssertTrue(fill.redacted)
        XCTAssertEqual(fill.nativeIdentity?.uid, 501); XCTAssertEqual(fill.nativeIdentity?.windowID, "1002")
        XCTAssertEqual(fill.nativeIdentity?.startToken, "1790000000:1002")
        let data = try JSONEncoder().encode(batch)
        let text = String(decoding: data, as: UTF8.self)
        XCTAssertFalse(text.contains("clipboard")); XCTAssertFalse(text.contains("typedText")); XCTAssertFalse(text.contains("\"value\":\"password"))
        XCTAssertEqual(fixture.count(\.installs), 1); XCTAssertEqual(fixture.count(\.closes), 1)
        XCTAssertThrowsError(try recorder.start(options("another")))
    }
    func testDeniedOrSecureStartupNeverInstallsProducer() {
        for mode in ["authorization", "watchdog", "ax", "listen", "secure"] {
            let fixture = RecordingFixture()
            fixture.update { switch mode { case "authorization": fixture.authorized = false; case "watchdog": fixture.watchdog = false; case "ax": fixture.ax = false; case "listen": fixture.listen = false; default: fixture.secure = true } }
            let recorder = NativeRecorder(runtime: fixture.runtime())
            XCTAssertThrowsError(try recorder.start(options()))
            XCTAssertEqual(fixture.count(\.installs), 0); XCTAssertEqual(fixture.count(\.reads), 0)
        }
        // Dormant production providers are denied before preflight/tap work.
        let dormant = NativeRecorder(runtime: .live(authorizedLive: { false }, watchdogLive: { false }))
        XCTAssertThrowsError(try dormant.start(NativeRecordingOptions(recordingID: "denied", expectedUID: getuid(), maxEvents: 128, durationMs: 60_000)))
    }
    func testSecureInputStopsBeforeAnyTargetRead() throws {
        let fixture = RecordingFixture(); let recorder = NativeRecorder(runtime: fixture.runtime())
        _ = try recorder.start(options())
        fixture.update { fixture.secure = true }
        fixture.send(NativeRecordingSignal(.textEdit, timestamp: fixture.time, pid: 1001))
        try waitUntil { try recorder.poll(after: 0).state == "paused" }
        let batch = try recorder.poll(after: 0)
        XCTAssertEqual(batch.gaps.first?.reason, "secureInput")
        XCTAssertEqual(fixture.count(\.reads), 0); XCTAssertEqual(fixture.count(\.closes), 1)
        _ = try recorder.stop()
    }
    func testPermissionConsentAndWatchdogLossAreExplicitGaps() throws {
        for mode in ["permissionLost", "consentWithdrawn", "watchdogStopped"] {
            let fixture = RecordingFixture(); let recorder = NativeRecorder(runtime: fixture.runtime())
            _ = try recorder.start(options())
            fixture.update { switch mode { case "permissionLost": fixture.listen = false; case "consentWithdrawn": fixture.authorized = false; default: fixture.watchdog = false } }
            let batch = try recorder.poll(after: 0)
            XCTAssertEqual(batch.state, "paused"); XCTAssertEqual(batch.gaps.first?.reason, mode)
            XCTAssertEqual(fixture.count(\.reads), 0); XCTAssertEqual(fixture.count(\.closes), 1)
            _ = try recorder.stop()
        }
    }
    func testUnresolvedActionsPreserveGapAndLaterAppEvents() throws {
        let fixture = RecordingFixture(); let recorder = NativeRecorder(runtime: fixture.runtime())
        _ = try recorder.start(options())
        fixture.update { fixture.identityUID = 502 }
        fixture.send(NativeRecordingSignal(.primaryClick, timestamp: fixture.time, pid: 1001))
        try waitUntil { try recorder.poll(after: 0).gaps.count == 1 }
        XCTAssertEqual(try recorder.poll(after: 0).state, "recording")
        fixture.update { fixture.identityUID = 501 }
        fixture.send(NativeRecordingSignal(.textEdit, timestamp: fixture.time, pid: 1002))
        try waitUntil { try recorder.poll(after: 0).events.contains { $0.kind == "fill" } }
        let batch = try recorder.stop()
        XCTAssertEqual(batch.gaps.first?.reason, "targetUnresolved")
        XCTAssertFalse(batch.events.contains { $0.nativeIdentity?.uid == 502 })
        XCTAssertEqual(batch.events.first { $0.kind == "fill" }?.nativeIdentity?.bundleID, "com.example.Editor")
    }
    func testBoundedBacklogAndUncertainStopCannotClaimCompletion() throws {
        let fixture = RecordingFixture(); let gate = DispatchSemaphore(value: 0)
        fixture.update { fixture.gate = gate }
        let recorder = NativeRecorder(runtime: fixture.runtime())
        _ = try recorder.start(options())
        fixture.send(NativeRecordingSignal(.primaryClick, timestamp: fixture.time, pid: 1001))
        try waitUntil { fixture.count(\.reads) == 1 }
        for _ in 0..<100 { fixture.send(NativeRecordingSignal(.health, timestamp: fixture.time)) }
        let batch = try recorder.poll(after: 0)
        XCTAssertEqual(batch.state, "paused"); XCTAssertEqual(batch.gaps.first?.reason, "producerOverflow")
        gate.signal(); _ = try recorder.stop()
        let uncertainFixture = RecordingFixture(); uncertainFixture.update { uncertainFixture.closeConfirmed = false }
        let uncertain = NativeRecorder(runtime: uncertainFixture.runtime())
        _ = try uncertain.start(options("uncertain"))
        XCTAssertEqual(try uncertain.stop().state, "stopUnconfirmed")
        XCTAssertEqual(try uncertain.stop().state, "stopUnconfirmed")
        uncertainFixture.update { uncertainFixture.closeConfirmed = true }
        XCTAssertEqual(try uncertain.stop().state, "stopped")
    }
}
