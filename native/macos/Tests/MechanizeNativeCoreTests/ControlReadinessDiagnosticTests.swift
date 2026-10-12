import XCTest
@testable import MechanizeNativeCore

final class ControlReadinessDiagnosticTests: XCTestCase {
    func testOnlyAuthenticatedExactManagedDoctorMayLog() {
        for (authenticated, request) in [(false, "launch-readiness"), (true, "doctor"), (true, "launch-readiness-private-canary"), (true, "launch-readiness\n")] {
            XCTAssertNil(ControlReadinessDiagnostic.line(authenticated: authenticated, requestID: request, doctor: [:], probes: [:], expectedUID: 501))
        }
        XCTAssertNotNil(ControlReadinessDiagnostic.line(authenticated: true, requestID: "launch-readiness", doctor: [:], probes: [:], expectedUID: 501))
    }
    func testProjectionIncludesOnlyFixedLabelsBooleansAndClosedProbeCodes() throws {
        let doctor: [String: Any] = ["brokerIdentityAuthenticated":true, "axTrusted":true, "semanticEnabled":false,
            "secureInputEnabled":false, "targetedKeyboardEnabled":false, "private-key-canary":"private-value-canary",
            "pid":987654, "bundleID":"private-bundle-canary", "windowTitle":"private-title-canary", "nonce":"private-nonce-canary",
            "windowSession":["available":true,"onConsole":true,"loginDone":true,"uid":UInt32(987654)]]
        let line = try XCTUnwrap(ControlReadinessDiagnostic.line(authenticated:true,requestID:"launch-readiness",doctor:doctor,
            probes:[.targetedKeyboard:.foregroundCorroborationConflict,.sessionText:.ready],expectedUID:987654))
        XCTAssertTrue(line.contains("brokerAuth=true")); XCTAssertTrue(line.contains("secureInput=false")); XCTAssertTrue(line.contains("semantic=false"))
        XCTAssertTrue(line.contains("sessionUIDMatch=true")); XCTAssertTrue(line.contains("targetedKeyboardProbe=foregroundCorroborationConflict"))
        XCTAssertTrue(line.contains("sessionTextProbe=ready")); XCTAssertTrue(line.contains("sessionKeyboardProbe=notEvaluated"))
        XCTAssertFalse(line.contains("private-")); XCTAssertFalse(line.contains("987654")); XCTAssertFalse(line.contains("nonce")); XCTAssertFalse(line.contains("bundle"))
        XCTAssertLessThan(line.utf8.count, 1024)
    }
    func testMalformedBooleansAndUIDAreUnknownRatherThanAuthority() throws {
        for uid: Any in [true, "private-uid-canary", -1, 501.5, Double.infinity] {
            let line = try XCTUnwrap(ControlReadinessDiagnostic.line(authenticated:true,requestID:"launch-readiness",
                doctor:["axTrusted":1,"semanticEnabled":"private-flag-canary","windowSession":["uid":uid]],probes:[:],expectedUID:501))
            XCTAssertTrue(line.contains("AX=unknown")); XCTAssertTrue(line.contains("semantic=unknown")); XCTAssertTrue(line.contains("sessionUIDMatch=unknown"))
            XCTAssertFalse(line.contains("private-"))
        }
    }
    func testRawFailureMessagesAndArbitraryCodesCannotEscape() {
        for code in ["foregroundRefreshUnavailable", "foregroundUnavailable", "foregroundNotActive", "foregroundOwnerUnqualified", "foregroundCorroborationConflict", "deadlineExceeded"] {
            let result = ControlReadinessProbeResult.failure(NativeFailure(code, "private-message-canary"))
            XCTAssertEqual(result.rawValue,code); XCTAssertFalse(result.rawValue.contains("private-"))
        }
        for code in ["private-code-canary", "ready", "foregroundChanged", "foregroundNotActive\nprivate-canary"] {
            XCTAssertEqual(ControlReadinessProbeResult.failure(NativeFailure(code,"private-message-canary")),.probeUnavailable)
        }
        XCTAssertEqual(ControlReadinessProbeResult.failure(NSError(domain:"private-domain-canary",code:1,userInfo:[NSLocalizedDescriptionKey:"private-message-canary"])),.probeUnavailable)
    }
}
