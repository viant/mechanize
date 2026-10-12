import XCTest
import Darwin
@testable import MechanizeNative
import MechanizeNativeCore

final class ControlReadinessProbeTests: XCTestCase {
    private var session: [String: Any] { ["available":true,"onConsole":true,"loginDone":true,"uid":getuid()] }
    func testDiagnosticUsesSameSingleForegroundProbeAndDoesNotChangeResult() {
        for failing in [false,true] {
            for enabled in [false,true] {
                var probes = 0, received:[ControlReadinessProbeResult] = []
                let runtime = TargetedKeyboardSessionRuntime(session:{self.session},secureInput:{false},foreground:{
                    probes += 1
                    if failing { throw NativeFailure("foregroundRefreshUnavailable","private-message-canary") }
                })
                let callback: ((ControlReadinessProbeResult)->Void)? = enabled ? { received.append($0) } : nil
                XCTAssertEqual(targetedKeyboardSessionAvailable(diagnostic:callback,runtime:runtime),!failing)
                XCTAssertEqual(probes,1)
                XCTAssertEqual(received,enabled ? [failing ? .foregroundRefreshUnavailable:.ready] : [])
            }
        }
    }
    func testSessionAndSecureInputRefusalNeverProbeForeground() {
        for missing in ["available","onConsole","loginDone","uid","secure"] {
            var state = session, received:[ControlReadinessProbeResult] = []
            if missing != "secure" { state.removeValue(forKey:missing) }
            let runtime = TargetedKeyboardSessionRuntime(session:{state},secureInput:{missing == "secure"},foreground:{XCTFail("Foreground was inspected despite session refusal")})
            XCTAssertFalse(targetedKeyboardSessionAvailable(diagnostic:{received.append($0)},runtime:runtime))
            XCTAssertEqual(received,[.sessionUnqualified])
        }
    }
    func testForeignSessionAndUnexpectedProbeFailureRemainRefused() {
        var state = session; state["uid"] = getuid() + 1
        var received:[ControlReadinessProbeResult] = []
        let foreign = TargetedKeyboardSessionRuntime(session:{state},secureInput:{false},foreground:{XCTFail("Foreign session reached foreground")})
        XCTAssertFalse(targetedKeyboardSessionAvailable(diagnostic:{received.append($0)},runtime:foreign))
        XCTAssertEqual(received,[.sessionUnqualified]); received=[]
        let unexpected = TargetedKeyboardSessionRuntime(session:{self.session},secureInput:{false},foreground:{throw NativeFailure("private-code-canary","private-message-canary")})
        XCTAssertFalse(targetedKeyboardSessionAvailable(diagnostic:{received.append($0)},runtime:unexpected))
        XCTAssertEqual(received,[.probeUnavailable])
    }
}
