import XCTest
@testable import MechanizeNative
import MechanizeNativeCore

final class PrivateAdministrationTests: XCTestCase {
    func testUnqualifiedOrdinaryHelperCannotServePrivateMethods() async {
        let helper = Helper(brokerAuthenticated:false)
        for method in ["private.consoleWindows","private.managementProof"] {
            let response = await helper.handle(["protocolVersion":1,"requestId":"fixture","helperEpoch":helper.epoch,"method":method,"deadlineRemainingMs":100,"params":[:]])
            XCTAssertNotNil(response["error"])
            XCTAssertNil(response["result"])
        }
    }
    func testMalformedNonceRejectedBeforeAnyAXAccess() throws {
        XCTAssertThrowsError(try privateAdministrationResult(method:"private.consoleWindows",params:["nonce":"malformed"],budget:Budget(milliseconds:100)))
    }
}
