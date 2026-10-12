import XCTest
@testable import MechanizeNative

final class ConsoleDelegationTests:XCTestCase {
    func testClosedDelegationRequiresExactSeparateBrokerAndParentPin() throws {
        XCTAssertNil(try consoleDelegationArguments(["helper","--private-administration"]))
        let valid = ["helper","--console-owned","--console-parent-requirement","exact-console-pin","--console-broker-pid","123"]
        let result = try XCTUnwrap(consoleDelegationArguments(valid))
        XCTAssertEqual(result.broker,123);XCTAssertEqual(result.requirement,"exact-console-pin")
        for malformed in [Array(valid.dropLast()),valid + ["--console-owned"],valid + ["--console-broker-pid","456"],Array(valid.filter{$0 != "--console-owned"}),["helper","--console-owned"],valid.map{$0 == "123" ? "00123" : $0},valid.map{$0 == "123" ? "1" : $0},valid.map{$0 == "exact-console-pin" ? "" : $0}] {
            XCTAssertThrowsError(try consoleDelegationArguments(malformed))
        }
    }
}
