import XCTest
import ApplicationServices
@testable import MechanizeNative
import MechanizeNativeCore

final class SemanticAXDispatchTests: XCTestCase {
    private let target = AXUIElementCreateApplication(42_000)

    func testScopedReadTimeoutIsReplacedOnlyAfterLastValidationBeforeDispatch() throws {
        var events: [String] = [], currentTimeout: Float = 0
        let runtime = SemanticAXDispatchRuntime(setTimeout: { element, timeout in
            XCTAssertTrue(CFEqual(element, self.target))
            currentTimeout = timeout; events.append("configure")
            return .success
        }, perform: { element, action in
            XCTAssertTrue(CFEqual(element, self.target)); XCTAssertEqual(action, "AXPress")
            XCTAssertEqual(currentTimeout, 0.2); events.append("perform"); return .success
        })
        let result = try dispatchSemanticAXAction(target, action: "AXPress", budget: Budget(milliseconds: 1000), revalidate: {
            events.append("validate")
            // Mirror scoped ancestry's write to this exact target reference.
            XCTAssertEqual(runtime.setTimeout(self.target, 0.1), .success)
            events.append("validated")
        }, reserve: {
            XCTAssertEqual(currentTimeout, 0.2); events.append("reserve")
        }, runtime: runtime)
        XCTAssertEqual(result, .success)
        XCTAssertEqual(events, ["validate", "configure", "validated", "configure", "reserve", "perform"])
    }

    func testActionTimeoutCannotExceedActualRemainingBudget() throws {
        let budget = try Budget(milliseconds: 50)
        var configured: Float = 0, calls = 0
        let runtime = SemanticAXDispatchRuntime(setTimeout: { _, timeout in
            configured = timeout; XCTAssertGreaterThan(timeout, 0); XCTAssertLessThanOrEqual(timeout, 0.05)
            return .success
        }, perform: { _, action in calls += 1; XCTAssertEqual(action, "AXShowMenu"); return .success })
        XCTAssertEqual(try dispatchSemanticAXAction(target, action: "AXShowMenu", budget: budget, revalidate: {}, reserve: {}, runtime: runtime), .success)
        XCTAssertLessThan(configured, 0.2); XCTAssertEqual(calls, 1)
    }

    func testTimeoutConfigurationRefusalNeverReservesOrPerforms() throws {
        let runtime = SemanticAXDispatchRuntime(setTimeout: { _, _ in .cannotComplete }, perform: { _, _ in XCTFail("Action sent after timeout configuration failure"); return .success })
        XCTAssertThrowsError(try dispatchSemanticAXAction(target, action: "AXPress", budget: Budget(milliseconds: 1000), revalidate: {}, reserve: { XCTFail("Mutation reserved before timeout confirmation") }, runtime: runtime)) {
            XCTAssertEqual(($0 as? NativeFailure)?.code, "actionTimeoutUnavailable")
        }
    }

    func testValidationFailureAndExpiredBudgetNeverConfigureOrDispatch() throws {
        for expired in [false, true] {
            let runtime = SemanticAXDispatchRuntime(setTimeout: { _, _ in XCTFail("Configured after failed preflight"); return .success }, perform: { _, _ in XCTFail("Dispatched after failed preflight"); return .success })
            let budget = try Budget(milliseconds: expired ? 1 : 1000)
            XCTAssertThrowsError(try dispatchSemanticAXAction(target, action: "AXPress", budget: budget, revalidate: {
                if expired { Thread.sleep(forTimeInterval: 0.003) }
                else { throw NativeFailure("staleReference", "Synthetic hierarchy changed") }
            }, reserve: { XCTFail("Reserved after failed preflight") }, runtime: runtime)) {
                XCTAssertEqual(($0 as? NativeFailure)?.code, expired ? "deadlineExceeded" : "staleReference")
            }
        }
    }

    func testTimeoutSetterCannotConsumeDeadlineThenDispatch() throws {
        let runtime = SemanticAXDispatchRuntime(setTimeout: { _, _ in Thread.sleep(forTimeInterval: 0.003); return .success }, perform: { _, _ in XCTFail("Dispatched after deadline"); return .success })
        XCTAssertThrowsError(try dispatchSemanticAXAction(target, action: "AXPress", budget: Budget(milliseconds: 1), revalidate: {}, reserve: { XCTFail("Reserved after deadline") }, runtime: runtime)) {
            XCTAssertEqual(($0 as? NativeFailure)?.code, "deadlineExceeded")
        }
    }

    func testNativeUncertaintyIsReturnedUnchangedAfterExactlyOneInvocation() throws {
        for action in ["AXPress", "AXShowMenu", "AXConfirm"] {
            var reserved = 0, calls: [String] = []
            let runtime = SemanticAXDispatchRuntime(setTimeout: { _, _ in .success }, perform: { _, received in calls.append(received); return .cannotComplete })
            let result = try dispatchSemanticAXAction(target, action: action, budget: Budget(milliseconds: 1000), revalidate: {}, reserve: { reserved += 1 }, runtime: runtime)
            XCTAssertEqual(result, .cannotComplete); XCTAssertEqual(result.rawValue, -25204)
            XCTAssertEqual(reserved, 1); XCTAssertEqual(calls, [action])
        }
    }
}
