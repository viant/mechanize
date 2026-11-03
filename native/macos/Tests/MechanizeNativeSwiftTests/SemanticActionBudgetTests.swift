import Testing
import ApplicationServices
@testable import MechanizeNative
import MechanizeNativeCore

struct SemanticActionBudgetTests {
    @Test func slowAcknowledgementDoesNotUseObservationTimeout() throws {
        let target = AXUIElementCreateApplication(42_000)
        var timeout: Float = 0, calls = 0, events: [String] = []
        let runtime = SemanticAXDispatchRuntime(setTimeout: { _, value in
            timeout = value; events.append("timeout"); return .success
        }, perform: { _, _ in
            calls += 1; events.append("perform")
            // A synthetic provider needs 350 ms to acknowledge the single action.
            return timeout >= 0.35 ? .success : .cannotComplete
        })
        let result = try dispatchSemanticAXAction(target, action: "AXPress", budget: Budget(milliseconds: 3000), revalidate: { events.append("validate") }, reserve: { events.append("reserve") }, runtime: runtime)
        #expect(result == .success)
        #expect(timeout == 2)
        #expect(calls == 1)
        #expect(events == ["validate", "timeout", "reserve", "perform"])
    }

    @Test func shortDeadlineAndNativeUncertaintyRemainBounded() throws {
        var timeout: Float = 0, calls = 0, reserves = 0
        let runtime = SemanticAXDispatchRuntime(setTimeout: { _, value in timeout = value; return .success }, perform: { _, _ in calls += 1; return .cannotComplete })
        let result = try dispatchSemanticAXAction(AXUIElementCreateApplication(42_000), action: "AXPress", budget: Budget(milliseconds: 50), revalidate: {}, reserve: { reserves += 1 }, runtime: runtime)
        #expect(timeout > 0 && timeout <= 0.05)
        #expect(result == .cannotComplete)
        #expect(calls == 1 && reserves == 1)
    }

    @Test func rejectedTimeoutNeverDispatches() throws {
        var calls = 0, reserves = 0
        let runtime = SemanticAXDispatchRuntime(setTimeout: { _, _ in .cannotComplete }, perform: { _, _ in calls += 1; return .success })
        #expect(throws: (any Error).self) {
            try dispatchSemanticAXAction(AXUIElementCreateApplication(42_000), action: "AXPress", budget: Budget(milliseconds: 3000), revalidate: {}, reserve: { reserves += 1 }, runtime: runtime)
        }
        #expect(calls == 0 && reserves == 0)
    }
}
