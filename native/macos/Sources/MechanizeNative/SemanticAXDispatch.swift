import ApplicationServices
import MechanizeNativeCore

struct SemanticAXDispatchRuntime {
    let setTimeout: (AXUIElement, Float) -> AXError
    let perform: (AXUIElement, String) -> AXError
    static let system = SemanticAXDispatchRuntime(
        setTimeout: { AXUIElementSetMessagingTimeout($0, $1) },
        perform: { AXUIElementPerformAction($0, $1 as CFString) })
}

/// Scoped ancestry validation changes AX reference timeouts for its reads.
/// Restore the action cap only after that validation, and prove timeout
/// configuration succeeded before reserving or issuing the one native action.
/// A native error is returned unchanged: it never authorizes replay or fallback.
func dispatchSemanticAXAction(_ element: AXUIElement, action: String, budget: Budget,
                             revalidate: () throws -> Void, reserve: () throws -> Void,
                             runtime: SemanticAXDispatchRuntime = .system) throws -> AXError {
    try budget.check()
    try revalidate()
    try budget.check()
    // Save/export and modal actions can complete successfully after a short
    // accessibility read deadline. Give the one action a bounded response
    // interval; fast actions return immediately, and errors remain uncertain.
    let timeout = min(Float(2), budget.remainingSeconds)
    guard timeout.isFinite, timeout > 0 else {
        throw NativeFailure("deadlineExceeded", "Native request deadline expired")
    }
    guard runtime.setTimeout(element, timeout) == .success else {
        throw NativeFailure("actionTimeoutUnavailable", "Bounded semantic action timeout could not be configured")
    }
    try budget.check()
    try reserve()
    return runtime.perform(element, action)
}
