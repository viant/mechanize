import Foundation

public enum NativeRootScope: String, CaseIterable {
    case menuBar, focusedElement

    /// Native roots narrow a snapshot; they never compose with window selection.
    public static func requested(in params: [String: Any], method: String) throws -> NativeRootScope? {
        guard params.keys.contains("rootScope") else { return nil }
        guard method == "elements.snapshot", !params.keys.contains("windowScope"), !params.keys.contains("windowIndex"), !params.keys.contains("windowRef"),
              let raw = params["rootScope"] as? String, let scope = Self(rawValue: raw) else {
            throw NativeFailure("invalidScope", "Exact native root scope is required and cannot combine with window selection")
        }
        return scope
    }
}
