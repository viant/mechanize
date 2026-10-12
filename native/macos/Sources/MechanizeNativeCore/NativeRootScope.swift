import Foundation

public enum NativeRootScope: String, CaseIterable {
    case menuBar, focusedElement

    /// Native roots narrow a snapshot; they never compose with window selection.
    public static func requested(in params: [String: Any], method: String) throws -> NativeRootScope? {
        if let menu=params["nativeMenu"] {
            guard method=="elements.snapshot",params["rootScope"] as? String=="menuBar",let name=menu as? String,!name.trimmingCharacters(in:.whitespacesAndNewlines).isEmpty,name.utf8.count<=256,name.rangeOfCharacter(from:.controlCharacters)==nil else {throw NativeFailure("invalidScope","Bounded exact menu name requires the menuBar root")}
        }
        guard params.keys.contains("rootScope") else { return nil }
        guard method == "elements.snapshot", !params.keys.contains("windowScope"), !params.keys.contains("windowIndex"), !params.keys.contains("windowRef"),
              let raw = params["rootScope"] as? String, let scope = Self(rawValue: raw) else {
            throw NativeFailure("invalidScope", "Exact native root scope is required and cannot combine with window selection")
        }
        return scope
    }
}
