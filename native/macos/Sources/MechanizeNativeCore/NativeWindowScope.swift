import Foundation

public struct NativeWindowScope: Equatable {
    public let title: String
    public let role: String?
    public var metadata: [String: String] { var result = ["title": title]; if let role { result["role"] = role }; return result }
    public static func requested(in params: [String: Any], method: String) throws -> NativeWindowScope? {
        guard params.keys.contains("windowScope") else { return nil }
        guard method == "elements.snapshot", !params.keys.contains("rootScope"), !params.keys.contains("windowIndex"), !params.keys.contains("windowRef"),
              let value = params["windowScope"] as? [String: Any], value.keys.allSatisfy({ ["title", "role"].contains($0) }),
              let title = value["title"] as? String, !title.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty, title.utf8.count <= 512, !title.contains("\0") else {
            throw NativeFailure("invalidScope", "Closed exact window title scope required")
        }
        let role: String?
        if value.keys.contains("role") {
            guard let supplied = value["role"] as? String, ["window", "AXWindow"].contains(supplied) else { throw NativeFailure("invalidScope", "Exact window role required") }
            role = supplied
        } else { role = nil }
        return NativeWindowScope(title: title, role: role)
    }
}
