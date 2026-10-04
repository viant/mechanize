import Foundation

/// Separate from editable field value policy: app authorization permits only
/// positively classified, noneditable static text, and never snapshot values.
public enum StaticTextRead {
    public static let maximumBytes = 4096
    public static func authorize(allowed: Bool, role: String?, subrole: String?, subroleKnown: Bool, valueSettable: Bool?) throws {
        guard allowed, role == "AXStaticText", subroleKnown,
              subrole != "AXSecureTextField", valueSettable == false else {
            throw NativeFailure("staticTextReadDenied", "Explicit app policy and positively classified nonsecure, noneditable static text required")
        }
    }
    public static func bounded(_ value: String?) throws -> String {
        guard let value = value, value.utf8.count <= maximumBytes, !value.contains("\0") else {
            throw NativeFailure("attributeUnavailable", "Static text is unavailable or exceeds bounded string policy")
        }
        return value
    }
}
