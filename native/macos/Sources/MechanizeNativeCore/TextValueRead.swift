import Foundation

/// An absent optional AXSubrole is distinct from an unreadable or malformed one.
/// The caller must positively identify the exact enrolled field and its text role.
public enum TextValueRead {
    public static func permitted(allowed: Bool, expectedIdentifier: String?, identifier: String?,
                                 role: String?, subrole: String?, subroleKnown: Bool) -> Bool {
        guard allowed, let expectedIdentifier, !expectedIdentifier.isEmpty,
              identifier == expectedIdentifier, ["AXTextField", "AXTextArea", "AXComboBox"].contains(role ?? ""),
              subroleKnown, subrole != "AXSecureTextField" else { return false }
        return true
    }
}
