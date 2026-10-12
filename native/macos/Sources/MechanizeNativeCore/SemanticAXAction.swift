import Foundation

/// Menu disclosure is a distinct action. Pressing a split menu button may
/// perform its default document mutation instead of opening its options.
public func qualifiedSemanticAXAction(method: String, role: String, advertised: [String]) throws -> String {
    let action: String
    switch method {
    case "elements.press": action = "AXPress"
    case "elements.submit": action = "AXConfirm"
    case "elements.showMenu":
        guard ["AXMenuButton", "AXPopUpButton"].contains(role) else {
            throw NativeFailure("menuUnqualified", "Menu disclosure requires a menu control")
        }
        action = "AXShowMenu"
    default:
        throw NativeFailure("unsupported", "Semantic action is not qualified")
    }
    guard advertised.contains(action) else {
        throw NativeFailure("unsupported", "Target does not advertise the exact semantic AX action")
    }
    return action
}
