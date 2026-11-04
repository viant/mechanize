import AppKit
import ApplicationServices
import MechanizeNativeCore

struct FocusedTextControl: Equatable {
    let role: String, identifier: String, name: String
}

// Metadata only. Never read a value or infer editability from an opaque canvas.
// The caller separately proves current owner, exact AX keyboard focus and the
// matching physical window, then repeats these facts before input.
func readFocusedTextControl(_ element: AXUIElement,
                            read: (AXUIElement,String)->(AXError,CFTypeRef?) = ScopedNativeRootRuntime.system.attribute) -> FocusedTextControl? {
    func optional(_ result:(AXError,CFTypeRef?),limit:Int)->String? {
        if result.0 == .success, let text=result.1 as? String, text.utf8.count<=limit { return text }
        if (result.0 == .noValue || result.0 == .attributeUnsupported) && result.1 == nil { return "" }
        return nil
    }
    let role=read(element,kAXRoleAttribute),enabled=read(element,kAXEnabledAttribute)
    guard role.0 == .success, let role=role.1 as? String, [kAXTextFieldRole,kAXTextAreaRole].contains(role),
          enabled.0 == .success, let enabledValue=enabled.1, CFGetTypeID(enabledValue)==CFBooleanGetTypeID(), CFBooleanGetValue(enabledValue as! CFBoolean),
          let subrole=optional(read(element,kAXSubroleAttribute),limit:256),subrole != kAXSecureTextFieldSubrole,
          let identifier=optional(read(element,kAXIdentifierAttribute),limit:256),
          let name=optional(accessibleName(element,read:read),limit:65_536),
          !identifier.isEmpty || !name.isEmpty,
          !WindowTextPlan.protected(identifier+" "+name) else { return nil }
    return FocusedTextControl(role:role,identifier:identifier,name:name)
}
