import AppKit
import ApplicationServices
import MechanizeNativeCore

// Private adapter dependency, never an ordinary snapshot/value-read route.
// No field value, label, identifier or provider error is returned to a caller.
struct PrivatePasswordRecipientRuntime {
    let attribute: (AXUIElement, String) -> (AXError, CFTypeRef?)
    let owner: (AXUIElement) -> AXElementOwner
    let foreground: () throws -> pid_t
    let sessionQualified: () -> Bool
    static let system = PrivatePasswordRecipientRuntime(attribute: { element, name in
        var value: CFTypeRef?
        let status = AXUIElementCopyAttributeValue(element, name as CFString, &value)
        return (status, value)
    }, owner: { inspectAXElementOwner($0) }, foreground: freshFocusedApplicationPID,
    sessionQualified: {
        let state = windowSession()
        return state["available"] as? Bool == true && state["onConsole"] as? Bool == true &&
            state["loginDone"] as? Bool == true && state["uid"] as? UInt32 == getuid() && AXIsProcessTrusted()
    })
}

// Pin only an already focused secure field in an authenticated app. This proof
// does not authorize paste, release Secure Input, or grant origin/account trust.
// The private host must also hold consent, exposure and physical-input fences.
struct PrivatePasswordRecipient {
    private let application: AXUIElement
    private let element: AXUIElement
    private let pid: pid_t
    private let uid: uid_t
    private let birth: String
    private let bundle: String

    private static func failure() -> NativeFailure {
        NativeFailure("privatePasswordRecipientUnavailable", "Private password recipient could not be verified")
    }
    static func pin(pid: pid_t, uid: uid_t, birth: String, bundle: String,
                    check: () throws -> Void, runtime: PrivatePasswordRecipientRuntime = .system) throws -> PrivatePasswordRecipient {
        do {
            try check()
            guard pid > 0, !birth.isEmpty, !bundle.isEmpty else { throw failure() }
            let app = AXUIElementCreateApplication(pid)
            AXUIElementSetMessagingTimeout(app, 0.1)
            let (status, value) = runtime.attribute(app, kAXFocusedUIElementAttribute)
            guard status == .success, let value, CFGetTypeID(value) == AXUIElementGetTypeID() else { throw failure() }
            let field = value as! AXUIElement
            AXUIElementSetMessagingTimeout(field, 0.1)
            let recipient = PrivatePasswordRecipient(application: app, element: field, pid: pid, uid: uid, birth: birth, bundle: bundle)
            try recipient.validate(check: check, runtime: runtime)
            return recipient
        } catch { throw failure() }
    }
    func validate(check: () throws -> Void, runtime: PrivatePasswordRecipientRuntime = .system) throws {
        do {
            try check()
            guard runtime.sessionQualified(), try runtime.foreground() == pid else { throw Self.failure() }
            for node in [application, element] {
                guard runtime.owner(node).match(pid: pid, uid: uid, birth: birth, bundle: bundle) == .matched else { throw Self.failure() }
            }
            for (name, expected) in [(kAXRoleAttribute, kAXTextFieldRole), (kAXSubroleAttribute, kAXSecureTextFieldSubrole)] {
                let (status, value) = runtime.attribute(element, name)
                guard status == .success, value as? String == expected else { throw Self.failure() }
            }
            for name in [kAXEnabledAttribute, kAXFocusedAttribute] {
                let (status, value) = runtime.attribute(element, name)
                guard status == .success, value as? Bool == true else { throw Self.failure() }
            }
            let (status, focused) = runtime.attribute(application, kAXFocusedUIElementAttribute)
            guard status == .success, let focused, CFGetTypeID(focused) == AXUIElementGetTypeID(), CFEqual(focused, element) else { throw Self.failure() }
            guard try runtime.foreground() == pid,
                  runtime.owner(element).match(pid: pid, uid: uid, birth: birth, bundle: bundle) == .matched else { throw Self.failure() }
            try check()
        } catch { throw Self.failure() }
    }
    // Exact private comparison. Mask glyphs, length-only equality and an absent
    // AXValue cannot attest delivery; unsupported controls remain unqualified.
    func requireValue(_ expected: [UInt8], check: () throws -> Void,
                      runtime: PrivatePasswordRecipientRuntime = .system) throws {
        do {
            guard expected.count <= 4096 else { throw Self.failure() }
            try validate(check: check, runtime: runtime)
            let (status, value) = runtime.attribute(element, kAXValueAttribute)
            guard status == .success, let text = value as? String,
                  text.utf8.count <= 4096, text.utf8.elementsEqual(expected) else { throw Self.failure() }
            try validate(check: check, runtime: runtime)
        } catch { throw Self.failure() }
    }
}
