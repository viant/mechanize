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
    // Structural delivery evidence only: never read AXValue or selected text.
    // The adapter must qualify this control's character-count convention. A
    // matching count does not attest password equality or successful sign-in.
    func requireCharacterCount(_ expected: Int, check: () throws -> Void,
                               runtime: PrivatePasswordRecipientRuntime = .system) throws {
        do {
            guard (0...4096).contains(expected) else { throw Self.failure() }
            try validate(check: check, runtime: runtime)
            let (status, value) = runtime.attribute(element, kAXNumberOfCharactersAttribute)
            guard status == .success, let count = value as? NSNumber,
                  CFGetTypeID(count) != CFBooleanGetTypeID(),
                  count.doubleValue.isFinite, count.doubleValue == Double(expected) else { throw Self.failure() }
            try validate(check: check, runtime: runtime)
        } catch { throw Self.failure() }
    }
    // Only the fixed public probe can use this setter. Credential bytes never
    // enter this API. The caller reserves its uncertain input receipt first.
    func writeProbe(inserting: Bool, check: () throws -> Void,
                    runtime: PrivatePasswordRecipientRuntime = .system,
                    write: (AXUIElement, String) -> AXError = { element, value in
                        AXUIElementSetAttributeValue(element, kAXValueAttribute as CFString, value as CFString)
                    }) throws {
        do {
            try requireCharacterCount(inserting ? 0 : 1, check: check, runtime: runtime)
            guard write(element, inserting ? "x" : "") == .success else { throw Self.failure() }
            try requireCharacterCount(inserting ? 1 : 0, check: check, runtime: runtime)
        } catch { throw Self.failure() }
    }

    // Called only inside the private attempt's held executor fence. The OS
    // performs the app's own Paste command; Secure Input is never disabled.
    func pasteUsingMenu(check: () throws -> Void,
                        runtime: PrivatePasswordRecipientRuntime = .system,
                        press: (AXUIElement) -> AXError = { AXUIElementPerformAction($0, kAXPressAction as CFString) }) throws {
        do {
            try requireCharacterCount(0, check: check, runtime: runtime)
            func resolve() throws -> AXUIElement {
                try privatePasteMenuItem(application: self.application, check: check,
                    ownerMatches: { runtime.owner($0).match(pid: self.pid, uid: self.uid, birth: self.birth, bundle: self.bundle) == .matched },
                    attribute: runtime.attribute)
            }
            let item = try resolve()
            try requireCharacterCount(0, check: check, runtime: runtime)
            guard CFEqual(item, try resolve()) else { throw Self.failure() }
            try requireCharacterCount(0, check: check, runtime: runtime)
            guard press(item) == .success else { throw Self.failure() }
            try validate(check: check, runtime: runtime)
        } catch { throw Self.failure() }
    }

}
