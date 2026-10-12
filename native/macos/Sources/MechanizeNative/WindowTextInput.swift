import AppKit
import ApplicationServices
import CryptoKit
import MechanizeNativeCore

struct WindowTextOutcome {
    let dispatchState: String
    let failure: NativeFailure?
    let result: [String: Any]
}

func qualifiedOutlookRecipient(role: String, identifier: String, bundle: String,
                               enabledStatus: AXError, enabled: CFTypeRef?,
                               focusedStatus: AXError, focused: CFTypeRef?,
                               editableStatus: AXError, editable: Bool) -> Bool {
    bundle == "com.microsoft.Outlook" && role == kAXTextFieldRole && identifier == "toTextField" &&
    (enabledStatus == .noValue || enabledStatus == .attributeUnsupported) && enabled == nil &&
    focusedStatus == .success && focused.map { CFGetTypeID($0) == CFBooleanGetTypeID() && CFBooleanGetValue(($0 as! CFBoolean)) } == true &&
    editableStatus == .success && editable
}

private func qualifiedTextFocus(pid: pid_t, birth: String, bundle: String, plan: WindowTextPlan,
                                budget: Budget, original: AXUIElement? = nil) throws -> AXUIElement {
    try budget.check()
    let app = AXUIElementCreateApplication(pid)
    AXUIElementSetMessagingTimeout(app, 0.1)
    var raw: CFTypeRef?
    guard AXUIElementCopyAttributeValue(app, kAXFocusedUIElementAttribute as CFString, &raw) == .success,
          let raw, CFGetTypeID(raw) == AXUIElementGetTypeID() else { throw NativeFailure("textFocusUnavailable", "Focused control is unavailable") }
    let focus = raw as! AXUIElement
    AXUIElementSetMessagingTimeout(focus, 0.1)
    let owner = inspectAXElementOwner(focus)
    guard owner.pid == pid, owner.uid == getuid(), owner.birth == birth, owner.bundle == bundle,
          original == nil || CFEqual(original!, focus) else { throw NativeFailure("textFocusChanged", "Exact focused control changed") }
    func text(_ attribute: String, optional: Bool = false) throws -> String {
        var value: CFTypeRef?
        let status: AXError
        if attribute == kAXTitleAttribute { (status, value) = accessibleName(focus) }
        else { status = AXUIElementCopyAttributeValue(focus, attribute as CFString, &value) }
        if status == .success, let value = value as? String { return value }
        if optional && (status == .noValue || status == .attributeUnsupported) && value == nil { return "" }
        throw NativeFailure("textClassificationUnavailable", "Focused control classification unavailable")
    }
    let role = try text(kAXRoleAttribute), identifier = try text(kAXIdentifierAttribute, optional: true)
    let name = try text(kAXTitleAttribute, optional: true), subrole = try text(kAXSubroleAttribute, optional: true)
    guard subrole != kAXSecureTextFieldSubrole, plan.permits(role: role, identifier: identifier, name: name, bundle: bundle) else {
        throw NativeFailure("textFocusMismatch", "Focused control does not match the declared text target")
    }
    var enabled: CFTypeRef?
    let status = AXUIElementCopyAttributeValue(focus, kAXEnabledAttribute as CFString, &enabled)
    let knownCanvas = role == kAXSplitGroupRole && bundle == "com.microsoft.Word" && identifier == "Document Pane"
    var focused: CFTypeRef?
    let focusedStatus = AXUIElementCopyAttributeValue(focus, kAXFocusedAttribute as CFString, &focused)
    var editable: DarwinBoolean = false
    let editableStatus = AXUIElementIsAttributeSettable(focus, kAXValueAttribute as CFString, &editable)
    let recipient = qualifiedOutlookRecipient(role: role, identifier: identifier, bundle: bundle,
        enabledStatus: status, enabled: enabled, focusedStatus: focusedStatus, focused: focused,
        editableStatus: editableStatus, editable: editable.boolValue)
    guard (status == .success && enabled as? Bool == true) ||
            (knownCanvas && (status == .noValue || status == .attributeUnsupported) && enabled == nil) || recipient else {
        throw NativeFailure("textTargetDisabled", "Text target enabled state is unqualified")
    }
    try budget.check()
    return focus
}

extension Helper {
    func typeWindowText(_ params: [String: Any], budget: Budget, present: () -> Void = {}, reserve: () throws -> Void) throws -> WindowTextOutcome {
        guard Set(params.keys) == Set(["expectedApp", "pid", "processStartToken", "windowId", "text", "focusRole", "focusIdentifier", "focusName"]),
              let bundle = params["expectedApp"] as? String, concreteApplicationBundle(bundle),
              let birth = params["processStartToken"] as? String, validApplicationProcessStartToken(birth),
              let text = params["text"] as? String, let role = params["focusRole"] as? String,
              let identifier = params["focusIdentifier"] as? String, let name = params["focusName"] as? String else {
            throw NativeFailure("invalidText", "Closed exact window text request required")
        }
        let rawPID = try RecordingConsentLease.integer(params["pid"], maximum: UInt64(Int32.max))
        let rawWindow = try RecordingConsentLease.integer(params["windowId"], maximum: UInt64(UInt32.max))
        guard rawPID > 0, rawWindow > 0 else { throw NativeFailure("invalidText", "Positive process and window required") }
        let pid = Int32(rawPID), windowID = UInt32(rawWindow)
        let plan = try WindowTextPlan(text: text, role: role, identifier: identifier, name: name)
        func authority() throws {
            try qualifyWindowSessionKey(pid: pid, uid: getuid(), birth: birth, bundle: bundle, windowID: windowID, check: { try budget.check() })
            let modifiers: CGEventFlags = [.maskCommand, .maskControl, .maskAlternate, .maskShift]
            guard CGEventSource.flagsState(.hidSystemState).intersection(modifiers).isEmpty else {
                throw NativeFailure("textModifiersHeld", "Physical modifiers must be released before literal text")
            }
            guard sessionTextEnabled, watchdog?.live() == true, let held = lease, let persisted = fenceLease(),
                  persisted["id"] as? String == held.0, persisted["generation"] as? Int == held.1,
                  let scope = persisted["scope"] as? [String: Any], fenceScopeAllows(scope, bundle) else {
                throw NativeFailure("staleLease", "Window text authority changed")
            }
        }
        try authority()
        let focus = try qualifiedTextFocus(pid: pid, birth: birth, bundle: bundle, plan: plan, budget: budget)
        let result: [String: Any] = ["pid": pid, "startToken": birth, "bundleID": bundle, "windowId": windowID,
            "identity": "window:\(windowID)", "textHash": SHA256.hash(data: Data(text.utf8)).map { String(format: "%02x", $0) }.joined(),
            "focusRole": role, "focusIdentifier": identifier, "focusName": name, "businessSuccess": false]
        try reserve()
        let outcome = WindowTextSequence.perform(plan.chunks, preflight: {
            try authority()
            _ = try qualifiedTextFocus(pid: pid, birth: birth, bundle: bundle, plan: plan, budget: budget, original: focus)
        }, send: { chunk, willPost in
                guard let down = CGEvent(keyboardEventSource: nil, virtualKey: 0, keyDown: true),
                      let up = CGEvent(keyboardEventSource: nil, virtualKey: 0, keyDown: false) else {
                    throw NativeFailure("eventUnavailable", "Unicode event unavailable")
                }
                chunk.withUnsafeBufferPointer { buffer in
                    down.keyboardSetUnicodeString(stringLength: buffer.count, unicodeString: buffer.baseAddress!)
                    up.keyboardSetUnicodeString(stringLength: buffer.count, unicodeString: buffer.baseAddress!)
                }
                down.flags = []; up.flags = []
                down.setIntegerValueField(.eventSourceUserData, value: 0x4d454348)
                up.setIntegerValueField(.eventSourceUserData, value: 0x4d454348)
                try KeyboardPosting.press(inputs: inputs, token: "key:0", delivery: .session, preflight: {
                    try authority()
                    _ = try qualifiedTextFocus(pid: pid, birth: birth, bundle: bundle, plan: plan, budget: budget, original: focus)
                }, down: { _ in willPost(); present(); down.post(tap: .cgSessionEventTap); return true }, up: { _ in
                    guard sessionKeyReleaseAllowed() else { return false }
                    up.post(tap: .cgSessionEventTap); return true
                })
        })
        return WindowTextOutcome(dispatchState: outcome.dispatchState, failure: outcome.failure, result: result)
    }
}
