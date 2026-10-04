import AppKit
import ApplicationServices
import Carbon
import MechanizeNativeCore

func targetedKeyCode(_ key: String) throws -> CGKeyCode {
    let fixed: [String: CGKeyCode] = ["Space":49,"Tab":48,"Return":36,"Escape":53,"ArrowLeft":123,"ArrowRight":124,"ArrowUp":126,"ArrowDown":125,"Home":115,"End":119,"PageUp":116,"PageDown":121,"Backspace":51,"Delete":117]
    if let code = fixed[key] { return code }
    let functionKeys: [String: CGKeyCode] = [
        "F1": CGKeyCode(kVK_F1), "F2": CGKeyCode(kVK_F2), "F3": CGKeyCode(kVK_F3), "F4": CGKeyCode(kVK_F4),
        "F5": CGKeyCode(kVK_F5), "F6": CGKeyCode(kVK_F6), "F7": CGKeyCode(kVK_F7), "F8": CGKeyCode(kVK_F8),
        "F9": CGKeyCode(kVK_F9), "F10": CGKeyCode(kVK_F10), "F11": CGKeyCode(kVK_F11), "F12": CGKeyCode(kVK_F12),
        "F13": CGKeyCode(kVK_F13), "F14": CGKeyCode(kVK_F14), "F15": CGKeyCode(kVK_F15), "F16": CGKeyCode(kVK_F16),
        "F17": CGKeyCode(kVK_F17), "F18": CGKeyCode(kVK_F18), "F19": CGKeyCode(kVK_F19), "F20": CGKeyCode(kVK_F20)
    ]
    if let code = functionKeys[key] { return code }
    guard let source = TISCopyCurrentKeyboardLayoutInputSource()?.takeRetainedValue(), let property = TISGetInputSourceProperty(source, kTISPropertyUnicodeKeyLayoutData) else { throw NativeFailure("keyboardLayoutUnqualified", "Current keyboard layout unavailable") }
    let data = unsafeBitCast(property, to: CFData.self)
    guard let bytes = CFDataGetBytePtr(data) else { throw NativeFailure("keyboardLayoutUnqualified", "Keyboard layout data unavailable") }
    let layout = UnsafeRawPointer(bytes).assumingMemoryBound(to: UCKeyboardLayout.self)
    var matches: [CGKeyCode] = []
    for code in UInt16(0)...UInt16(127) {
        var dead: UInt32 = 0
        var count: Int = 0
        var chars = [UniChar](repeating: 0, count: 4)
        let status = UCKeyTranslate(layout, code, UInt16(kUCKeyActionDown), 0, UInt32(LMGetKbdType()), OptionBits(kUCKeyTranslateNoDeadKeysMask), &dead, 4, &count, &chars)
        if status == noErr, count == 1, String(utf16CodeUnits: chars, count: 1).uppercased() == key { matches.append(code) }
    }
    guard matches.count == 1 else { throw NativeFailure("keyboardLayoutUnqualified", "Letter requires one verified layout mapping") }
    return matches[0]
}
private func keyboardAttributeResult(_ element:AXUIElement,_ name:String)->(AXError,CFTypeRef?) {
    var result:CFTypeRef?
    let code=AXUIElementCopyAttributeValue(element,name as CFString,&result)
    return (code,result)
}
func freshFocusedApplicationPID() throws -> pid_t {
    let system=AXUIElementCreateSystemWide()
    AXUIElementSetMessagingTimeout(system,0.1)
    let value=keyboardAttributeResult(system,kAXFocusedApplicationAttribute)
    guard value.0 == .success, let element=value.1, CFGetTypeID(element)==AXUIElementGetTypeID() else {throw NativeFailure("foregroundUnavailable","System AX focused application unavailable (AX status \(value.0.rawValue))")}
    var pid:pid_t=0
    guard AXUIElementGetPid(element as! AXUIElement,&pid) == .success,pid>0 else {throw NativeFailure("foregroundUnavailable","System AX focused application PID unavailable")}
    return pid
}
func freshTargetedForeground(_ ref:Reference,_ budget:Budget) throws {
    _ = try qualifiedForeground(ForegroundIdentity(pid:ref.pid,uid:getuid(),birth:ref.startToken,bundle:ref.bundleID,active:true),budget)
    try ref.validateProcess()
}
func validateTargetedFocus(_ ref: Reference,_ budget:Budget) throws {
    try ref.validateProcess()
    let session=windowSession()
    guard session["available"] as? Bool == true,session["onConsole"] as? Bool == true,session["loginDone"] as? Bool == true,session["uid"] as? UInt32 == getuid() else {throw NativeFailure("sessionUnqualified","Current-user console/login session unavailable")}
    guard !IsSecureEventInputEnabled() else {throw NativeFailure("secureInput","Secure input inhibits focus qualification")}
    try freshTargetedForeground(ref,budget)
    let enabled=keyboardAttributeResult(ref.element,kAXEnabledAttribute)
    guard enabled.0 == .success, enabled.1 as? Bool == true else {throw NativeFailure("targetDisabledOrUnknown","Target enabled attribute is false or unavailable")}
    let subrole=keyboardAttributeResult(ref.element,kAXSubroleAttribute)
    let known=(subrole.0 == .success && subrole.1 is String) || subrole.0 == .noValue || subrole.0 == .attributeUnsupported
    guard known else {throw NativeFailure("targetClassificationUnknown","Target secure classification unavailable")}
    guard subrole.1 as? String != kAXSecureTextFieldSubrole else {throw NativeFailure("secureInput","Secure target focus cannot qualify keyboard input")}
    let focusedAttribute=keyboardAttributeResult(ref.element,kAXFocusedAttribute)
    guard focusedAttribute.0 == .success,let focused=focusedAttribute.1 as? Bool else {throw NativeFailure("targetFocusUnavailable","Target AXFocused attribute unavailable")}
    guard focused else {throw NativeFailure("focusNotObserved","Exact target AXFocused is not true")}
    let app=AXUIElementCreateApplication(ref.pid)
    AXUIElementSetMessagingTimeout(app,0.1)
    let focusedElement=keyboardAttributeResult(app,kAXFocusedUIElementAttribute)
    guard focusedElement.0 == .success,let element=focusedElement.1,CFGetTypeID(element)==AXUIElementGetTypeID() else {throw NativeFailure("focusedIdentityUnavailable","Application AXFocusedUIElement unavailable (AX status \(focusedElement.0.rawValue))")}
    guard CFEqual(element,ref.element) else {throw NativeFailure("focusedIdentityMismatch","Application focused element differs from exact target reference")}
    try freshTargetedForeground(ref,budget)
    try ref.validateProcess()
}
func settleTargetedFocus(_ ref:Reference,_ budget:Budget) throws {
    try FocusProof.settle(validate:{
        try budget.check()
        guard DispatchTime.now().uptimeNanoseconds - ref.observedAt < 5_000_000_000 else {throw NativeFailure("staleReference","Focus reference expired while observing settlement")}
        try validateTargetedFocus(ref,budget)
        try budget.check()
    },refresh:{},pause:{Thread.sleep(forTimeInterval:0.02)})
}

func targetedKeyboardSessionAvailable() -> Bool {
    let state=windowSession()
    guard state["available"] as? Bool == true,state["onConsole"] as? Bool == true,state["loginDone"] as? Bool == true,state["uid"] as? UInt32 == getuid(),!IsSecureEventInputEnabled(),(try? qualifiedForeground(nil,Budget(milliseconds:1000))) != nil else {return false}
    return true
}
func observedTargetedFocus(_ ref:Reference,_ budget:Budget) throws -> Bool {
    try FocusProof.read {try validateTargetedFocus(ref,budget)}
}
