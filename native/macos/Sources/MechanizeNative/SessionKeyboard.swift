import ApplicationServices
import MechanizeNativeCore

/// OS-session delivery is not atomically PID/window addressed: human focus can
/// change after verification. Explicit enrollment/intent and independent outcome
/// checks remain required. This never replaces a failed process-stream attempt.
func validateSessionKeyboardWindow(_ ref:Reference,_ budget:Budget)throws {
 let app=AXUIElementCreateApplication(ref.pid)
 AXUIElementSetMessagingTimeout(app,min(0.1,budget.remainingSeconds))
 var window:CFTypeRef?
 guard AXUIElementCopyAttributeValue(app,kAXFocusedWindowAttribute as CFString,&window) == .success,let window,CFGetTypeID(window)==AXUIElementGetTypeID() else {throw NativeFailure("sessionWindowUnqualified","Application focused container unavailable")}
 let focused=window as! AXUIElement
 try SessionWindowProof.validate(target:ref.element,focusedWindow:focused,rootPID:ref.pid,owner:{element in
  var pid:pid_t=0;guard AXUIElementGetPid(element,&pid) == .success else {throw NativeFailure("sessionWindowUnqualified","Container owner PID unavailable")};return pid
 },role:{element in
  AXUIElementSetMessagingTimeout(element,min(0.1,budget.remainingSeconds));var value:CFTypeRef?
  guard AXUIElementCopyAttributeValue(element,kAXRoleAttribute as CFString,&value) == .success,let role=value as? String else {throw NativeFailure("sessionWindowUnqualified","Container role unavailable")};return role
 },parent:{element in
  AXUIElementSetMessagingTimeout(element,min(0.1,budget.remainingSeconds));var value:CFTypeRef?
  guard AXUIElementCopyAttributeValue(element,kAXParentAttribute as CFString,&value) == .success,let value,CFGetTypeID(value)==AXUIElementGetTypeID() else {return nil};return (value as! AXUIElement)
 },equal:{CFEqual($0,$1)},recheck:{
  try budget.check();var current:CFTypeRef?
  guard AXUIElementCopyAttributeValue(app,kAXFocusedWindowAttribute as CFString,&current) == .success,let current,CFGetTypeID(current)==AXUIElementGetTypeID() else {throw NativeFailure("sessionWindowUnqualified","Focused container disappeared during proof")}
  return current as! AXUIElement
 },check:{try budget.check();try ref.validateProcess();guard DispatchTime.now().uptimeNanoseconds-ref.observedAt<5_000_000_000 else {throw NativeFailure("staleReference","Session keyboard target reference expired")}})
 try validateTargetedFocus(ref,budget)
 try budget.check()
}
func sessionKeyReleaseAllowed()->Bool {
 let state=windowSession()
 return state["available"] as? Bool == true && state["onConsole"] as? Bool == true && state["loginDone"] as? Bool == true && state["uid"] as? UInt32 == getuid() && CGPreflightPostEventAccess()
}
