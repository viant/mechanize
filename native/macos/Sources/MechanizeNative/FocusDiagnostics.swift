import AppKit
import ApplicationServices
import Carbon
import MechanizeNativeCore

/// Failure-path observations only. Never used to authorize or qualify focus.
/// No application names, target contents, attribute strings or values are emitted.
func focusFailureDiagnostics(_ ref:Reference,_ budget:Budget) -> String {
    let started=DispatchTime.now().uptimeNanoseconds
    defer { AXUIElementSetMessagingTimeout(ref.element,0.2) }
    var facts:[String]=[]
    func add(_ key:String,_ value:Any) {facts.append("\(key)=\(value)")}
    func flag(_ value:Bool?)->String {value.map {$0 ? "true":"false"} ?? "unknown"}
    func type(_ value:CFTypeRef?)->Int {value.map {Int(CFGetTypeID($0))} ?? -1}
    func probe(_ element:AXUIElement,_ attribute:String,_ prefix:String)->(AXError,CFTypeRef?) {
        guard (try? budget.check()) != nil,budget.remainingSeconds>0.01 else {add(prefix+"Budget","expired");return(.cannotComplete,nil)}
        let timeout=min(Float(0.35),max(Float(0.01),budget.remainingSeconds/8))
        AXUIElementSetMessagingTimeout(element,timeout)
        var value:CFTypeRef?
        let start=DispatchTime.now().uptimeNanoseconds
        let status=AXUIElementCopyAttributeValue(element,attribute as CFString,&value)
        add(prefix+"Status",status.rawValue);add(prefix+"Type",type(value));add(prefix+"ElapsedMs",(DispatchTime.now().uptimeNanoseconds-start)/1_000_000);add(prefix+"TimeoutMs",Int(timeout*1000))
        return(status,value)
    }
    func elementFacts(_ prefix:String,_ value:CFTypeRef?,compare:Bool) {
        let isAX=value.map {CFGetTypeID($0)==AXUIElementGetTypeID()} ?? false
        add(prefix+"IsAX",isAX)
        guard isAX,let value else {add(prefix+"PIDMatch","unknown");if compare{add(prefix+"Equal","unknown")};return}
        var pid:pid_t=0
        let status=AXUIElementGetPid(value as! AXUIElement,&pid)
        add(prefix+"PIDStatus",status.rawValue);add(prefix+"PIDMatch",status == .success ? flag(pid==ref.pid):"unknown")
        if compare {add(prefix+"Equal",CFEqual(value,ref.element))}
    }
    add("workspacePIDMatch",flag(NSWorkspace.shared.frontmostApplication.map {$0.processIdentifier==ref.pid}))
    let session=windowSession()
    add("sessionAvailable",session["available"] as? Bool ?? false);add("sessionOnConsole",session["onConsole"] as? Bool ?? false);add("sessionLoginDone",session["loginDone"] as? Bool ?? false)
    add("sessionUIDMatch",flag((session["uid"] as? UInt32).map {$0==getuid()}));add("secureInput",IsSecureEventInputEnabled())
    let system=AXUIElementCreateSystemWide()
    let sysApp=probe(system,kAXFocusedApplicationAttribute,"sysApp");elementFacts("sysApp",sysApp.1,compare:false)
    let sysFocus=probe(system,kAXFocusedUIElementAttribute,"sysFocus");elementFacts("sysFocus",sysFocus.1,compare:true)
    let enabled=probe(ref.element,kAXEnabledAttribute,"targetEnabled");add("targetEnabledBool",flag(enabled.1 as? Bool))
    let focused=probe(ref.element,kAXFocusedAttribute,"targetFocused");add("targetFocusedBool",flag(focused.1 as? Bool))
    let subrole=probe(ref.element,kAXSubroleAttribute,"targetSubrole")
    add("targetSubroleKnown",(subrole.0 == .success && subrole.1 is String) || subrole.0 == .noValue || subrole.0 == .attributeUnsupported)
    add("targetIsSecure",flag((subrole.1 as? String).map {$0==kAXSecureTextFieldSubrole}))
    let app=AXUIElementCreateApplication(ref.pid)
    let appFocus=probe(app,kAXFocusedUIElementAttribute,"appFocus");elementFacts("appFocus",appFocus.1,compare:true)
    add("totalElapsedMs",(DispatchTime.now().uptimeNanoseconds-started)/1_000_000)
    let message="diagnosticOnly{"+facts.joined(separator:";")+"}"
    return String(message.prefix(3500))
}
