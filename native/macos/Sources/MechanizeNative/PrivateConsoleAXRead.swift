import ApplicationServices
import MechanizeNativeCore

// The private window proof reads only console window metadata. A busy/background
// AppKit main thread can exceed50ms; two bounded observations are safe, while
// missing shape/ownership/permission remains a closed failure with no fallback.
struct PrivateConsoleAXRuntime {
    let owner: (AXUIElement) -> (AXError,pid_t)
    let timeout: (AXUIElement,Float) -> AXError
    let read: (AXUIElement,String) -> (AXError,CFTypeRef?)
    static let system = PrivateConsoleAXRuntime(owner: {element in
        var pid:pid_t=0; let status=AXUIElementGetPid(element,&pid); return(status,pid)
    }, timeout: {AXUIElementSetMessagingTimeout($0,$1)}, read: {element,name in
        var value:CFTypeRef?; let status=AXUIElementCopyAttributeValue(element,name as CFString,&value);return(status,value)
    })
}
func privateConsoleAXValue(_ element:AXUIElement,_ name:String,pid:pid_t,budget:Budget,runtime:PrivateConsoleAXRuntime = .system)throws->CFTypeRef {
    for attempt in 0..<2 {
        try budget.check()
        let before=runtime.owner(element)
        guard before.0 == .success,before.1 == pid else {throw NativeFailure("privateConsoleProcessInvalid","Independent private proof unavailable")}
        try budget.check()
        let timeout=min(0.25,budget.remainingSeconds)
        guard timeout>0 else {throw NativeFailure("deadlineExceeded","Independent private proof unavailable")}
        guard runtime.timeout(element,timeout) == .success else {throw NativeFailure("privateAXIPCUnavailable","Independent private proof unavailable")}
        let (status,raw)=runtime.read(element,name)
        try budget.check()
        let after=runtime.owner(element)
        guard after.0 == .success,after.1 == pid else {throw NativeFailure("privateConsoleProcessInvalid","Independent private proof unavailable")}
        if status == .success,let raw {return raw}
        if [.attributeUnsupported,.noValue,.illegalArgument].contains(status) {throw NativeFailure("privateWindowShapeUnavailable","Independent private proof unavailable")}
        // Retry only a failed read transport. Never repeat unknown input or
        // adopt an absent attribute, different target, or permission fallback.
        if status == .cannotComplete,raw == nil,attempt == 0 {continue}
        throw NativeFailure("privateAXIPCUnavailable","Independent private proof unavailable")
    }
    throw NativeFailure("privateAXIPCUnavailable","Independent private proof unavailable")
}
