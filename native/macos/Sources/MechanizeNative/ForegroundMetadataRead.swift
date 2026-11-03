import ApplicationServices
import MechanizeNativeCore

// Exact recipient proof reads are not a broad AX-tree traversal. Allow one
// bounded IPC response during UI transitions instead of inheriting the short
// snapshot timeout. This neither retries input nor accepts unavailable metadata.
func readForegroundMetadata(_ element:AXUIElement,attribute:String,budget:Budget,
                            read:(AXUIElement,String)->(AXError,CFTypeRef?),
                            setTimeout:(AXUIElement,Float)->AXError={AXUIElementSetMessagingTimeout($0,$1)})throws->(AXError,CFTypeRef?) {
    try budget.check()
    let timeout=min(Float(0.25),budget.remainingSeconds)
    guard timeout.isFinite,timeout>0 else {throw NativeFailure("deadlineExceeded","Native request deadline expired")}
    guard setTimeout(element,timeout) == .success else {
        throw NativeFailure("foregroundMetadataTimeoutUnavailable","Bounded foreground metadata timeout unavailable; business input was not dispatched")
    }
    try budget.check()
    let result=read(element,attribute)
    try budget.check()
    return result
}
