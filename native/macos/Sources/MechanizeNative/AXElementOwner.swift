import AppKit
import ApplicationServices
import MechanizeNativeCore

/// AX owner facts describe the actual element process. They grant no delegated
/// routing/authority and do not replace the enrolled root application identity.
struct AXElementOwner {
    let pid:pid_t?
    let uid:uid_t?
    let birth:String?
    let bundle:String?
    let status:Int32
    func metadata(root:pid_t)->[String:Any] {
        var result:[String:Any]=[:]
        var unavailable:[String]=[]
        if let pid {result["nativeOwnerProcessId"]=pid;result["nativeOwnerMatchesRoot"]=pid==root}else{unavailable.append("nativeOwnerProcessId")}
        if let uid {result["nativeOwnerUid"]=uid}else{unavailable.append("nativeOwnerUid")}
        if let birth {result["nativeOwnerStartToken"]=String(birth.prefix(27))}else{unavailable.append("nativeOwnerStartToken")}
        if let bundle {result["nativeOwnerBundleId"]=String(bundle.prefix(255))}else{unavailable.append("nativeOwnerBundleId")}
        result["unavailable"]=unavailable
        return result
    }
}
struct AXElementOwnerRuntime {
    let owner:(AXUIElement)->(AXError,pid_t)
    let uid:(pid_t)->uid_t?
    let birth:(pid_t)->String?
    let bundle:(pid_t)->String?
    static let system=AXElementOwnerRuntime(owner:{element in var pid:pid_t=0;let status=AXUIElementGetPid(element,&pid);return(status,pid)},uid:applicationLoginUID,birth:applicationProcessStartToken,bundle:{NSRunningApplication(processIdentifier:$0)?.bundleIdentifier})
}
func inspectAXElementOwner(_ element:AXUIElement,runtime:AXElementOwnerRuntime = .system)->AXElementOwner {
    let (status,pid)=runtime.owner(element)
    guard status == .success,pid>0 else {return AXElementOwner(pid:nil,uid:nil,birth:nil,bundle:nil,status:status.rawValue)}
    let before=runtime.birth(pid),uid=runtime.uid(pid),bundle=runtime.bundle(pid),after=runtime.birth(pid)
    guard let before,!before.isEmpty,before==after else {return AXElementOwner(pid:pid,uid:nil,birth:nil,bundle:nil,status:status.rawValue)}
    return AXElementOwner(pid:pid,uid:uid,birth:before,bundle:bundle,status:status.rawValue)
}

// Missing metadata is not a mismatching owner. Re-read only the same retained
// element, within the original budget, before any input. Every available fact
// must agree; no foreign owner, changed birth, or invalid AX reference is retried.
func requireAXElementOwner(_ element:AXUIElement,pid:pid_t,uid:uid_t,birth:String,bundle:String,budget:Budget,
                           owner:(AXUIElement)->AXElementOwner={inspectAXElementOwner($0)},
                           pause:(TimeInterval)->Void={Thread.sleep(forTimeInterval:$0)})throws {
    for attempt in 0..<3 {
        try budget.check()
        let facts=owner(element)
        try budget.check()
        if facts.pid.map({$0 != pid}) == true || facts.uid.map({$0 != uid}) == true ||
           facts.birth.map({$0 != birth}) == true || facts.bundle.map({$0 != bundle}) == true {
            throw NativeFailure("foregroundAXOwnerMismatch","Exact AX recipient owner changed; business input was not dispatched")
        }
        if facts.status == AXError.success.rawValue,facts.pid==pid,facts.uid==uid,facts.birth==birth,facts.bundle==bundle {return}
        guard facts.status == AXError.success.rawValue || facts.status == AXError.cannotComplete.rawValue else {
            throw NativeFailure("foregroundAXOwnerUnavailable","Exact AX recipient ownership is unavailable; business input was not dispatched")
        }
        if attempt < 2 {pause(min(0.015,Double(budget.remainingSeconds)))}
    }
    throw NativeFailure("foregroundAXOwnerUnavailable","Exact AX recipient ownership did not settle; business input was not dispatched")
}
