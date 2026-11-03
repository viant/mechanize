import AppKit
import ApplicationServices
import MechanizeNativeCore

enum AXOwnerMatch:String {case matched,unavailable,pidMismatch,uidMismatch,birthMismatch,bundleMismatch}

/// AX owner facts describe the actual element process. They grant no delegated
/// routing/authority and do not replace the enrolled root application identity.
struct AXElementOwner {
    let pid:pid_t?
    let uid:uid_t?
    let birth:String?
    let bundle:String?
    let status:Int32
    func match(pid expectedPID:pid_t,uid expectedUID:uid_t,birth expectedBirth:String,bundle expectedBundle:String)->AXOwnerMatch {
        if let pid,pid != expectedPID{return .pidMismatch}
        if let uid,uid != expectedUID{return .uidMismatch}
        if let birth,birth != expectedBirth{return .birthMismatch}
        if let bundle,bundle != expectedBundle{return .bundleMismatch}
        guard status==AXError.success.rawValue,pid==expectedPID,uid==expectedUID,birth==expectedBirth,bundle==expectedBundle else{return .unavailable}
        return .matched
    }
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
        let match=facts.match(pid:pid,uid:uid,birth:birth,bundle:bundle)
        if match != .matched && match != .unavailable {
            throw NativeFailure("foregroundAXOwnerMismatch","Exact AX recipient owner changed; business input was not dispatched")
        }
        if match == .matched {return}
        guard facts.status == AXError.success.rawValue || facts.status == AXError.cannotComplete.rawValue else {
            throw NativeFailure("foregroundAXOwnerUnavailable","Exact AX recipient ownership is unavailable; business input was not dispatched")
        }
        if attempt < 2 {pause(min(0.015,Double(budget.remainingSeconds)))}
    }
    throw NativeFailure("foregroundAXOwnerUnavailable","Exact AX recipient ownership did not settle; business input was not dispatched")
}
