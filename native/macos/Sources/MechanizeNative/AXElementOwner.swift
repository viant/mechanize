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
