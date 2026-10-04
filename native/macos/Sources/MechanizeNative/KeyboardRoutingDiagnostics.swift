import AppKit
import ApplicationServices
import MechanizeNativeCore

struct RoutingDiagnosticRuntime {
    let read:(AXUIElement,String)->(AXError,CFTypeRef?)
    let owner:(AXUIElement)->(AXError,pid_t)
    static let system=RoutingDiagnosticRuntime(read:{element,name in var value:CFTypeRef?;let status=AXUIElementCopyAttributeValue(element,name as CFString,&value);return(status,value)},owner:{element in var pid:pid_t=0;let status=AXUIElementGetPid(element,&pid);return(status,pid)})
}
/// Only closed scalar facts; no title/name/value/path reads occur.
func keyboardWindowDiagnostics(_ target:AXUIElement,rootPID:pid_t,budget:Budget,runtime:RoutingDiagnosticRuntime = .system)->[String:Any] {
    var result:[String:Any]=["diagnosticOnly":true,"qualificationChanged":false]
    let app=AXUIElementCreateApplication(rootPID)
    func read(_ element:AXUIElement,_ name:String,_ prefix:String)->CFTypeRef? {
        guard (try? budget.check()) != nil else {result[prefix+"Unavailable"]=true;return nil}
        AXUIElementSetMessagingTimeout(element,min(0.015,max(0.001,budget.remainingSeconds/30)))
        let (status,value)=runtime.read(element,name)
        result[prefix+"Status"]=status.rawValue;result[prefix+"Type"]=value.map {Int(CFGetTypeID($0))} ?? -1
        return status == .success ? value:nil
    }
    func element(_ value:CFTypeRef?)->AXUIElement? {guard let value,CFGetTypeID(value)==AXUIElementGetTypeID() else {return nil};return (value as! AXUIElement)}
    var refs:[String:AXUIElement]=[:]
    for (key,base,attribute) in [("focusedWindow",app,kAXFocusedWindowAttribute),("mainWindow",app,kAXMainWindowAttribute),("targetWindow",target,kAXWindowAttribute),("targetTop",target,kAXTopLevelUIElementAttribute)] {
        if let value=element(read(base,attribute,key)){refs[key]=value}
    }
    for key in ["focusedWindow","mainWindow","targetWindow","targetTop"] {
        guard let item=refs[key] else {continue}
        let (status,pid)=runtime.owner(item);result[key+"OwnerStatus"]=status.rawValue;result[key+"RootPIDMatch"]=status == .success && pid==rootPID
        let role=read(item,kAXRoleAttribute,key+"Role") as? String
        result[key+"RoleBucket"] = role==kAXSheetRole ? "sheet":role==kAXWindowRole ? "window":role==kAXDrawerRole ? "drawer":"other"
        for (name,attribute) in [("Focused",kAXFocusedAttribute),("Main",kAXMainAttribute),("Modal",kAXModalAttribute)] {if let flag=read(item,attribute,key+name) as? Bool{result[key+name]=flag}}
    }
    for (key,left,right) in [("focusedEqualsTargetWindow","focusedWindow","targetWindow"),("mainEqualsTargetWindow","mainWindow","targetWindow"),("focusedEqualsTargetTop","focusedWindow","targetTop"),("targetWindowEqualsTop","targetWindow","targetTop")] {if let a=refs[left],let b=refs[right]{result[key]=CFEqual(a,b)}}
    var current=target,seen:[AXUIElement]=[],matched=false
    for depth in 0..<8 {
        if seen.contains(where:{CFEqual($0,current)}){result["parentCycle"]=true;break};seen.append(current)
        let prefix="ancestor\(depth)"
        let role=read(current,kAXRoleAttribute,prefix+"Role") as? String
        result[prefix+"RoleBucket"] = role==kAXSheetRole ? "sheet":role==kAXWindowRole ? "window":role==kAXDrawerRole ? "drawer":role==nil ? "unavailable":"other"
        let (ownerStatus,ownerPID)=runtime.owner(current)
        result[prefix+"OwnerStatus"]=ownerStatus.rawValue
        if ownerStatus == .success {result[prefix+"RootPIDMatch"]=ownerPID==rootPID}
        if let focused=refs["focusedWindow"] {result[prefix+"EqualsFocusedWindow"]=CFEqual(current,focused)}
        if let main=refs["mainWindow"] {result[prefix+"EqualsMainWindow"]=CFEqual(current,main)}
        if let top=refs["targetTop"],CFEqual(current,top){result["topParentDepth"]=depth;matched=true;break}
        guard let parent=element(read(current,kAXParentAttribute,"parent\(depth)")) else {break};current=parent
    }
    result["topFoundInParentChain"]=matched
    return result
}
/// Builds a representative chord exactly like dispatchInput; NEVER posts it.
func constructedChordDiagnostics(keyCode:CGKeyCode,key:String,modifiers:[String])->[String:Any] {
    guard let down=CGEvent(keyboardEventSource:nil,virtualKey:keyCode,keyDown:true),let up=CGEvent(keyboardEventSource:nil,virtualKey:keyCode,keyDown:false) else {return ["eventConstructed":false]}
    var flags:CGEventFlags=[]
    for modifier in modifiers {switch modifier{case "command":flags.insert(.maskCommand);case "shift":flags.insert(.maskShift);case "option":flags.insert(.maskAlternate);case "control":flags.insert(.maskControl);default:return["eventConstructed":false,"modifierInvalid":true]}}
    down.flags=flags;up.flags=[]
    var result:[String:Any]=["eventConstructed":true,"eventPosted":false,"keyCode":down.getIntegerValueField(.keyboardEventKeycode),"cgCommand":down.flags.contains(.maskCommand),"cgShift":down.flags.contains(.maskShift),"cgOption":down.flags.contains(.maskAlternate),"cgControl":down.flags.contains(.maskControl),"upFlagsClear":up.flags.isEmpty,"sourceState":down.getIntegerValueField(.eventSourceStateID),"keyboardType":down.getIntegerValueField(.keyboardEventKeyboardType),"repeat":down.getIntegerValueField(.keyboardEventAutorepeat)]
    if let cocoa=NSEvent(cgEvent:down){result["nsEventAvailable"]=true;result["nsCommand"]=cocoa.modifierFlags.contains(.command);result["nsShift"]=cocoa.modifierFlags.contains(.shift);result["nsKeyCodeMatch"]=cocoa.keyCode==keyCode;result["nsWindowNumber"]=cocoa.windowNumber;result["nsRepeat"]=cocoa.isARepeat;result["charactersIgnoringModifiersMatch"]=cocoa.charactersIgnoringModifiers?.uppercased()==key.uppercased()}else{result["nsEventAvailable"]=false}
    return result
}
func logKeyboardRoutingDiagnostic(requestID:String,ref:Reference,budget:Budget) {
    // Temporary development diagnostics, one entry per explicitly focused read.
    // Construction/serialization/write failure cannot change the read result.
    defer {AXUIElementSetMessagingTimeout(ref.element,0.2)}
    guard budget.remainingSeconds>0.01,let diagnosticBudget=try? Budget(milliseconds:min(300,max(1,Int(budget.remainingSeconds*1000)))) else {return}
    var facts=keyboardWindowDiagnostics(ref.element,rootPID:ref.pid,budget:diagnosticBudget)
    if let code=try? targetedKeyCode("G"){facts["constructedChord"]=constructedChordDiagnostics(keyCode:code,key:"G",modifiers:["command","shift"])}
    let entry:[String:Any]=["kind":"mechanizeKeyboardRoutingDiagnostic","requestId":String(requestID.prefix(128)),"rootPID":ref.pid,"rootBirth":ref.startToken,"facts":facts]
    guard let data=try? JSONSerialization.data(withJSONObject:entry,options:[.sortedKeys]),data.count<=12000 else {return}
    try? FileHandle.standardError.write(contentsOf:data+Data([10]))
}
