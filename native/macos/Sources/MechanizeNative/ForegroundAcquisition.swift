import AppKit
import Carbon
import ApplicationServices
import MechanizeNativeCore

// Preparation evidence is distinct from the requested action's dispatch receipt.
// It never claims that a key, click, text setter or semantic action occurred.
struct ForegroundAcquisitionReceipt {
 var activationRequested=false,windowRaiseRequested=false,confirmed=false
 var metadata:[String:Any]{["version":1,"activationRequested":activationRequested,"windowRaiseRequested":windowRaiseRequested,"confirmed":confirmed]}
}
struct ForegroundAcquisitionRuntime {
 let validate:()throws->Void
 let ready:()throws->Bool
 let activate:()throws->Bool
 let needsRaise:()throws->Bool
 let raise:()throws->Bool
 let pause:(TimeInterval)->Void
}
func acquireNativeForeground(_ budget:Budget,runtime:ForegroundAcquisitionRuntime,reserve:()throws->Void,publish:(ForegroundAcquisitionReceipt)->Void)throws {
 var receipt=ForegroundAcquisitionReceipt();publish(receipt)
 func validate()throws{try budget.check();try runtime.validate();try budget.check()}
 func ready()throws->Bool{
  do{return try runtime.ready()}catch let f as NativeFailure{
   if ["foregroundChanged","foregroundNotActive","foregroundUnavailable","foregroundRefreshUnavailable"].contains(f.code){return false};throw f
  }
 }
 try validate()
 if try ready(){try validate();receipt.confirmed=true;publish(receipt);return}
 try validate();try reserve();try validate()
 receipt.activationRequested=true;publish(receipt)
 guard try runtime.activate() else{throw NativeFailure("foregroundAcquisitionUnavailable","Exact application activation was requested without confirmation; business input was not dispatched")}
 try validate()
 if try runtime.needsRaise(){try validate();receipt.windowRaiseRequested=true;publish(receipt);guard try runtime.raise() else{throw NativeFailure("foregroundWindowUnavailable","Exact window raise was requested without confirmation; business input was not dispatched")}}
 for _ in 0..<80 {
  try validate()
  if try ready(){try validate();receipt.confirmed=true;publish(receipt);return}
  try budget.check();runtime.pause(min(0.015,Double(budget.remainingSeconds)))
 }
 throw NativeFailure("foregroundAcquisitionUnavailable","Exact foreground/window did not settle within the original action deadline; business input was not dispatched")
}

// Direct AX setters/actions address the retained AX object, not a screen point.
// Pin its exact owned AX window; equal CG rectangles cannot identify that object.
// The runtime seam contains only role/window/owner metadata, never AX values.
struct AXSemanticForegroundRecipient {
 let element:AXUIElement,application:AXUIElement
 let window:AXUIElement?
 let pid:pid_t,uid:uid_t,birth:String,bundle:String
 let menuRoot:Bool
 private func read(_ element:AXUIElement,_ name:String,_ budget:Budget,_ runtime:ScopedNativeRootRuntime)throws->(AXError,CFTypeRef?){
  try budget.check();AXUIElementSetMessagingTimeout(element,min(0.05,budget.remainingSeconds))
  let result=runtime.attribute(element,name);try budget.check();return result
 }
 private func owned(_ element:AXUIElement,_ budget:Budget,_ runtime:ScopedNativeRootRuntime)throws {
  try budget.check();let owner=runtime.owner(element);try budget.check()
  guard owner.status==AXError.success.rawValue,owner.pid==pid,owner.uid==uid,owner.birth==birth,owner.bundle==bundle else{throw NativeFailure("foregroundAXOwnerMismatch","Exact AX recipient owner changed; business input was not dispatched")}
 }
 private func currentWindow(_ budget:Budget,_ runtime:ScopedNativeRootRuntime)throws->AXUIElement? {
  try owned(element,budget,runtime)
  let role=try read(element,kAXRoleAttribute,budget,runtime)
  guard role.0 == .success,role.1 is String else{throw NativeFailure("foregroundAXWindowUnavailable","Exact target role unavailable")}
  if role.1 as? String==kAXWindowRole{return element}
  let raw=try read(element,kAXWindowAttribute,budget,runtime)
  if raw.0 == .success,let value=raw.1,CFGetTypeID(value)==AXUIElementGetTypeID(){return value as! AXUIElement}
  // Only the already-owned menu-bar scope may legitimately have no AX window.
  if menuRoot,(raw.0 == .noValue || raw.0 == .attributeUnsupported || raw.0 == .success),raw.1==nil{return nil}
  throw NativeFailure("foregroundAXWindowUnavailable","Exact target AX window unavailable; business input was not dispatched")
 }
 static func bind(element:AXUIElement,application:AXUIElement,pid:pid_t,uid:uid_t,birth:String,bundle:String,menuRoot:Bool,budget:Budget,runtime:ScopedNativeRootRuntime = .system)throws->AXSemanticForegroundRecipient {
  let candidate=AXSemanticForegroundRecipient(element:element,application:application,window:nil,pid:pid,uid:uid,birth:birth,bundle:bundle,menuRoot:menuRoot)
  let window=try candidate.currentWindow(budget,runtime)
  let bound=AXSemanticForegroundRecipient(element:element,application:application,window:window,pid:pid,uid:uid,birth:birth,bundle:bundle,menuRoot:menuRoot)
  try bound.validate(budget,runtime:runtime);return bound
 }
 func validate(_ budget:Budget,runtime:ScopedNativeRootRuntime = .system)throws {
  try owned(application,budget,runtime)
  let current=try currentWindow(budget,runtime)
  if let window {
   guard let current,CFEqual(current,window) else{throw NativeFailure("foregroundAXWindowChanged","Exact target AX window changed; business input was not dispatched")}
   try owned(window,budget,runtime)
   let role=try read(window,kAXRoleAttribute,budget,runtime)
   guard role.0 == .success,role.1 as? String==kAXWindowRole else{throw NativeFailure("foregroundAXWindowUnavailable","Exact recipient is not an AX window")}
  } else if current != nil || !menuRoot {throw NativeFailure("foregroundAXWindowChanged","Windowless menu recipient changed")}
 }
 func focused(_ budget:Budget,runtime:ScopedNativeRootRuntime = .system)throws->Bool {
  try validate(budget,runtime:runtime)
  guard let window else{return true}
  func readFocused()throws->AXUIElement {
   let raw=try read(application,kAXFocusedWindowAttribute,budget,runtime)
   guard raw.0 == .success,let value=raw.1,CFGetTypeID(value)==AXUIElementGetTypeID() else{throw NativeFailure("foregroundAXFocusUnavailable","Application focused AX window unavailable; business input was not dispatched")}
   let focused=value as! AXUIElement
   try owned(focused,budget,runtime)
   let role=try read(focused,kAXRoleAttribute,budget,runtime)
   guard role.0 == .success,role.1 as? String==kAXWindowRole else{throw NativeFailure("foregroundAXFocusUnavailable","Application focused object is not an AX window")}
   return focused
  }
  let before=try readFocused();try validate(budget,runtime:runtime)
  let after=try readFocused()
  guard CFEqual(before,after) else{throw NativeFailure("foregroundAXFocusChanged","Application focused AX window changed during recipient proof; business input was not dispatched")}
  return CFEqual(window,after)
 }
 // Named reference keyboard delivery has an exact AX recipient, unlike a
 // window-ID shortcut or pointer action. AppKit search popups need not have a
 // supported pixel layer; require their owned AX window and already-focused
 // element instead. This proof never focuses a field or reads its contents.
 func keyboardFocused(_ budget:Budget,runtime:ScopedNativeRootRuntime = .system)throws->Bool {
  guard window != nil else{throw NativeFailure("foregroundAXWindowUnavailable","Keyboard recipient requires an exact owned AX window")}
  guard try focused(budget,runtime:runtime) else{return false}
  func readFocusedElement()throws->AXUIElement {
   let raw=try read(application,kAXFocusedUIElementAttribute,budget,runtime)
   guard raw.0 == .success,let value=raw.1,CFGetTypeID(value)==AXUIElementGetTypeID() else{throw NativeFailure("foregroundAXFocusUnavailable","Application focused AX element unavailable; business input was not dispatched")}
   let current=value as! AXUIElement;try owned(current,budget,runtime);return current
  }
  func targetFocused()throws->Bool {
   let raw=try read(element,kAXFocusedAttribute,budget,runtime)
   guard raw.0 == .success,let value=raw.1 as? Bool else{throw NativeFailure("foregroundAXFocusUnavailable","Exact target focus attribute unavailable; business input was not dispatched")}
   return value
  }
  let before=try readFocusedElement(),beforeFocused=try targetFocused()
  try validate(budget,runtime:runtime)
  let after=try readFocusedElement(),afterFocused=try targetFocused()
  guard CFEqual(before,after),beforeFocused==afterFocused else{throw NativeFailure("foregroundAXElementFocusChanged","Exact keyboard element focus changed during recipient proof; business input was not dispatched")}
  guard beforeFocused,CFEqual(after,element) else{return false}
  return try focused(budget,runtime:runtime)
 }
}

struct NativeForegroundTarget {
 let pid:pid_t,birth:String,bundle:String
 let windowID:UInt32?
 let window:AXUIElement?
 let reference:Reference?
 var pointerDelivery=false
 var semanticRecipient:AXSemanticForegroundRecipient?=nil
 var keyboardRecipient=false
 private static func bounds(_ window:AXUIElement,pid:pid_t,budget:Budget)throws->CGRect {
  try budget.check();AXUIElementSetMessagingTimeout(window,min(0.05,budget.remainingSeconds))
  guard let rect=AutomationPointer.windowBounds(element:window,pid:pid) else{throw NativeFailure("foregroundGeometryUnavailable","Exact owned window geometry unavailable")};try budget.check();return rect
 }
 private static func ownedRows(pid:pid_t,birth:String,bundle:String,budget:Budget)throws->[SessionKeyWindow]{
  try budget.check();guard applicationLoginUID(pid)==getuid(),applicationProcessStartToken(pid)==birth,NSRunningApplication(processIdentifier:pid)?.bundleIdentifier==bundle,
   let rows=WindowSessionKeyRuntime.system.windows(),rows.count<=1000 else{throw NativeFailure("staleReference","Exact process/window metadata unavailable")};try budget.check();return rows
 }
 static func from(_ ref:Reference,budget:Budget,semanticOnly:Bool=false,keyboardOnly:Bool=false)throws->NativeForegroundTarget{
  try ref.validateProcess();try budget.check()
  if semanticOnly || keyboardOnly {
   try ref.validateInputScope(budget)
   let proof=try AXSemanticForegroundRecipient.bind(element:ref.element,application:AXUIElementCreateApplication(ref.pid),pid:ref.pid,uid:getuid(),birth:ref.startToken,bundle:ref.bundleID,menuRoot:semanticOnly && ref.scopedRoot?.scope == .menuBar,budget:budget)
   return NativeForegroundTarget(pid:ref.pid,birth:ref.startToken,bundle:ref.bundleID,windowID:nil,window:proof.window,reference:ref,semanticRecipient:proof,keyboardRecipient:keyboardOnly)
  }
  AXUIElementSetMessagingTimeout(ref.element,min(0.05,budget.remainingSeconds))
  var raw:CFTypeRef?,role:CFTypeRef?
  _=AXUIElementCopyAttributeValue(ref.element,kAXRoleAttribute as CFString,&role)
  let window:AXUIElement?
  if role as? String==kAXWindowRole{window=ref.element}
  else if AXUIElementCopyAttributeValue(ref.element,kAXWindowAttribute as CFString,&raw) == .success,let raw,CFGetTypeID(raw)==AXUIElementGetTypeID(){window=(raw as! AXUIElement)}
  else if ref.scopedRoot?.scope == .menuBar{window=nil}
  else{throw NativeFailure("foregroundWindowUnavailable","Target's exact owned AX window is unavailable")}
  var id:UInt32?
  if let window {
   let rect=try bounds(window,pid:ref.pid,budget:budget),rows=try ownedRows(pid:ref.pid,birth:ref.startToken,bundle:ref.bundleID,budget:budget)
   let matches=rows.filter{$0.pid==ref.pid&&$0.visible&&[0,3,8].contains($0.layer)&&$0.alpha>0&&close($0.bounds,rect)}
   guard matches.count==1 else{throw NativeFailure(matches.isEmpty ? "foregroundGeometryUnbound":"foregroundGeometryAmbiguous","AX window has no unique physical-window identity")};id=matches[0].id
  }
  return NativeForegroundTarget(pid:ref.pid,birth:ref.startToken,bundle:ref.bundleID,windowID:id,window:window,reference:ref)
 }
 enum PhysicalPhase:String {case preflight="foregroundWindow",raise="foregroundRaiseWindow"}
 // Classify only the existing exact CG-census predicate; no AX IDs, titles,
 // input contents or raw platform errors enter the diagnostic.
 static func physicalWindow(_ rows:[SessionKeyWindow],pid:pid_t,windowID:UInt32,phase:PhysicalPhase)throws->SessionKeyWindow {
  let owned=rows.filter{$0.id==windowID&&$0.pid==pid}
  let visible=owned.filter{$0.visible}
  let supported=phase == .preflight ? visible.filter{[0,3,8].contains($0.layer)}:visible
  let matches=phase == .preflight ? supported.filter{$0.alpha>0}:supported
  if matches.count==1{return matches[0]}
  let reason:String
  if matches.count>1{reason="Ambiguous"}
  else if owned.isEmpty{reason="Missing"}
  else if visible.isEmpty{reason="Invisible"}
  else if supported.isEmpty{reason="UnsupportedLayer"}
  else if supported.allSatisfy({$0.alpha==0}){reason="ZeroAlpha"}
  else{reason="AlphaUnavailable"}
  throw NativeFailure(phase.rawValue+reason,"Exact physical window rejected during \(phase == .preflight ? "preflight":"raise") (\(reason)); business input was not dispatched")
 }
 static func physical(pid:pid_t,birth:String,bundle:String,windowID:UInt32,budget:Budget,pointerDelivery:Bool=false)throws->NativeForegroundTarget {
  let rows=try ownedRows(pid:pid,birth:birth,bundle:bundle,budget:budget)
  _=try physicalWindow(rows,pid:pid,windowID:windowID,phase:.preflight)
  // A physical-window action already has independent CG identity. Resolving
  // AXWindows is necessary only if that exact window actually needs raising;
  // already-qualified keyboard/RobotGo routes keep their existing metadata path.
  return NativeForegroundTarget(pid:pid,birth:birth,bundle:bundle,windowID:windowID,window:nil,reference:nil,pointerDelivery:pointerDelivery)
 }
 private func windowForRaise(_ budget:Budget)throws->AXUIElement {
  if let window{return window}
  guard let windowID else{throw NativeFailure("foregroundWindowUnavailable","No exact window to raise")}
  let rows=try Self.ownedRows(pid:pid,birth:birth,bundle:bundle,budget:budget)
  let match=try Self.physicalWindow(rows,pid:pid,windowID:windowID,phase:.raise)
  let app=AXUIElementCreateApplication(pid);AXUIElementSetMessagingTimeout(app,min(0.05,budget.remainingSeconds))
  let windows=try OwnedAXWindows.enumerate(application:app,pid:pid,uid:getuid(),birth:birth,bundle:bundle,check:{try budget.check()})
  var found:[AXUIElement]=[]
  for candidate in windows {let rect=try Self.bounds(candidate,pid:pid,budget:budget);if Self.close(rect,match.bounds){found.append(candidate)}}
  guard found.count==1 else{throw NativeFailure("foregroundWindowUnavailable","Physical window has no unique owned AX window")}
  return found[0]
 }

 private static func close(_ a:CGRect,_ b:CGRect)->Bool{[a.minX,a.minY,a.width,a.height,b.minX,b.minY,b.width,b.height].allSatisfy{$0.isFinite}&&abs(a.minX-b.minX)<=1&&abs(a.minY-b.minY)<=1&&abs(a.width-b.width)<=1&&abs(a.height-b.height)<=1}
 func validate(_ budget:Budget)throws {
  let state=windowSession()
  guard state["available"] as? Bool==true,state["onConsole"] as? Bool==true,state["loginDone"] as? Bool==true,state["uid"] as? UInt32==getuid(),!IsSecureEventInputEnabled() else{throw NativeFailure("sessionUnqualified","Unlocked current-user nonsecure session required")}
  if let semanticRecipient {
   guard let reference else{throw NativeFailure("staleReference","Exact AX reference unavailable")}
   try reference.validateInputScope(budget);try semanticRecipient.validate(budget);try budget.check();return
  }
  let rows=try Self.ownedRows(pid:pid,birth:birth,bundle:bundle,budget:budget)
  if let reference {try reference.validateInputScope(budget);let owner=inspectAXElementOwner(reference.element);guard owner.status==AXError.success.rawValue,owner.pid==pid,owner.uid==getuid(),owner.birth==birth,owner.bundle==bundle else{throw NativeFailure("staleReference","Original element owner changed")}}
  if let windowID {
   guard rows.filter({$0.id==windowID&&$0.pid==pid&&$0.visible&&[0,3,8].contains($0.layer)&&$0.alpha.isFinite&&$0.alpha>0&&$0.alpha<=1}).count==1 else{throw NativeFailure("staleReference","Original physical window changed")}
  }
  if let windowID,let window {
   let owner=inspectAXElementOwner(window),rect=try Self.bounds(window,pid:pid,budget:budget)
   guard owner.pid==pid,owner.uid==getuid(),owner.birth==birth,owner.bundle==bundle,rows.filter({$0.id==windowID&&$0.pid==pid&&$0.visible&&Self.close($0.bounds,rect)}).count==1 else{throw NativeFailure("staleReference","Original AX/physical window identity changed")}
  }
  try budget.check()
 }
 // Frame clicks already require fresh pixels and the public mouse-down
 // recipient proof. Select their exact supported physical window; unrelated
 // owned windows do not establish interception at the intended click point.
 // Keyboard routes retain the highest-owned-window rule.
 static func physicalWindowReady(_ rows:[SessionKeyWindow],pid:pid_t,windowID:UInt32,pointerDelivery:Bool)->Bool {
  if pointerDelivery {
   let matches=rows.filter{$0.id==windowID}
   return matches.count==1 && matches[0].pid==pid && matches[0].visible && matches[0].alpha.isFinite && matches[0].alpha>0 && matches[0].alpha<=1 && supportedSessionInputWindowLayer(matches[0].layer)
  }
  return rows.first{$0.pid==pid&&$0.visible&&$0.alpha>0}?.id==windowID
 }
 func windowReady(_ budget:Budget)throws->Bool {
  if let semanticRecipient {
   if keyboardRecipient{return try semanticRecipient.keyboardFocused(budget)}
   return try semanticRecipient.focused(budget)
  }
  guard let windowID else{return true};let rows=try Self.ownedRows(pid:pid,birth:birth,bundle:bundle,budget:budget)
  return Self.physicalWindowReady(rows,pid:pid,windowID:windowID,pointerDelivery:pointerDelivery)
 }
 func ready(_ budget:Budget)throws->Bool {
  _=try qualifiedForeground(ForegroundIdentity(pid:pid,uid:getuid(),birth:birth,bundle:bundle,active:true),budget)
  return try windowReady(budget)
 }
 func acquire(_ budget:Budget,authorize:@escaping()throws->Void,reserve:()throws->Void,publish:(ForegroundAcquisitionReceipt)->Void)throws {
  let runtime=ForegroundAcquisitionRuntime(validate:{try authorize();try self.validate(budget);try authorize()},ready:{try self.ready(budget)},activate:{
   let entry=ApplicationInventoryEntry(pid:self.pid,bundleID:self.bundle,name:"",owner:getuid(),launchTime:nil,startToken:self.birth,active:false,terminated:false)
   return ApplicationControlRuntime.system.activate(entry)
  },needsRaise:{try !self.windowReady(budget)},raise:{
   guard self.windowID != nil || self.semanticRecipient?.window != nil else{return true};try self.validate(budget)
   let window=try self.windowForRaise(budget)
   var actions:CFArray?;guard AXUIElementCopyActionNames(window,&actions) == .success,let names=actions as? [String],names.contains(kAXRaiseAction) else{return false}
   try budget.check();return AXUIElementPerformAction(window,kAXRaiseAction as CFString) == .success
  },pause:{Thread.sleep(forTimeInterval:$0)})
  try acquireNativeForeground(budget,runtime:runtime,reserve:reserve,publish:publish)
 }
}

enum NativeForegroundRoutes {
 // These methods dispatch only AX actions/setters. Event delivery is excluded.
 static let semantic:Set<String>=["elements.focus","elements.press","elements.showMenu","elements.submit","elements.setValue","elements.replaceText"]
 // Only named, reference-addressed keys use AX keyboard recipient proof.
 // Raw inputs and physical window/text/mouse routes retain CG qualification.
 static let focusedKeyboard:Set<String>=["elements.pressKey","elements.pressSessionKey"]
 static let reference:Set<String>=["elements.focus","elements.press","elements.showMenu","elements.submit","elements.setValue","elements.replaceText","elements.pressKey","elements.pressSessionKey","input.key","input.text","input.pointer","windows.setPosition"]
 static let physical:Set<String>=["windows.pressSessionKey","windows.typeText"]
 static func requiresAcquisition(_ method:String)->Bool{reference.contains(method)||physical.contains(method)||method=="windows.clickFrame"}
}
extension Helper {
 func foregroundTarget(method:String,params:[String:Any],budget:Budget)throws->NativeForegroundTarget? {
  if NativeForegroundRoutes.reference.contains(method){
   let base:Set<String>=["elementRef","generation","expectedApp"];var required=base,optional=Set<String>()
   switch method {
   case "elements.setValue","elements.replaceText":required.insert("value");optional.insert("verifyReplacement");_=try boundedTextLiteral(params["value"])
   case "elements.pressKey","elements.pressSessionKey":required.insert("key");guard let key=params["key"] as? String else{throw NativeFailure("invalidKey","Named chord required")};_=try TargetedKeyChord(key)
   case "windows.setPosition":required.insert("position");_=try NativeWindowPosition(params["position"])
   case "input.key":required.insert("keyCode");optional.insert("modifiers");guard let key=params["keyCode"] as? UInt16,key<=127 else{throw NativeFailure("invalidKey","Bounded key code required")}
   case "input.text":required.insert("text");optional.insert("modifiers");guard let value=params["text"] as? String,!value.isEmpty,value.utf16.count<=1024 else{throw NativeFailure("invalidValue","Bounded Unicode text required")}
   case "input.pointer":required.formUnion(["x","y","displayID","button"]);guard let x=params["x"] as? Double,let y=params["y"] as? Double,x.isFinite,y.isFinite,params["button"] as? String=="left",let display=params["displayID"] as? UInt32,CGDisplayIsActive(display) != 0 else{throw NativeFailure("invalidCoordinates","Exact display/point required")}
   default:break
   }
   if let raw=params["verifyReplacement"] {guard CFGetTypeID(raw as CFTypeRef)==CFBooleanGetTypeID() else{throw NativeFailure("invalidValue","Boolean verification required")}}
   if let raw=params["modifiers"] {guard let values=raw as? [String],values.count<=4,Set(values).count==values.count,values.allSatisfy({["command","shift","option","control"].contains($0)}) else{throw NativeFailure("invalidModifier","Closed named modifiers required")}}
   guard required.isSubset(of:Set(params.keys)),Set(params.keys).isSubset(of:required.union(optional)),let id=params["elementRef"] as? String,let ref=refs[id],ref.generation==generation,params["generation"] as? Int==generation,params["expectedApp"] as? String==ref.bundleID,DispatchTime.now().uptimeNanoseconds-ref.observedAt<5_000_000_000 else{throw NativeFailure("staleReference","Fresh exact native reference required before foreground preparation")}
   return try NativeForegroundTarget.from(ref,budget:budget,semanticOnly:NativeForegroundRoutes.semantic.contains(method),keyboardOnly:NativeForegroundRoutes.focusedKeyboard.contains(method))
  }
  if NativeForegroundRoutes.physical.contains(method){
   let fields:Set<String>=method=="windows.pressSessionKey" ? ["expectedApp","pid","processStartToken","windowId","key"]:["expectedApp","pid","processStartToken","windowId","text","focusRole","focusIdentifier","focusName"]
   guard Set(params.keys)==fields,let bundle=params["expectedApp"] as? String,concreteApplicationBundle(bundle),let birth=params["processStartToken"] as? String,validApplicationProcessStartToken(birth) else{throw NativeFailure("invalidScope","Exact window action scope required")}
   if method=="windows.pressSessionKey"{guard let key=params["key"] as? String else{throw NativeFailure("invalidKey","Named chord required")};_=try TargetedKeyChord(key)}
   else {guard let text=params["text"] as? String,let role=params["focusRole"] as? String,let identifier=params["focusIdentifier"] as? String,let name=params["focusName"] as? String else{throw NativeFailure("invalidText","Typed literal target required")};_=try WindowTextPlan(text:text,role:role,identifier:identifier,name:name)}
   let pid=try RecordingConsentLease.integer(params["pid"],maximum:UInt64(Int32.max)),window=try RecordingConsentLease.integer(params["windowId"],maximum:UInt64(UInt32.max))
   guard pid>0,window>0 else{throw NativeFailure("invalidScope","Positive process/window required")}
   return try NativeForegroundTarget.physical(pid:pid_t(pid),birth:birth,bundle:bundle,windowID:UInt32(window),budget:budget)
  }
  return nil
 }
}
