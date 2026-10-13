import AppKit
import MechanizeNativeCore
struct BrowserBadgePresentation {
 let begin:(CGRect)->UInt64?,move:(UInt64,CGRect)->Void,hide:(UInt64)->Void,renew:(UInt64)->Void,complete:(UInt64)->Void
 var measure:((pid_t,CGRect)->ControlBadgeAnchor?)?,beginAnchored:((CGRect,ControlBadgeAnchor)->UInt64?)?,moveAnchored:((UInt64,CGRect,ControlBadgeAnchor)->Void)?,state:((UInt64,Bool)->Void)?,suspend:((UInt64)->Void)?,resume:((UInt64)->Void)?
 init(begin:@escaping(CGRect)->UInt64?,move:@escaping(UInt64,CGRect)->Void,hide:@escaping(UInt64)->Void,renew:@escaping(UInt64)->Void,complete:@escaping(UInt64)->Void={AutomationPointer.setControlActive($0,false)}){self.begin=begin;self.move=move;self.hide=hide;self.renew=renew;self.complete=complete}
 static let system:BrowserBadgePresentation = {
  var v=BrowserBadgePresentation(begin:{_ in nil},move:{_,_ in},hide:{AutomationPointer.hideControl($0)},renew:{AutomationPointer.setControlActive($0,true)},complete:{AutomationPointer.setControlActive($0,false)})
  v.measure={ControlBadgeAnchor.measure(pid:$0,bounds:$1)}
  v.beginAnchored={AutomationPointer.beginControl(window:$0,persistent:true,anchor:$1)}
  v.moveAnchored={AutomationPointer.repositionControl($0,window:$1,allowCompleted:true,anchor:$2)}
  v.suspend={AutomationPointer.suspendControl($0)};v.resume={AutomationPointer.resumeControl($0)}
  v.state={AutomationPointer.setControlActive($0,$1)};return v
 }()
}
// Session ownership is presentation only. It never grants input authority.
@MainActor final class BrowserControlBadge {
 static let shared=BrowserControlBadge()
 private struct Owner {
  let token:String,session:String?,pid:pid_t,birth:String,bundle:String,windowID:UInt32,sequence:UInt64
  var activeUntil:TimeInterval;var completed=false
  var key:String {"\(pid):\(birth):\(windowID)"}
 }
 private var owners:[String:Owner]=[:],usedTokens=Set<String>(),closedSessions=Set<String>()
 private var connectionClosed=false
 private var sequence:UInt64=0,timer:Timer?
 private var shownKey:String?,shownToken:UInt64?,shownActive:Bool?,shownBounds:CGRect?
 private var suspended=false,anchorKey:String?,anchorSize:CGSize?,anchor:ControlBadgeAnchor?,nextMeasureAt:TimeInterval=0,measuredAt:TimeInterval=0

 private let runtime:WindowSessionKeyRuntime,now:()->TimeInterval,schedule:Bool,presentation:BrowserBadgePresentation
 init(runtime:WindowSessionKeyRuntime = .system,now:@escaping()->TimeInterval={ProcessInfo.processInfo.systemUptime},schedule:Bool=true,presentation:BrowserBadgePresentation = .system){self.runtime=runtime;self.now=now;self.schedule=schedule;self.presentation=presentation}
 private func identity(_ owner:Owner)->Bool {guard let a=runtime.process(owner.pid) else{return false};return a.0==getuid()&&a.1==owner.birth&&a.2==owner.bundle}
 func releaseAll(){connectionClosed=true;owners.removeAll();closedSessions.removeAll();hide();timer?.invalidate();timer=nil}
 private func hide(){if let token=shownToken{presentation.hide(token)};shownKey=nil;shownToken=nil;shownActive=nil;shownBounds=nil;suspended=false}
 private func suspend(){guard let token=shownToken else{return};if let conceal=presentation.suspend{if !suspended{conceal(token)};suspended=true}else{hide()}}
 private func measuredAnchor(_ owner:Owner,_ bounds:CGRect)->ControlBadgeAnchor? {
  guard let measure=presentation.measure else{return nil}
  if anchorKey != owner.key {anchorKey=owner.key;anchorSize=nil;anchor=nil;nextMeasureAt=0;measuredAt=0}
  if anchorSize==bounds.size,now()<nextMeasureAt{return anchor}
  // Relative offsets survive translations; resize and failed scans have a
  // cooldown rather than synchronous AX IPC on every 100ms tracking tick.
  if anchorSize != nil && now()<measuredAt+0.5 && anchorSize != bounds.size{return nil}
  anchor=measure(owner.pid,bounds);anchorSize=bounds.size;measuredAt=now();nextMeasureAt=now()+(anchor == nil ? 1:5)
  return anchor
 }
 private func startTimer(){guard schedule&&timer==nil else{return};let t=Timer(timeInterval:0.1,repeats:true){_ in Task{@MainActor in _=self.refresh()}};timer=t;RunLoop.main.add(t,forMode:.common)}
 func handle(method:String,params:[String:Any])throws->[String:Any]{
  guard !connectionClosed else{throw NativeFailure("badgeUnavailable","Presentation connection closed")}
  if method=="controlBadge.releaseSession" {
   guard Set(params.keys)==["sessionToken"],let s=params["sessionToken"] as? String,ControlBadgeScope.validToken(s),closedSessions.count<4096||closedSessions.contains(s) else{throw NativeFailure("badgeUnavailable","Presentation session unavailable")}
   closedSessions.insert(s);owners=owners.filter{$0.value.session != s};return ["status":refresh()]
  }
  guard let token=params["token"] as? String,ControlBadgeScope.validToken(token) else{throw NativeFailure("badgeUnavailable","Presentation scope unavailable")}
  var expected:Set<String> = method=="controlBadge.begin" ? ["token","expectedApp","pid","processStartToken","windowBounds","durationMs"] : method=="controlBadge.renew" ? ["token","durationMs"] : ["token"]
  if method=="controlBadge.begin"&&params["sessionToken"] != nil {expected.insert("sessionToken")}
  if method=="controlBadge.begin"&&params["windowId"] != nil {expected.insert("windowId")}
  guard Set(params.keys)==expected else{throw NativeFailure("badgeUnavailable","Presentation scope unavailable")}
  if method=="controlBadge.stop" {owners.removeValue(forKey:token);return ["status":refresh()]}
  if method=="controlBadge.end" {if var o=owners[token]{o.completed=true;if o.session==nil{o.activeUntil=now()+1.2};owners[token]=o};return ["status":refresh()]}
  guard let duration=params["durationMs"] as? Int,ControlBadgeScope.validDuration(duration) else{throw NativeFailure("badgeUnavailable","Presentation duration unavailable")}
  if method=="controlBadge.begin" {
   let session=params["sessionToken"] as? String
   guard params["windowId"] == nil || params["windowId"] as? UInt32 != nil else {throw NativeFailure("badgeUnavailable","Presentation window identity unavailable")}
   guard !usedTokens.contains(token),usedTokens.count<4096,owners.count<256,params["sessionToken"]==nil||session.map({ControlBadgeScope.validToken($0) && !closedSessions.contains($0)})==true,
    let pid=params["pid"] as? Int32,let birth=params["processStartToken"] as? String,let bundle=params["expectedApp"] as? String,
    let a=runtime.process(pid),a.0==getuid(),a.1==birth,a.2==bundle,
    let raw=params["windowBounds"] as? [String:Any],Set(raw.keys)==["x","y","width","height"],let x=raw["x"] as? Double,let y=raw["y"] as? Double,let w=raw["width"] as? Double,let h=raw["height"] as? Double,
    let rows=runtime.windows(),let id=ControlBadgeScope.match(pid:pid,bounds:CGRect(x:x,y:y,width:w,height:h),windows:rows.map{ControlBadgeWindow(id:$0.id,pid:$0.pid,layer:$0.layer,visible:$0.visible,alpha:$0.alpha,bounds:$0.bounds)},allowedLayers:[0,3,8],foregroundPID:runtime.foreground(),windowID:params["windowId"] as? UInt32),
    let after=runtime.process(pid),after.0==a.0,after.1==birth,after.2==bundle else{throw NativeFailure("badgeUnavailable","Presentation scope unavailable")}
   sequence &+= 1
   let o=Owner(token:token,session:session,pid:pid,birth:birth,bundle:bundle,windowID:id,sequence:sequence,activeUntil:now()+Double(duration)/1000)
   // Replace completed action ownership on this exact session/target only.
   if let session {owners=owners.filter{!($0.value.session==session&&$0.value.key==o.key&&($0.value.completed||$0.value.activeUntil<=now()))}}
   usedTokens.insert(token);owners[token]=o;startTimer()
  } else if method=="controlBadge.renew" {
   guard var o=owners[token],!o.completed,o.activeUntil>now(),identity(o) else{return ["status":"unavailable"]}
   o.activeUntil=now()+Double(duration)/1000;owners[token]=o
  } else {throw NativeFailure("badgeUnavailable","Presentation method unavailable")}
  return ["status":refresh()]
 }
 func refresh()->String {
  guard !owners.isEmpty else{hide();timer?.invalidate();timer=nil;return "hidden"}
  guard let rows=runtime.windows(),rows.count<=1000 else{suspend();return "unavailable"}
  var invalid=false
  for (token,o) in owners {
   let matches=rows.filter{$0.id==o.windowID&&$0.pid==o.pid&&[0,3,8].contains($0.layer)&&$0.alpha.isFinite&&$0.alpha>0&&$0.alpha<=1}
   if !identity(o)||matches.count != 1||ControlBadgeGeometry.frame(window:matches[0].bounds)==nil||o.session==nil&&o.activeUntil<=now(){owners.removeValue(forKey:token);invalid=true}
  }
  let front=rows.first{[0,3,8].contains($0.layer)&&$0.visible&&$0.alpha>0},foreground=runtime.foreground()
  let candidates=owners.values.filter{$0.pid==foreground&&$0.pid==front?.pid&&$0.windowID==front?.id}.sorted{$0.sequence>$1.sequence}
  guard let o=candidates.first,let bounds=front?.bounds else{if owners.isEmpty{hide()}else{suspend()};return owners.isEmpty&&invalid ? "unavailable":"hidden"}
  let active=candidates.contains{!$0.completed&&$0.activeUntil>now()}
  let oldAnchor=anchor,resolved=measuredAnchor(o,bounds)
  if presentation.measure != nil && resolved == nil {suspend();return "placementUnavailable"}
  let newlyShown=shownKey != o.key || shownToken == nil
  if newlyShown {hide();shownToken=resolved.flatMap{presentation.beginAnchored?(bounds,$0)} ?? (presentation.measure == nil ? presentation.begin(bounds):nil);shownKey=o.key;shownBounds=bounds;shownActive=nil}
  guard identity(o) else {owners.removeValue(forKey:o.token);hide();return "unavailable"}
  guard let token=shownToken else{return "placementUnavailable"}
  if !newlyShown && (shownBounds != bounds || oldAnchor != resolved) {if let anchor=resolved,let move=presentation.moveAnchored{move(token,bounds,anchor)}else{presentation.move(token,bounds)};shownBounds=bounds}
  if shownActive != active {if let state=presentation.state{state(token,active)}else if active{presentation.renew(token)}else{presentation.complete(token)};shownActive=active}
  if suspended {presentation.resume?(token);suspended=false}
  return "shown"
 }
}
