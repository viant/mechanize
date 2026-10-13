import XCTest
import AppKit
import MechanizeNativeCore
@testable import MechanizeNative
final class BadgeSessionLifetimeTests:XCTestCase {
 func testIdlePersistsAcrossActionsAndFocusReturnUntilOwnedSessionRelease()async throws {
  try await MainActor.run {
   var time=100.0,front:pid_t?=42,shown=0,hidden=0;var states:[Bool]=[]
   let bounds=CGRect(x:0,y:26,width:900,height:700),session=String(repeating:"d",count:64)
   let runtime=WindowSessionKeyRuntime(process:{_ in(getuid(),"100:1","com.fixture.app")},foreground:{front},windows:{[SessionKeyWindow(id:7,pid:42,layer:0,visible:true,alpha:1,bounds:bounds)]},session:{true},secure:{false})
   var view=BrowserBadgePresentation(begin:{_ in shown+=1;return UInt64(shown)},move:{_,_ in},hide:{_ in hidden+=1},renew:{_ in},complete:{_ in})
   view.state={_,active in states.append(active)}
   let badge=BrowserControlBadge(runtime:runtime,now:{time},schedule:false,presentation:view)
   for i in 1...20 {
    let token=String(format:"%064x",i)
    _=try badge.handle(method:"controlBadge.begin",params:["token":token,"sessionToken":session,"expectedApp":"com.fixture.app","pid":Int32(42),"processStartToken":"100:1","windowBounds":["x":0.0,"y":26.0,"width":900.0,"height":700.0],"durationMs":300])
    XCTAssertEqual(states.last,true)
    _=try badge.handle(method:"controlBadge.end",params:["token":token]);XCTAssertEqual(states.last,false)
    time+=10;XCTAssertEqual(badge.refresh(),"shown")
   }
   XCTAssertEqual(shown,1);XCTAssertEqual(hidden,0)
   front=99;XCTAssertEqual(badge.refresh(),"hidden")
   front=42;XCTAssertEqual(badge.refresh(),"shown");XCTAssertEqual(states.last,false)
   _=try badge.handle(method:"controlBadge.releaseSession",params:["sessionToken":session]);XCTAssertEqual(badge.refresh(),"hidden")
   XCTAssertThrowsError(try badge.handle(method:"controlBadge.begin",params:["token":String(repeating:"f",count:64),"sessionToken":session,"expectedApp":"com.fixture.app","pid":Int32(42),"processStartToken":"100:1","windowBounds":["x":0.0,"y":26.0,"width":900.0,"height":700.0],"durationMs":300]))
  }
 }
 func testExpiredActivityBecomesIdleAndOldEndCannotAffectNewSession()async throws {
  try await MainActor.run {
   var time=100.0,birth="100:1";var states:[Bool]=[];var hidden=0
   let bounds=CGRect(x:0,y:26,width:900,height:700)
   let runtime=WindowSessionKeyRuntime(process:{_ in(getuid(),birth,"com.fixture.app")},foreground:{42},windows:{[SessionKeyWindow(id:7,pid:42,layer:0,visible:true,alpha:1,bounds:bounds)]},session:{true},secure:{false})
   var view=BrowserBadgePresentation(begin:{_ in 1},move:{_,_ in},hide:{_ in hidden+=1},renew:{_ in},complete:{_ in});view.state={_,v in states.append(v)}
   let badge=BrowserControlBadge(runtime:runtime,now:{time},schedule:false,presentation:view)
   @MainActor func begin(_ token:String,_ session:String)throws{_=try badge.handle(method:"controlBadge.begin",params:["token":token,"sessionToken":session,"expectedApp":"com.fixture.app","pid":Int32(42),"processStartToken":"100:1","windowBounds":["x":0.0,"y":26.0,"width":900.0,"height":700.0],"durationMs":300])}
   let a=String(repeating:"a",count:64),b=String(repeating:"b",count:64),s=String(repeating:"c",count:64),s2=String(repeating:"d",count:64)
   try begin(a,s);time+=2;XCTAssertEqual(badge.refresh(),"shown");XCTAssertEqual(states.last,false)
   try begin(b,s2);_=try badge.handle(method:"controlBadge.end",params:["token":a]);XCTAssertEqual(states.last,true)
   _=try badge.handle(method:"controlBadge.releaseSession",params:["sessionToken":s]);XCTAssertEqual(badge.refresh(),"shown");XCTAssertEqual(states.last,true)
   birth="101:1";XCTAssertEqual(badge.refresh(),"unavailable");XCTAssertEqual(hidden,1)
  }
 }
 func testNativeObservationThenAXActionTracksExactWindowAndStopReleasesOwner()async throws {
  try await MainActor.run {
   var rows=[SessionKeyWindow(id:7,pid:42,layer:0,visible:true,alpha:1,bounds:CGRect(x:0,y:26,width:900,height:700)),SessionKeyWindow(id:8,pid:42,layer:0,visible:true,alpha:1,bounds:CGRect(x:950,y:26,width:600,height:500))]
   var frames:[CGRect]=[],states:[Bool]=[];var hidden=0
   let runtime=WindowSessionKeyRuntime(process:{_ in(getuid(),"100:1","com.fixture.app")},foreground:{42},windows:{rows},session:{true},secure:{false})
   var view=BrowserBadgePresentation(begin:{frames.append($0);return UInt64(frames.count)},move:{_,bounds in frames.append(bounds)},hide:{_ in hidden+=1},renew:{_ in},complete:{_ in})
   view.state={_,value in states.append(value)}
   let badge=BrowserControlBadge(runtime:runtime,schedule:false,presentation:view)
   let session=String(repeating:"c",count:64),observe=String(repeating:"a",count:64),action=String(repeating:"b",count:64)
   @MainActor func begin(_ token:String,_ bounds:CGRect)throws {
    _=try badge.handle(method:"controlBadge.begin",params:["token":token,"sessionToken":session,"expectedApp":"com.fixture.app","pid":Int32(42),"processStartToken":"100:1","windowBounds":["x":Double(bounds.minX),"y":Double(bounds.minY),"width":Double(bounds.width),"height":Double(bounds.height)],"durationMs":300])
   }
   // The native observation and action bridge both enter these same routes.
   try begin(observe,rows[0].bounds);XCTAssertEqual(states.last,true)
   _=try badge.handle(method:"controlBadge.end",params:["token":observe]);XCTAssertEqual(states.last,false)
   try begin(action,rows[0].bounds);XCTAssertEqual(states.last,true);XCTAssertEqual(frames.count,1)
   _=try badge.handle(method:"controlBadge.end",params:["token":action]);XCTAssertEqual(states.last,false)
   let translated=rows[0].bounds.offsetBy(dx:40,dy:50)
   rows[0]=SessionKeyWindow(id:7,pid:42,layer:0,visible:true,alpha:1,bounds:translated)
   XCTAssertEqual(badge.refresh(),"shown");XCTAssertEqual(frames.last,translated)
   rows.swapAt(0,1);XCTAssertEqual(badge.refresh(),"hidden") // Same app, different window.
   rows.swapAt(0,1);XCTAssertEqual(badge.refresh(),"shown");XCTAssertEqual(states.last,false)
   _=try badge.handle(method:"controlBadge.stop",params:["token":action]);XCTAssertEqual(badge.refresh(),"hidden")
   XCTAssertGreaterThan(hidden,0)
  }
 }
 func testTransportEndReleasesAllOwnersWithoutAHeartbeat()async throws {
  try await MainActor.run {
   var hidden=0
   let bounds=CGRect(x:0,y:26,width:900,height:700)
   let runtime=WindowSessionKeyRuntime(process:{_ in(getuid(),"100:1","com.fixture.app")},foreground:{42},windows:{[SessionKeyWindow(id:7,pid:42,layer:0,visible:true,alpha:1,bounds:bounds)]},session:{true},secure:{false})
   let view=BrowserBadgePresentation(begin:{_ in 1},move:{_,_ in},hide:{_ in hidden+=1},renew:{_ in},complete:{_ in})
   let badge=BrowserControlBadge(runtime:runtime,schedule:false,presentation:view)
   _=try badge.handle(method:"controlBadge.begin",params:["token":String(repeating:"a",count:64),"sessionToken":String(repeating:"b",count:64),"expectedApp":"com.fixture.app","pid":Int32(42),"processStartToken":"100:1","windowBounds":["x":0.0,"y":26.0,"width":900.0,"height":700.0],"durationMs":300])
   badge.releaseAll();XCTAssertEqual(hidden,1);XCTAssertEqual(badge.refresh(),"hidden")
  }
 }
}

extension BadgeSessionLifetimeTests {
 // Explicit opt-in: own fixture and own indicator only, no user-window
 // capture, activation, keyboard, pointer or accessibility mutation.
 func testOwnPanelPersistsIdleBeyondActionTailAndHidesOnSessionRelease()async throws {
  guard ProcessInfo.processInfo.environment["MECHANIZE_BADGE_PANEL_FIXTURE"]=="1" else{throw XCTSkip("requires explicit own-panel fixture opt-in")}
  let session=String(repeating:"e",count:64),token=String(repeating:"f",count:64)
  let badge=await MainActor.run{()->BrowserControlBadge in
   _=NSApplication.shared.setActivationPolicy(.accessory)
   let bounds=CGRect(x:320,y:220,width:900,height:700)
   let runtime=WindowSessionKeyRuntime(process:{_ in(getuid(),"fixture-birth","com.fixture.app")},foreground:{getpid()},windows:{[SessionKeyWindow(id:7,pid:getpid(),layer:0,visible:true,alpha:1,bounds:bounds)]},session:{true},secure:{false})
   var presentation=BrowserBadgePresentation.system
            presentation.measure={_,_ in ControlBadgeAnchor(headerCenter:17,leading:84)} // Own synthetic panel geometry only.
            return BrowserControlBadge(runtime:runtime,presentation:presentation)
  }
  addTeardownBlock{await MainActor.run{badge.releaseAll();AutomationPointer.stopControl()}}
  try await MainActor.run {
   _=try badge.handle(method:"controlBadge.begin",params:["token":token,"sessionToken":session,"expectedApp":"com.fixture.app","pid":getpid(),"processStartToken":"fixture-birth","windowBounds":["x":320.0,"y":220.0,"width":900.0,"height":700.0],"durationMs":300])
   _=try badge.handle(method:"controlBadge.end",params:["token":token])
  }
  try await Task.sleep(nanoseconds:2_000_000_000)
  let idle=await MainActor.run{(AutomationPointer.controlPresentationVisible(),AutomationPointer.controlPresentationActive())}
  XCTAssertTrue(idle.0);XCTAssertEqual(idle.1,false)
  _=try await MainActor.run{try badge.handle(method:"controlBadge.releaseSession",params:["sessionToken":session])}
  try await Task.sleep(nanoseconds:50_000_000)
  let visible=await MainActor.run{AutomationPointer.controlPresentationVisible()};XCTAssertFalse(visible)
 }
}
