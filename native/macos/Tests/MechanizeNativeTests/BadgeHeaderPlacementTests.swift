import XCTest
import AppKit
import MechanizeNativeCore
@testable import MechanizeNative

final class BadgeHeaderPlacementTests:XCTestCase {
 func testGeometryAvoidsFirstTabAndUsesCompactFreeHeaderFallback() {
  let window=CGRect(x:-900,y:40,width:900,height:700)
  let lights=(0..<3).map{CGRect(x:window.minX+14+CGFloat($0*20),y:window.minY+18,width:12,height:12)}
  let firstTab=CGRect(x:window.minX+80,y:window.minY,width:240,height:44)
  let full=ControlBadgeGeometry.freeHeaderFrame(window:window,trafficLights:lights,occupied:[firstTab])!
  XCTAssertEqual(full.size,CGSize(width:46,height:18));XCTAssertFalse(full.intersects(firstTab));XCTAssertGreaterThanOrEqual(full.minX,firstTab.maxX)
  let tabs=CGRect(x:window.minX+76,y:window.minY,width:window.width-76,height:44)
  let compact=ControlBadgeGeometry.freeHeaderFrame(window:window,trafficLights:lights,occupied:[tabs])!
  XCTAssertEqual(compact.size,CGSize(width:22,height:12));XCTAssertLessThan(compact.maxY,lights[0].minY);XCTAssertFalse(compact.intersects(tabs))
  XCTAssertNil(ControlBadgeGeometry.freeHeaderFrame(window:window,trafficLights:lights,occupied:[CGRect(x:window.minX,y:window.minY,width:window.width,height:44)]))
 }
 func testTranslationCachesGeometryAndFocusReturnKeepsIdlePanelToken()async throws {
  try await MainActor.run {
   var time=100.0,front:pid_t?=42,bounds=CGRect(x:0,y:26,width:900,height:700)
   var measurements=0,begins=0,moves=0,suspends=0,resumes=0,ends=0;var states:[Bool]=[]
   let runtime=WindowSessionKeyRuntime(process:{_ in(getuid(),"100:1","com.fixture.app")},foreground:{front},windows:{[SessionKeyWindow(id:7,pid:42,layer:0,visible:true,alpha:1,bounds:bounds)]},session:{true},secure:{false})
   var p=BrowserBadgePresentation(begin:{_ in XCTFail("blind fallback");return nil},move:{_,_ in},hide:{_ in ends+=1},renew:{_ in})
   p.measure={_,_ in measurements+=1;return ControlBadgeAnchor(headerCenter:22,leading:340)}
   p.beginAnchored={_,_ in begins+=1;return 8};p.moveAnchored={token,_,anchor in XCTAssertEqual(token,8);XCTAssertEqual(anchor.leading,340);moves+=1}
   p.suspend={token in XCTAssertEqual(token,8);suspends+=1};p.resume={token in XCTAssertEqual(token,8);resumes+=1};p.state={_,active in states.append(active)}
   let badge=BrowserControlBadge(runtime:runtime,now:{time},schedule:false,presentation:p),token=String(repeating:"a",count:64),session=String(repeating:"b",count:64)
   _=try badge.handle(method:"controlBadge.begin",params:["token":token,"sessionToken":session,"expectedApp":"com.fixture.app","pid":Int32(42),"processStartToken":"100:1","windowBounds":["x":0.0,"y":26.0,"width":900.0,"height":700.0],"durationMs":300])
   _=try badge.handle(method:"controlBadge.end",params:["token":token])
   for _ in 0..<50{bounds.origin.x+=2;time+=0.08;XCTAssertEqual(badge.refresh(),"shown")}
   XCTAssertEqual(measurements,1);XCTAssertEqual(moves,50);XCTAssertEqual(states.last,false)
   bounds.size.width+=50;XCTAssertEqual(badge.refresh(),"shown");XCTAssertEqual(measurements,2)
   for _ in 0..<10{front=99;XCTAssertEqual(badge.refresh(),"hidden");front=42;XCTAssertEqual(badge.refresh(),"shown")}
   XCTAssertEqual(begins,1);XCTAssertEqual(suspends,10);XCTAssertEqual(resumes,10);XCTAssertEqual(states.last,false)
   _=try badge.handle(method:"controlBadge.releaseSession",params:["sessionToken":session]);XCTAssertEqual(ends,1);XCTAssertEqual(badge.refresh(),"hidden")
  }
 }
 func testIncompletePlacementRetriesBoundedlyWithoutUnanchoredFallback()async throws {
  try await MainActor.run {
   var time=100.0,measurements=0,begins=0
   let bounds=CGRect(x:0,y:26,width:900,height:700)
   let runtime=WindowSessionKeyRuntime(process:{_ in(getuid(),"100:1","com.fixture.app")},foreground:{42},windows:{[SessionKeyWindow(id:7,pid:42,layer:0,visible:true,alpha:1,bounds:bounds)]},session:{true},secure:{false})
   var p=BrowserBadgePresentation(begin:{_ in XCTFail("blind fallback");return nil},move:{_,_ in},hide:{_ in},renew:{_ in})
   p.measure={_,_ in measurements+=1;return measurements==1 ? nil:ControlBadgeAnchor(headerCenter:8,leading:6,size:CGSize(width:22,height:12))};p.beginAnchored={_,anchor in XCTAssertEqual(anchor.size.width,22);begins+=1;return 1}
   let badge=BrowserControlBadge(runtime:runtime,now:{time},schedule:false,presentation:p)
   let result=try badge.handle(method:"controlBadge.begin",params:["token":String(repeating:"a",count:64),"sessionToken":String(repeating:"b",count:64),"expectedApp":"com.fixture.app","pid":Int32(42),"processStartToken":"100:1","windowBounds":["x":0.0,"y":26.0,"width":900.0,"height":700.0],"durationMs":300])
   XCTAssertEqual(result["status"] as? String,"placementUnavailable");for _ in 0..<5{time+=0.1;XCTAssertEqual(badge.refresh(),"placementUnavailable")};XCTAssertEqual(measurements,1)
   time+=0.6;XCTAssertEqual(badge.refresh(),"shown");XCTAssertEqual(measurements,2);XCTAssertEqual(begins,1)
  }
 }
}
