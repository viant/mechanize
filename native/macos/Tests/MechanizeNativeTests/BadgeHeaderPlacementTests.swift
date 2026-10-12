import XCTest
import AppKit
import MechanizeNativeCore
@testable import MechanizeNative

final class BadgeHeaderPlacementTests:XCTestCase {
 func testFullMarkStaysInLeadingZoneBesideTrafficLightsAndNeverWandersAfterTabs() {
  let window=CGRect(x:-900,y:40,width:900,height:700)
  let lights=(0..<3).map{CGRect(x:window.minX+14+CGFloat($0*20),y:window.minY+18,width:12,height:12)}
  let zoneEnd=ControlBadgeGeometry.leadingZoneEnd(window:window,trafficLights:lights)
  XCTAssertEqual(zoneEnd,lights[2].maxX+ControlBadgeGeometry.leadingZoneSlack);XCTAssertEqual(ControlBadgeGeometry.leadingZoneSlack,60)
  // Genuinely free leading header: a toolbar far right must not pull the mark.
  let toolbar=CGRect(x:window.minX+400,y:window.minY+6,width:300,height:32)
  for occupied in [[],[toolbar]] {
   let full=ControlBadgeGeometry.freeHeaderFrame(window:window,trafficLights:lights,occupied:occupied)!
   XCTAssertEqual(full,CGRect(x:lights[2].maxX+2,y:lights[0].midY-9,width:46,height:18));XCTAssertLessThanOrEqual(full.maxX,zoneEnd)
   for light in lights{XCTAssertFalse(full.intersects(light))}
  }
  // A first tab leaving a 70pt gap beside the lights still hosts the full mark.
  let roomyTab=CGRect(x:window.minX+140,y:window.minY,width:240,height:44)
  XCTAssertEqual(ControlBadgeGeometry.freeHeaderFrame(window:window,trafficLights:lights,occupied:[roomyTab]),CGRect(x:lights[2].maxX+2,y:lights[0].midY-9,width:46,height:18))
  // Crowded leading zone with empty space far right: reduced leading placement,
  // never a full mark after the distant tab.
  let firstTab=CGRect(x:window.minX+80,y:window.minY,width:240,height:44)
  let reduced=ControlBadgeGeometry.freeHeaderFrame(window:window,trafficLights:lights,occupied:[firstTab])!
  XCTAssertEqual(reduced.size,CGSize(width:22,height:12));XCTAssertLessThan(reduced.maxX,firstTab.minX);XCTAssertLessThanOrEqual(reduced.maxX,zoneEnd)
  XCTAssertLessThan(reduced.maxY,lights[0].minY-2);XCTAssertFalse(reduced.intersects(firstTab));XCTAssertEqual(reduced.minX,window.minX+6)
  // A Chrome-like strip starting 8pt down beside the lights behaves the same.
  let strip=CGRect(x:window.minX+76,y:window.minY+8,width:window.width-76,height:36)
  let compact=ControlBadgeGeometry.freeHeaderFrame(window:window,trafficLights:lights,occupied:[strip])!
  XCTAssertEqual(compact.size,CGSize(width:22,height:12));XCTAssertLessThan(compact.maxY,lights[0].minY);XCTAssertFalse(compact.intersects(strip));XCTAssertLessThanOrEqual(compact.maxX,zoneEnd)
  // A fully occupied header, or a control sitting in the only leading gap,
  // yields no placement rather than a wandering one.
  XCTAssertNil(ControlBadgeGeometry.freeHeaderFrame(window:window,trafficLights:lights,occupied:[CGRect(x:window.minX,y:window.minY,width:window.width,height:44)]))
  XCTAssertNil(ControlBadgeGeometry.freeHeaderFrame(window:window,trafficLights:lights,occupied:[CGRect(x:window.minX,y:window.minY,width:zoneEnd-window.minX,height:44)]))
 }
 func testPlacementOffsetsAreDisplayIndependentAndConvertToAppKitPerDisplay() throws {
  // Same window on the primary display, a display to the upper left (negative
  // global coordinates) and a display to the right: identical window-relative
  // offsets, and AppKit panel frames keep each display's own coordinates.
  let primaryCG=CGRect(x:0,y:0,width:2560,height:1440),primaryAppKit=CGRect(x:0,y:0,width:2560,height:1440)
  var offsets:Set<[CGFloat]>=[]
  for origin in [CGPoint(x:0,y:26),CGPoint(x:-1440,y:-900),CGPoint(x:2560,y:300)] {
   let window=CGRect(origin:origin,size:CGSize(width:900,height:700))
   let lights=(0..<3).map{CGRect(x:window.minX+14+CGFloat($0*20),y:window.minY+18,width:12,height:12)}
   let placement=try XCTUnwrap(ControlBadgeGeometry.freeHeaderFrame(window:window,trafficLights:lights,occupied:[]))
   XCTAssertTrue(window.contains(placement));offsets.insert([placement.minX-window.minX,placement.minY-window.minY,placement.width,placement.height])
   let anchor=ControlBadgeAnchor(headerCenter:placement.midY-window.minY,leading:placement.minX-window.minX,size:placement.size)
   let frame=try XCTUnwrap(ControlBadgeGeometry.frame(window:window,headerCenter:anchor.headerCenter,leading:anchor.leading,size:anchor.size))
   XCTAssertEqual(frame,placement)
   let topLeft=try appKitMouseDownPoint(frame.origin,primaryCG:primaryCG,primaryAppKit:primaryAppKit)
   let panel=CGRect(x:topLeft.x,y:topLeft.y-frame.height,width:frame.width,height:frame.height)
   XCTAssertEqual(panel.minX,frame.minX);XCTAssertEqual(panel.maxY,primaryAppKit.maxY-frame.minY);XCTAssertEqual(panel.minY,primaryAppKit.maxY-frame.maxY)
  }
  XCTAssertEqual(offsets.count,1);XCTAssertEqual(offsets.first,[68,15,46,18])
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
