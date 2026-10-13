import XCTest
import AppKit
import MechanizeNativeCore
@testable import MechanizeNative
final class CompactBadgeRenderingTests:XCTestCase {
 // Synthetic header fixtures only: three painted title rows with traffic lights
 // and a toolbar or tab block. No user window, capture, activation or content
 // is involved. Row 0: light header, free leading zone, toolbar far right.
 // Row 1: dark header, first tab leaves a gap beside the lights. Row 2: dark
 // header, tab crowds the leading zone with empty space far right.
 func testCapsuleMarkRendersOffscreenInBothHeaderThemesWithoutShadowOrLabel()throws {
  _=NSApplication.shared.setActivationPolicy(.accessory)
  let image=try XCTUnwrap(NSBitmapImageRep(bitmapDataPlanes:nil,pixelsWide:1200,pixelsHigh:288,bitsPerSample:8,samplesPerPixel:4,hasAlpha:true,isPlanar:false,colorSpaceName:.deviceRGB,bytesPerRow:0,bitsPerPixel:0))
  let graphics=try XCTUnwrap(NSGraphicsContext(bitmapImageRep:image));NSGraphicsContext.saveGraphicsState()
  graphics.cgContext.translateBy(x:0,y:288);graphics.cgContext.scaleBy(x:2,y:-2);NSGraphicsContext.current=NSGraphicsContext(cgContext:graphics.cgContext,flipped:true)
  var placements:[CGRect]=[];let headers:[CGFloat]=[0.94,0.22,0.22]
  for row in 0..<3 {
   let y=CGFloat(row*48),window=CGRect(x:0,y:y,width:600,height:700)
   NSColor(calibratedWhite:headers[row],alpha:1).setFill();NSRect(x:0,y:y,width:600,height:48).fill()
   let lights=(0..<3).map{CGRect(x:14+CGFloat($0*20),y:y+18,width:12,height:12)}
   for (i,color) in [NSColor.systemRed,NSColor.systemYellow,NSColor.systemGreen].enumerated(){color.setFill();NSBezierPath(ovalIn:lights[i]).fill()}
   let tab=row==0 ? CGRect(x:400,y:y+6,width:180,height:32):CGRect(x:row==1 ? 140:76,y:y,width:240,height:44)
   NSColor(calibratedWhite:row==0 ? 0.82:0.32,alpha:1).setFill();NSBezierPath(roundedRect:tab,xRadius:7,yRadius:7).fill()
   let placement=try XCTUnwrap(ControlBadgeGeometry.freeHeaderFrame(window:window,trafficLights:lights,occupied:[tab]));placements.append(placement)
   XCTAssertFalse(placement.intersects(tab));for light in lights{XCTAssertFalse(placement.intersects(light))}
   XCTAssertLessThan(placement.minX,tab.minX,"row \(row) stays in the leading zone");XCTAssertLessThanOrEqual(placement.maxX,ControlBadgeGeometry.leadingZoneEnd(window:window,trafficLights:lights))
   if row<2 {XCTAssertEqual(placement.origin,CGPoint(x:lights[2].maxX+2,y:lights[0].midY-9),"row \(row) full mark beside the lights")} else {XCTAssertEqual(placement.origin,CGPoint(x:6,y:y+2),"row 2 reduced leading placement")}
   NSGraphicsContext.saveGraphicsState();graphics.cgContext.translateBy(x:placement.minX,y:placement.minY)
   let view=AutomationControlBadgeView(frame:CGRect(origin:.zero,size:placement.size));view.active=row==0;view.draw(view.bounds);XCTAssertNil(view.hitTest(NSPoint(x:10,y:8)))
   NSGraphicsContext.restoreGraphicsState()
  }
  NSGraphicsContext.restoreGraphicsState()
  XCTAssertEqual(placements[0].size,CGSize(width:46,height:18));XCTAssertEqual(placements[2].size,CGSize(width:22,height:12))
  func pixel(_ x:CGFloat,_ y:CGFloat)throws->NSColor {try XCTUnwrap(image.colorAt(x:Int((x*2).rounded(.down)),y:Int((y*2).rounded(.down)))?.usingColorSpace(.deviceRGB))}
  func gray(_ c:NSColor,_ reference:NSColor)->Bool {abs(c.redComponent-reference.redComponent)<0.03&&abs(c.greenComponent-reference.greenComponent)<0.03&&abs(c.blueComponent-reference.blueComponent)<0.03}
  for (row,p) in placements.enumerated() {
   // Reference the painted header itself (below the tab block) rather than the
   // nominal calibrated gray, which the device bitmap does not round-trip.
   let header=try pixel(598,CGFloat(row*48)+46)
   XCTAssertEqual(header.redComponent,headers[row],accuracy:0.12)
   // The capsule interior is a light plate on light and dark headers alike;
   // the square corner outside the rounded end still shows header pixels, and
   // nothing is painted beyond the measured frame (no shadow, halo or label).
   for x in [p.minX+2.75,p.maxX-2.75] {
    let interior=try pixel(x,p.midY)
    XCTAssertGreaterThan(min(interior.redComponent,interior.greenComponent,interior.blueComponent),0.85,"row \(row) capsule fill at \(x)")
   }
   XCTAssertTrue(gray(try pixel(p.minX+0.25,p.minY+0.25),header),"row \(row) corner keeps header")
   XCTAssertTrue(gray(try pixel(p.maxX-0.25,p.maxY-0.25),header),"row \(row) corner keeps header")
   // Outside samples skip the green light's antialiased rim next to the full mark.
   let lightRim=CGRect(x:54,y:CGFloat(row*48)+18,width:12,height:12).insetBy(dx:-1.5,dy:-1.5)
   for (x,y) in [(p.minX-1.5,p.midY),(p.maxX+1.5,p.midY),(p.midX,p.minY-1.5),(p.midX,p.maxY+1.5)] where !lightRim.contains(CGPoint(x:x,y:y)) {XCTAssertTrue(gray(try pixel(x,y),header),"row \(row) outside frame at \(x),\(y)")}
   // Letters are sampled inside the ring so the active blue border is excluded.
   var blue=0,red=0,blueRight=0,redLeft=0
   let inner=p.insetBy(dx:2.5,dy:2.5)
   for py in Int(inner.minY*2)..<Int(inner.maxY*2) {for px in Int(inner.minX*2)..<Int(inner.maxX*2) {
    let c=try XCTUnwrap(image.colorAt(x:px,y:py)?.usingColorSpace(.deviceRGB)),left=CGFloat(px)/2<p.midX
    if c.blueComponent>0.55&&c.redComponent<0.5&&c.greenComponent<0.7 {blue+=1;if !left{blueRight+=1}}
    if c.redComponent>0.6&&c.greenComponent<0.45&&c.blueComponent<0.5 {red+=1;if left{redLeft+=1}}
   }}
   XCTAssertGreaterThan(blue,row==2 ? 6:30,"row \(row) blue M");XCTAssertGreaterThan(red,row==2 ? 6:24,"row \(row) red V")
   // The pair is centred, so the M's trailing stem may graze the centre line.
   XCTAssertEqual(redLeft,0,"row \(row) V stays right of centre");XCTAssertLessThan(blueRight*5,blue,"row \(row) M stays left of centre")
  }
  let path=ProcessInfo.processInfo.environment["MECHANIZE_BADGE_PREVIEW"] ?? "/private/tmp/mechanize-compact-badge-header.png"
  try XCTUnwrap(image.representation(using:.png,properties:[:])).write(to:URL(fileURLWithPath:path),options:.atomic)
 }
 func testCenteredNarrowMarkRendersReadableActiveAndIdleLetters()throws {
  _=NSApplication.shared.setActivationPolicy(.accessory)
  let image=try XCTUnwrap(NSBitmapImageRep(bitmapDataPlanes:nil,pixelsWide:800,pixelsHigh:192,bitsPerSample:8,samplesPerPixel:4,hasAlpha:true,isPlanar:false,colorSpaceName:.deviceRGB,bytesPerRow:0,bitsPerPixel:0))
  let graphics=try XCTUnwrap(NSGraphicsContext(bitmapImageRep:image));NSGraphicsContext.saveGraphicsState()
  graphics.cgContext.translateBy(x:0,y:192);graphics.cgContext.scaleBy(x:2,y:-2)
  NSGraphicsContext.current=NSGraphicsContext(cgContext:graphics.cgContext,flipped:true)
  for row in 0..<2 {
   let y=CGFloat(row*48),window=CGRect(x:0,y:y,width:400,height:700)
   NSColor(calibratedWhite:row==0 ? 0.94:0.22,alpha:1).setFill();CGRect(x:0,y:y,width:400,height:48).fill()
   let lights=(0..<3).map{CGRect(x:14+CGFloat($0*20),y:y+18,width:12,height:12)}
   for (i,color) in [NSColor.systemRed,NSColor.systemYellow,NSColor.systemGreen].enumerated(){color.setFill();NSBezierPath(ovalIn:lights[i]).fill()}
   let project=CGRect(x:94,y:y+6,width:180,height:32)
   NSColor(calibratedWhite:row==0 ? 0.82:0.32,alpha:1).setFill();NSBezierPath(roundedRect:project,xRadius:7,yRadius:7).fill()
   let placement=try XCTUnwrap(ControlBadgeGeometry.presentationHeaderFrame(window:window,trafficLights:lights,occupied:[project],coverageComplete:false))
   XCTAssertEqual(placement.size,CGSize(width:22,height:18));XCTAssertEqual(placement.midY,lights[0].midY)
   NSGraphicsContext.saveGraphicsState();graphics.cgContext.translateBy(x:placement.minX,y:placement.minY)
   let view=AutomationControlBadgeView(frame:CGRect(origin:.zero,size:placement.size));view.active=row==0;view.draw(view.bounds)
   NSGraphicsContext.restoreGraphicsState()
   // Count actual colored glyph pixels inside the ring, excluding traffic lights.
   var blue=0,red=0
   let inner=placement.insetBy(dx:2,dy:2)
   for py in Int(inner.minY*2)..<Int(inner.maxY*2) {for px in Int(inner.minX*2)..<Int(inner.maxX*2) {
    let c=try XCTUnwrap(image.colorAt(x:px,y:py)?.usingColorSpace(.deviceRGB))
    if c.blueComponent>0.55&&c.redComponent<0.5&&c.greenComponent<0.7{blue+=1}
    if c.redComponent>0.6&&c.greenComponent<0.45&&c.blueComponent<0.5{red+=1}
   }}
   XCTAssertGreaterThan(blue,18);XCTAssertGreaterThan(red,14)
  }
  NSGraphicsContext.restoreGraphicsState()
  try XCTUnwrap(image.representation(using:.png,properties:[:])).write(to:URL(fileURLWithPath:"/private/tmp/mechanize-centered-narrow-badge-header.png"),options:.atomic)
 }
 func testCapsuleLayoutKeepsLettersInsideBothMarkSizes() {
  for size in [CGSize(width:46,height:18),CGSize(width:22,height:18),CGSize(width:22,height:12)] {
   let layout=AutomationControlBadgeLayout(size:size),bounds=NSRect(origin:.zero,size:size)
   XCTAssertEqual(layout.radius,layout.pill.height/2,"full capsule");XCTAssertEqual(layout.compact,size.height<16 || size.width<30)
   XCTAssertTrue(bounds.contains(layout.pill));XCTAssertLessThan(layout.m.maxX,layout.v.minX,"M precedes V")
   let letters=layout.m.union(layout.v)
   XCTAssertGreaterThanOrEqual(letters.minX,2,"leading inset");XCTAssertLessThanOrEqual(letters.maxX,size.width-2,"trailing inset")
   XCTAssertEqual(letters.midX,size.width/2,accuracy:1.5,"horizontally centred")
   XCTAssertLessThanOrEqual(layout.font.capHeight,size.height-2*2,"cap height clears the capsule")
   XCTAssertEqual(layout.font.pointSize,size.height<16 ? 8:(size.width<30 ? 10:12))
  }
 }
 func testCompactGeometryAndPanelDoNotTakeFocusOrInterceptInput() {
  _=NSApplication.shared.setActivationPolicy(.accessory);let before=NSApp.keyWindow
  for width in stride(from:120,through:3000,by:47){for header in [CGFloat(11),17,28,100]{
   let window=CGRect(x:-1400,y:1200,width:width,height:700)
   let frame=ControlBadgeGeometry.frame(window:window,headerCenter:header,leading:84)!
   XCTAssertTrue(window.contains(frame));XCTAssertEqual(frame.size,CGSize(width:46,height:18));XCTAssertLessThanOrEqual(frame.maxY,window.minY+44)
  }}
  let panel=AutomationPointerPanel(contentRect:.zero,styleMask:[.borderless,.nonactivatingPanel],backing:.buffered,defer:false)
  panel.ignoresMouseEvents=true;panel.hasShadow=false;panel.setAccessibilityElement(false)
  XCTAssertFalse(panel.canBecomeKey);XCTAssertFalse(panel.canBecomeMain);XCTAssertTrue(panel.ignoresMouseEvents);XCTAssertFalse(panel.hasShadow);XCTAssertEqual(NSApp.keyWindow,before);panel.close()
 }
}
