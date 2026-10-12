import XCTest
import AppKit
import MechanizeNativeCore
@testable import MechanizeNative
final class CompactBadgeRenderingTests:XCTestCase {
 func testCompactMarkRendersOffscreenInBothHeaderThemesWithoutPlate()throws {
  _=NSApplication.shared.setActivationPolicy(.accessory)
  let image=try XCTUnwrap(NSBitmapImageRep(bitmapDataPlanes:nil,pixelsWide:1200,pixelsHigh:288,bitsPerSample:8,samplesPerPixel:4,hasAlpha:true,isPlanar:false,colorSpaceName:.deviceRGB,bytesPerRow:0,bitsPerPixel:0))
  let graphics=try XCTUnwrap(NSGraphicsContext(bitmapImageRep:image));NSGraphicsContext.saveGraphicsState()
  graphics.cgContext.translateBy(x:0,y:288);graphics.cgContext.scaleBy(x:2,y:-2);NSGraphicsContext.current=NSGraphicsContext(cgContext:graphics.cgContext,flipped:true)
  var placements:[CGRect]=[]
  for row in 0..<3 {
   let y=CGFloat(row*48),window=CGRect(x:0,y:y,width:600,height:700)
   (row==0 ? NSColor(calibratedWhite:0.94,alpha:1):NSColor(calibratedWhite:0.22,alpha:1)).setFill();NSRect(x:0,y:y,width:600,height:48).fill()
   let lights=(0..<3).map{CGRect(x:14+CGFloat($0*20),y:y+18,width:12,height:12)}
   for (i,color) in [NSColor.systemRed,NSColor.systemYellow,NSColor.systemGreen].enumerated(){color.setFill();NSBezierPath(ovalIn:lights[i]).fill()}
   let tab=CGRect(x:row==2 ? 76:80,y:y,width:row==2 ? 524:240,height:44)
   NSColor(calibratedWhite:row==0 ? 0.82:0.32,alpha:1).setFill();NSBezierPath(roundedRect:tab,xRadius:7,yRadius:7).fill()
   let placement=try XCTUnwrap(ControlBadgeGeometry.freeHeaderFrame(window:window,trafficLights:lights,occupied:[tab]));placements.append(placement);XCTAssertFalse(placement.intersects(tab))
   NSGraphicsContext.saveGraphicsState();graphics.cgContext.translateBy(x:placement.minX,y:placement.minY)
   let view=AutomationControlBadgeView(frame:CGRect(origin:.zero,size:placement.size));view.active=row==0;view.draw(view.bounds);XCTAssertNil(view.hitTest(NSPoint(x:10,y:8)))
   NSGraphicsContext.restoreGraphicsState()
  }
  NSGraphicsContext.restoreGraphicsState()
  // Sample inside the monitor, not outside the entire mark. Its interior must
  // retain dark header pixels rather than an opaque white under-stroke plate.
  let dark=placements[1]
  let interior=try XCTUnwrap(image.colorAt(x:Int((dark.minX+29)*2),y:Int((dark.minY+8)*2))?.usingColorSpace(.deviceRGB))
  XCTAssertLessThan(interior.redComponent,0.40);XCTAssertLessThan(interior.greenComponent,0.40);XCTAssertLessThan(interior.blueComponent,0.40)
  XCTAssertEqual(placements[2].size,CGSize(width:22,height:12))
  let path=ProcessInfo.processInfo.environment["MECHANIZE_BADGE_PREVIEW"] ?? "/private/tmp/mechanize-compact-badge-header.png"
  try XCTUnwrap(image.representation(using:.png,properties:[:])).write(to:URL(fileURLWithPath:path),options:.atomic)
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
