import XCTest
import AppKit
@testable import MechanizeNative

final class AutomationPointerRenderingTests: XCTestCase {
    func testModestScalePreservesExactCursorHotspot() {
        let geometry=AutomationPointerGeometry(imageSize:CGSize(width:17,height:25),hotSpot:CGPoint(x:2,y:3))
        XCTAssertEqual(AutomationPointerGeometry.scale,1.4)
        XCTAssertEqual(geometry.size.width,23.8,accuracy:0.001);XCTAssertEqual(geometry.size.height,35,accuracy:0.001)
        for point in [CGPoint(x:100,y:200),CGPoint(x:-800,y:1200)] {
            let frame=geometry.frame(at:point)
            XCTAssertEqual(frame.minX+geometry.hotSpot.x,point.x,accuracy:0.001)
            XCTAssertEqual(frame.maxY-geometry.hotSpot.y,point.y,accuracy:0.001)
        }
    }
    func testNativeArrowRendersOffscreenWithoutLargeRedHalo() throws {
        // Match helper startup's AppKit connection, without activation/windows.
        _ = NSApplication.shared.setActivationPolicy(.accessory)
        let view=AutomationPointerView(),size=view.bounds.size
        XCTAssertEqual(size.width,NSCursor.arrow.image.size.width*1.4,accuracy:0.001)
        XCTAssertEqual(size.height,NSCursor.arrow.image.size.height*1.4,accuracy:0.001)
        XCTAssertGreaterThan(size.width,0);XCTAssertGreaterThan(size.height,0)
        // An unattached view has no backing store. Supply a Retina bitmap and
        // flipped graphics context explicitly; never create/show a test window.
        let bitmap=try XCTUnwrap(NSBitmapImageRep(bitmapDataPlanes:nil,pixelsWide:Int(ceil(size.width*2)),pixelsHigh:Int(ceil(size.height*2)),bitsPerSample:8,samplesPerPixel:4,hasAlpha:true,isPlanar:false,colorSpaceName:.deviceRGB,bytesPerRow:0,bitsPerPixel:0))
        let graphics=try XCTUnwrap(NSGraphicsContext(bitmapImageRep:bitmap))
        NSGraphicsContext.saveGraphicsState()
        graphics.cgContext.translateBy(x:0,y:CGFloat(bitmap.pixelsHigh));graphics.cgContext.scaleBy(x:2,y:-2)
        NSGraphicsContext.current=NSGraphicsContext(cgContext:graphics.cgContext,flipped:true)
        view.draw(view.bounds)
        NSGraphicsContext.restoreGraphicsState()
        var painted=0,antialiased=0,red=0
        for y in 0..<bitmap.pixelsHigh {for x in 0..<bitmap.pixelsWide {
            let color=try XCTUnwrap(bitmap.colorAt(x:x,y:y)?.usingColorSpace(.deviceRGB))
            if color.alphaComponent>0 {painted += 1}
            if color.alphaComponent>0&&color.alphaComponent<0.99 {antialiased += 1}
            if color.alphaComponent>0.5&&color.redComponent>0.7&&color.greenComponent<0.35&&color.blueComponent<0.35 {red += 1}
        }}
        XCTAssertGreaterThan(painted,0);XCTAssertGreaterThan(antialiased,0);XCTAssertEqual(red,0)
        if let path=ProcessInfo.processInfo.environment["MECHANIZE_POINTER_PREVIEW"] {
            let png=try XCTUnwrap(bitmap.representation(using:.png,properties:[:]))
            try png.write(to:URL(fileURLWithPath:path),options:.atomic)
        }
    }
}
