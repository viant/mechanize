import XCTest
import AppKit
import ImageIO
@testable import MechanizeNative
import MechanizeNativeCore

final class WindowFrameClickTests: XCTestCase {
    let bounds = CGRect(x:100,y:100,width:100,height:100)
    func permit() throws -> WindowFramePermit {
        try WindowFramePermit(id:String(repeating:"b",count:32),owner:WindowFrameOwner(["namespace":String(repeating:"a",count:64),"clientId":"c","sessionId":"s"]),helperEpoch:"e",fenceGeneration:2,bundleId:"com.fixture.app",pid:42,processStartToken:"100:1",windowId:99,displayId:1,bounds:bounds,widthPixels:100,heightPixels:100,scale:1,contentHash:String(repeating:"c",count:64),capturedAt:Date(),uptime:100)
    }
    func window(_ id: UInt32 = 99, pid: Int32 = 42, alpha: Double = 1, bounds: CGRect? = nil) -> SessionKeyWindow {
        SessionKeyWindow(id:id,pid:pid,layer:0,visible:true,alpha:alpha,bounds:bounds ?? self.bounds)
    }
    func runtime(_ rows:[SessionKeyWindow], secure:Bool=false, foreground:Int32=42,birth:String="100:1",display:CGRect?=CGRect(x:0,y:0,width:1000,height:1000)) -> WindowFrameClickRuntime {
        WindowFrameClickRuntime(window:WindowSessionKeyRuntime(process:{_ in (501,birth,"com.fixture.app")},foreground:{foreground},windows:{rows},session:{true},secure:{secure}),display:{_ in display})
    }
    func testExactOwnedPointAndConservativeOcclusion() throws {
        let p=try permit(), point=CGPoint(x:150,y:150)
        try qualifyWindowFramePoint(p,point:point,uid:501,check:{},runtime:runtime([window()]))
        for r in [runtime([window(1,pid:77),window()]),runtime([window(1,pid:77,alpha:0.001),window()]),runtime([window(alpha:0.5)]),runtime([window(bounds:CGRect(x:101,y:100,width:100,height:100))]),runtime([window()],secure:true),runtime([window()],foreground:77),runtime([window()],birth:"101:1"),runtime([window()],display:nil),runtime([window(),window()]),runtime([window(1,pid:77,bounds:CGRect(x:Double.nan,y:0,width:10,height:10)),window()])] {
            XCTAssertThrowsError(try qualifyWindowFramePoint(p,point:point,uid:501,check:{},runtime:r))
        }
        XCTAssertThrowsError(try qualifyWindowFramePoint(p,point:point,uid:501,check:{},runtime:runtime([window(1,pid:77,alpha:0),window()])))
        try qualifyWindowFramePoint(p,point:point,uid:501,check:{},runtime:runtime([window(),window(1,pid:77,alpha:0)]))
        XCTAssertThrowsError(try qualifyWindowFramePoint(p,point:point,uid:501,check:{throw NativeFailure("cancelled","Cancelled")},runtime:runtime([window()])))
    }
    func image(_ color:CGColor,width:Int=100,height:Int=100) -> CGImage {
        let c=CGContext(data:nil,width:width,height:height,bitsPerComponent:8,bytesPerRow:width*4,space:CGColorSpace(name:CGColorSpace.sRGB)!,bitmapInfo:CGImageAlphaInfo.premultipliedLast.rawValue)!
        c.setFillColor(color); c.fill(CGRect(x:0,y:0,width:width,height:height)); return c.makeImage()!
    }
    func testBoundedExactPixelPatchRejectsContentChange() throws {
        let original=image(CGColor(red:1,green:0,blue:0,alpha:1))
        for (x,y) in [(0,0),(50,50),(99,99)] {
            let rect=try windowFramePatch(x:x,y:y,width:100,height:100)
            XCTAssertLessThanOrEqual(rect.width,64); XCTAssertLessThanOrEqual(rect.height,64); XCTAssertTrue(CGRect(x:0,y:0,width:100,height:100).contains(rect))
            try requireWindowFramePatch(original,current:original.cropping(to:rect)!,rect:rect,x:x,y:y)
            XCTAssertThrowsError(try requireWindowFramePatch(original,current:image(CGColor(red:0,green:1,blue:0,alpha:1),width:Int(rect.width),height:Int(rect.height)),rect:rect,x:x,y:y))
        }
        let transparent = image(CGColor(red:1,green:0,blue:0,alpha:0.5))
        let rect = try windowFramePatch(x:50,y:50,width:100,height:100)
        XCTAssertThrowsError(try requireWindowFramePatch(transparent,current:transparent.cropping(to:rect)!,rect:rect,x:50,y:50)) { error in
            XCTAssertEqual((error as? NativeFailure)?.code,"windowClickTransparent")
        }
        let inputs=InputSafety();inputs.enable();var downs=0
        XCTAssertThrowsError(try postWindowFrameClick(inputs:inputs,point:.zero,preflight:{try requireWindowFramePatch(transparent,current:transparent.cropping(to:rect)!,rect:rect,x:50,y:50)},willPost:{},down:{downs += 1;return true},up:{true}))
        XCTAssertEqual(downs,0)
        XCTAssertThrowsError(try windowFramePatch(x:100,y:0,width:100,height:100))
        XCTAssertThrowsError(try windowFrameRGBA(original))
    }
    func testPatchChangePreventsDownAndSingleClickReleasesWithoutRetargeting() throws {
        let inputs=InputSafety(); inputs.enable(); var downs=0,ups=0,attempts=0
        XCTAssertThrowsError(try postWindowFrameClick(inputs:inputs,point:CGPoint(x:1,y:1),preflight:{throw NativeFailure("staleCapture","Changed")},willPost:{attempts += 1},down:{downs += 1;return true},up:{ups += 1;return true}))
        XCTAssertEqual(downs,0); XCTAssertEqual(attempts,0)
        try postWindowFrameClick(inputs:inputs,point:CGPoint(x:1,y:1),preflight:{},willPost:{attempts += 1},down:{downs += 1;return true},up:{ups += 1;return true})
        XCTAssertEqual(downs,1); XCTAssertEqual(ups,1); XCTAssertEqual(attempts,1)
        XCTAssertEqual(inputs.inhibitAndRelease().unknown,0)
    }
    func testLargeUnscaledPNGAndExact32MiBBudget() throws {
        let width=800,height=600
        var bytes=[UInt8](repeating:0,count:width*height*4)
        var state:UInt64=0x123456789abcdef
        for offset in stride(from:0,to:bytes.count,by:4) {
            for component in 0..<3 { state ^= state<<13;state ^= state>>7;state ^= state<<17;bytes[offset+component]=UInt8(truncatingIfNeeded:state) }
            bytes[offset+3]=255
        }
        let image=bytes.withUnsafeMutableBytes { raw -> CGImage in
            CGContext(data:raw.baseAddress,width:width,height:height,bitsPerComponent:8,bytesPerRow:width*4,space:CGColorSpace(name:CGColorSpace.sRGB)!,bitmapInfo:CGImageAlphaInfo.premultipliedLast.rawValue)!.makeImage()!
        }
        let png=try encodeWindowFramePNG(image)
        XCTAssertGreaterThan(png.count,1024*1024)
        let source=try XCTUnwrap(CGImageSourceCreateWithData(png as CFData,nil))
        let restored=try XCTUnwrap(CGImageSourceCreateImageAtIndex(source,0,nil))
        XCTAssertEqual(restored.width,width);XCTAssertEqual(restored.height,height)
        try requireWindowFramePNGSize(32*1024*1024)
        XCTAssertThrowsError(try requireWindowFramePNGSize(32*1024*1024+1))
        XCTAssertThrowsError(try requireWindowFramePNGSize(0))
    }
    func testUnauthorizedHelperCannotMintOrDispatchAndClosedParamsReject() async throws {
        let helper = Helper(brokerAuthenticated: false)
        let owner: [String:Any] = ["namespace": String(repeating:"a",count:64),"clientId":"c","sessionId":"s"]
        var params: [String:Any] = ["expectedApp":"com.fixture.app","pid":42,"processStartToken":"100:1","windowId":99,"owner":owner]
        func request(_ method: String, _ params: [String:Any]) -> [String:Any] {
            ["protocolVersion":1,"requestId":UUID().uuidString,"helperEpoch":helper.epoch,"deadlineRemainingMs":1000,"method":method,"params":params]
        }
        let denied = await helper.handle(request("windows.captureFrame",params))
        XCTAssertEqual((denied["error"] as? [String:Any])?["code"] as? String,"staleLease");XCTAssertNil(denied["result"])
        params["rawGlobalX"] = 100
        let closed = await helper.handle(request("windows.captureFrame",params))
        XCTAssertEqual((closed["error"] as? [String:Any])?["code"] as? String,"invalidScope")
        let click = await helper.handle(request("windows.clickFrame",["expectedApp":"com.fixture.app","pid":42,"processStartToken":"100:1","owner":owner,"permitId":String(repeating:"b",count:32),"x":0,"y":0]))
        XCTAssertEqual((click["error"] as? [String:Any])?["dispatchState"] as? String,"notDispatched");XCTAssertNil(click["result"])
        XCTAssertEqual((click["error"] as? [String:Any])?["code"] as? String,"mutationDisabled")
    }
    func testFailedReleaseRetainsCleanupNeverRepeatsDownAndImageStoreBurns() throws {
        let inputs=InputSafety();inputs.enable();var downs=0,ups=0
        XCTAssertThrowsError(try postWindowFrameClick(inputs:inputs,point:.zero,preflight:{},willPost:{},down:{downs += 1;return true},up:{ups += 1;return false}))
        XCTAssertEqual(inputs.inhibitAndRelease().unknown,1);XCTAssertEqual(downs,1);XCTAssertEqual(ups,2)
        let store=WindowFrameImageStore();store.install("p",image(CGColor(gray:0,alpha:1)));_ = try store.take("p");XCTAssertThrowsError(try store.take("p"))
        store.install("p",image(CGColor(gray:0,alpha:1)));store.clear();XCTAssertThrowsError(try store.take("p"))
    }
}
