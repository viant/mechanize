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
        for r in [runtime([window(1,pid:77),window()]),runtime([window(1,pid:77,alpha:0.001),window()]),runtime([window(alpha:0.5)]),runtime([window(bounds:CGRect(x:101,y:100,width:100,height:100))]),runtime([window()],secure:true),runtime([window()],birth:"101:1"),runtime([window()],display:nil),runtime([window(),window()]),runtime([window(1,pid:77,bounds:CGRect(x:Double.nan,y:0,width:10,height:10)),window()])] {
            XCTAssertThrowsError(try qualifyWindowFramePoint(p,point:point,uid:501,check:{},runtime:r))
        }
        XCTAssertThrowsError(try qualifyWindowFramePoint(p,point:point,uid:501,check:{},runtime:runtime([window(1,pid:77,alpha:0),window()])))
        try qualifyWindowFramePoint(p,point:point,uid:501,check:{},runtime:runtime([window(),window(1,pid:77,alpha:0)]))
        XCTAssertThrowsError(try qualifyWindowFramePoint(p,point:point,uid:501,check:{throw NativeFailure("cancelled","Cancelled")},runtime:runtime([window()])))
    }
    func testPublicMouseDownRecipientCanProveClickThroughOverlayWithoutWhitelisting() throws {
        let p = try permit(), point = CGPoint(x:150,y:150)
        var r = runtime([window(1,pid:77),window()])
        r.mouseDownWindow = { observed in XCTAssertEqual(observed,point); return 99 }
        try qualifyWindowFramePoint(p,point:point,uid:501,check:{},runtime:r)
        for recipient: UInt32? in [nil,0,1,100] {
            r.mouseDownWindow = { _ in recipient }
            XCTAssertThrowsError(try qualifyWindowFramePoint(p,point:point,uid:501,check:{},runtime:r))
        }
        r = runtime([window()])
        r.mouseDownWindow = { _ in nil }
        // Unavailable hit-testing must not fall back even when CG says target is first.
        XCTAssertThrowsError(try qualifyWindowFramePoint(p,point:point,uid:501,check:{},runtime:r))
        r.mouseDownWindow = { _ in throw NativeFailure("windowHitTestUnavailable","expired") }
        XCTAssertThrowsError(try qualifyWindowFramePoint(p,point:point,uid:501,check:{},runtime:r))
        for rows in [[window(pid:77)], [window(alpha:0.5)], [window(),window()],
                     [window(1,pid:77,bounds:CGRect(x:Double.nan,y:0,width:10,height:10)),window()]] {
            r = runtime(rows); r.mouseDownWindow = { _ in 99 }
            XCTAssertThrowsError(try qualifyWindowFramePoint(p,point:point,uid:501,check:{},runtime:r))
        }
    }
    func testChangedMouseDownRecipientBeforePostingSendsNoInput() throws {
        let p = try permit(), point = CGPoint(x:150,y:150)
        var r = runtime([window(1,pid:77),window()]), reads = 0, downs = 0, ups = 0, attempts = 0
        r.mouseDownWindow = { _ in reads += 1; return reads == 1 ? 99 : 1 }
        try qualifyWindowFramePoint(p,point:point,uid:501,check:{},runtime:r)
        let inputs=InputSafety();inputs.enable()
        XCTAssertThrowsError(try postWindowFrameClick(inputs:inputs,point:point,preflight:{
            try qualifyWindowFramePoint(p,point:point,uid:501,check:{},runtime:r)
        },willPost:{attempts += 1},down:{downs += 1;return true},up:{ups += 1;return true}))
        XCTAssertEqual(reads,2);XCTAssertEqual(downs,0);XCTAssertEqual(ups,0);XCTAssertEqual(attempts,0)
    }
    func testDeadlineAfterPointerMoveDoesNotClaimMouseDownDispatch() throws {
        let inputs=InputSafety();inputs.enable()
        var checks=0,moves=0,downs=0,attempts=0
        XCTAssertThrowsError(try postWindowFrameClick(inputs:inputs,point:.zero,preflight:{
            checks += 1
            if checks == 2 { throw NativeFailure("deadlineExceeded","expired") }
        },willPost:{attempts += 1},down:{downs += 1;return true},up:{true},move:{moves += 1})) { error in
            XCTAssertEqual((error as? NativeFailure)?.code,"deadlineExceeded")
        }
        XCTAssertEqual(moves,1);XCTAssertEqual(downs,0);XCTAssertEqual(attempts,0)
        // The safety lock is released, but the previous frame permit remains
        // consumed by its caller. A new action still requires a fresh capture.
        try postWindowFrameClick(inputs:inputs,point:.zero,preflight:{},willPost:{attempts += 1},down:{downs += 1;return true},up:{true})
        XCTAssertEqual(downs,1);XCTAssertEqual(attempts,1)
    }
    func testMouseDownCoordinateTransformIncludesAdjacentDisplaysAndRejectsUncertainty() throws {
        let primary=CGRect(x:0,y:0,width:1312,height:848)
        XCTAssertEqual(try appKitMouseDownPoint(CGPoint(x:696,y:400),primaryCG:primary,primaryAppKit:primary),CGPoint(x:696,y:448))
        XCTAssertEqual(try appKitMouseDownPoint(CGPoint(x:-100,y:-200),primaryCG:primary,primaryAppKit:primary),CGPoint(x:-100,y:1048))
        for screen in [CGRect(x:1,y:0,width:1312,height:848),CGRect(x:0,y:0,width:1312,height:849),.zero] {
            XCTAssertThrowsError(try appKitMouseDownPoint(CGPoint(x:696,y:400),primaryCG:primary,primaryAppKit:screen))
        }
        XCTAssertThrowsError(try appKitMouseDownPoint(CGPoint(x:Double.nan,y:400),primaryCG:primary,primaryAppKit:primary))
    }
    func testPositiveDiagnosticCannotAuthorizeAnOccludedClick() throws {
        var calls = 0
        var r = runtime([window(1, pid: 77), window()])
        r.diagnostic = { _, _ in
            calls += 1
            return "hitMatchesTargetOwner=true; hitWindowBoundsMatch=true; hitWindowNumberMatch=true"
        }
        XCTAssertThrowsError(try qualifyWindowFramePoint(permit(), point: CGPoint(x: 150, y: 150), uid: 501,
                                                         check: {}, runtime: r)) { error in
            XCTAssertEqual((error as? NativeFailure)?.code, "windowClickOccluded")
        }
        XCTAssertEqual(calls, 1)
    }
    func testCaptureDoesNotChooseAClickPointButClickStillRejectsOcclusion() throws {
        let p = try permit()
        let r = runtime([window(1, pid: 77, bounds: CGRect(x: 140, y: 140, width: 20, height: 20)), window()])
        try qualifyWindowFrameCapture(p, uid: 501, check: {}, runtime: r)
        XCTAssertThrowsError(try qualifyWindowFramePoint(p, point: CGPoint(x: 150, y: 150), uid: 501, check: {}, runtime: r))
        try qualifyWindowFramePoint(p, point: CGPoint(x: 110, y: 110), uid: 501, check: {}, runtime: r)
        for invalid in [runtime([window()], secure: true),
                        runtime([window()], display: nil), runtime([window()], birth: "101:1"),
                        runtime([window(), window()]), runtime([window(alpha: 0.5)]),
                        runtime([window(bounds: CGRect(x: 101, y: 100, width: 100, height: 100))])] {
            XCTAssertThrowsError(try qualifyWindowFrameCapture(p, uid: 501, check: {}, runtime: invalid))
        }
    }
    func image(_ color:CGColor,width:Int=100,height:Int=100) -> CGImage {
        let c=CGContext(data:nil,width:width,height:height,bitsPerComponent:8,bytesPerRow:width*4,space:CGColorSpace(name:CGColorSpace.sRGB)!,bitmapInfo:CGImageAlphaInfo.premultipliedLast.rawValue)!
        c.setFillColor(color); c.fill(CGRect(x:0,y:0,width:width,height:height)); return c.makeImage()!
    }
    func testFullWindowComparisonPreservesLocalPatchAndGeometryChecks() throws {
        let context = CGContext(data: nil, width: 100, height: 100, bitsPerComponent: 8,
            bytesPerRow: 400, space: CGColorSpace(name: CGColorSpace.sRGB)!,
            bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)!
        context.setFillColor(CGColor(red: 1, green: 1, blue: 1, alpha: 1))
        context.fill(CGRect(x: 0, y: 0, width: 100, height: 100))
        context.setFillColor(CGColor(red: 0, green: 0, blue: 0, alpha: 1))
        context.fill(CGRect(x: 44, y: 40, width: 12, height: 20))
        let original = context.makeImage()!
        try requireWindowFrameCurrentImage(original, current: original, x: 50, y: 50)
        XCTAssertThrowsError(try requireWindowFrameCurrentImage(original,
            current: image(CGColor(red: 1, green: 1, blue: 1, alpha: 1)), x: 50, y: 50))
        XCTAssertThrowsError(try requireWindowFrameCurrentImage(original,
            current: original.cropping(to: CGRect(x: 0, y: 0, width: 99, height: 100))!, x: 50, y: 50))
        XCTAssertThrowsError(try requireWindowFrameCurrentImage(original, current: original, x: 100, y: 50))
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
    func testBackgroundPointerKeepsKeyboardForegroundAndOcclusionChecks() throws {
        let p = try permit(), point = CGPoint(x:150,y:150)
        var r = runtime([window()],foreground:77)
        r.mouseDownWindow = { _ in 99 }
        try qualifyWindowFrameCapture(p,uid:501,check:{},runtime:r)
        try qualifyWindowFramePoint(p,point:point,uid:501,check:{},runtime:r)
        XCTAssertThrowsError(try qualifyWindowSessionKey(pid:42,uid:501,birth:"100:1",bundle:"com.fixture.app",windowID:99,check:{},runtime:r.window))
        r.mouseDownWindow = { _ in 1 }
        XCTAssertThrowsError(try qualifyWindowFramePoint(p,point:point,uid:501,check:{},runtime:r))
        r = runtime([window(1,pid:42),window()],foreground:77)
        r.mouseDownWindow = { _ in 99 }
        // A modal owned window still prevents input to the document underneath.
        XCTAssertThrowsError(try qualifyWindowFrameCapture(p,uid:501,check:{},runtime:r))
    }

    func testOcclusionReportsActualRecipientSeparatelyFromBoundingBox() throws {
        var r = runtime([window(16,pid:77),window(),window(101,pid:88)])
        r.mouseDownWindow = { _ in 101 }
        XCTAssertThrowsError(try qualifyWindowFramePoint(permit(),point:CGPoint(x:150,y:150),uid:501,check:{},runtime:r)) { error in
            let message = (error as? NativeFailure)?.message ?? ""
            XCTAssertTrue(message.contains("mouseDownWindowId=101"))
            XCTAssertTrue(message.contains("mouseDownOwnerPid=88"))
            XCTAssertTrue(message.contains("boundingBoxFrontWindowId=16"))
            XCTAssertTrue(message.contains("ownedMatches=true; hitMatches=false"))
        }
        r = runtime([window(bounds:CGRect(x:101,y:100,width:100,height:100))])
        r.mouseDownWindow = { _ in 99 }
        XCTAssertThrowsError(try qualifyWindowFramePoint(permit(),point:CGPoint(x:150,y:150),uid:501,check:{},runtime:r)) { error in
            XCTAssertTrue(((error as? NativeFailure)?.message ?? "").contains("ownedMatches=false; hitMatches=true"))
        }
    }

}
