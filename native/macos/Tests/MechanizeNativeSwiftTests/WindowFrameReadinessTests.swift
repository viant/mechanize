import AppKit
import Testing
import MechanizeNativeCore
@testable import MechanizeNative

struct WindowFrameReadinessTests {
    let bounds=CGRect(x:100,y:100,width:100,height:100)
    func permit() throws -> WindowFramePermit {
        try WindowFramePermit(id:String(repeating:"b",count:32),owner:WindowFrameOwner(["namespace":String(repeating:"a",count:64),"clientId":"fixture","sessionId":"fixture"]),helperEpoch:"fixture",fenceGeneration:2,bundleId:"com.example.Editor",pid:42,processStartToken:"100:1",windowId:99,displayId:1,bounds:bounds,widthPixels:100,heightPixels:100,scale:1,contentHash:String(repeating:"c",count:64),capturedAt:Date(),uptime:100)
    }
    @Test func pointReadinessDistinguishesOcclusionFromUnavailableAuthority() throws {
        let permit=try permit(),point=CGPoint(x:150,y:150)
        for mode in ["target","occluded","unavailable","changed-geometry","changed-owner","cancelled"] {
            let rectangle=mode=="changed-geometry" ? CGRect(x:101,y:100,width:100,height:100):bounds
            let row=SessionKeyWindow(id:99,pid:42,layer:0,visible:true,alpha:1,bounds:rectangle)
            let window=WindowSessionKeyRuntime(process:{_ in (501,mode=="changed-owner" ? "100:2":"100:1","com.example.Editor")},foreground:{42},windows:{[row]},session:{true},secure:{false})
            var runtime=WindowFrameClickRuntime(window:window,display:{_ in CGRect(x:0,y:0,width:1000,height:1000)})
            runtime.mouseDownWindow={_ in mode=="unavailable" ? nil:mode=="occluded" ? 100:99}
            let read={try windowFramePointReadyForForeground(permit,point:point,uid:501,check:{if mode=="cancelled"{throw NativeFailure("cancelled","fixture")}},runtime:runtime)}
            if mode=="target" {#expect(try read())}
            else if mode=="occluded" {#expect(try !read())}
            else {#expect(throws:(any Error).self){try read()}}
        }
    }
    @Test func readinessDoesNotReplaceFinalPointerRecipientCheck() throws {
        let permit=try permit(),point=CGPoint(x:150,y:150)
        let row=SessionKeyWindow(id:99,pid:42,layer:0,visible:true,alpha:1,bounds:bounds)
        let window=WindowSessionKeyRuntime(process:{_ in (501,"100:1","com.example.Editor")},foreground:{42},windows:{[row]},session:{true},secure:{false})
        var recipient:UInt32=99,downs=0,ups=0
        var runtime=WindowFrameClickRuntime(window:window,display:{_ in CGRect(x:0,y:0,width:1000,height:1000)})
        runtime.mouseDownWindow={_ in recipient}
        #expect(try windowFramePointReadyForForeground(permit,point:point,uid:501,check:{},runtime:runtime))
        recipient=100
        let inputs=InputSafety();inputs.enable()
        #expect(throws:(any Error).self){
            try postWindowFrameClick(inputs:inputs,point:point,
                preflight:{try qualifyWindowFramePoint(permit,point:point,uid:501,check:{},runtime:runtime)},
                willPost:{},down:{downs += 1;return true},up:{ups += 1;return true})
        }
        #expect(downs==0);#expect(ups==0)
    }
}
