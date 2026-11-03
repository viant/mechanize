import AppKit
import Testing
@testable import MechanizeNative

struct FocusedSessionWindowTests {
    let bounds=CGRect(x:10,y:20,width:800,height:600)
    func row(_ id:UInt32=7,_ title:String?="Draft copy",layer:Int=0)->SessionKeyWindow {
        SessionKeyWindow(id:id,pid:42,layer:layer,visible:true,alpha:1,bounds:bounds,title:title)
    }
    func focus(pid:pid_t=42,uid:uid_t=502,birth:String="birth",bundle:String="com.example.Editor",title:String="Draft copy",rect:CGRect?=nil)->FocusedSessionWindow {
        FocusedSessionWindow(pid:pid,uid:uid,birth:birth,bundle:bundle,title:title,bounds:rect ?? bounds)
    }
    func matches(_ rows:[SessionKeyWindow],_ f:FocusedSessionWindow?)->Bool {
        focusedSessionWindowMatches(rows,pid:42,uid:502,birth:"birth",bundle:"com.example.Editor",windowID:7,focused:f)
    }
    @Test func exactFocusDistinguishesOverlappingDocumentsBehindTooltip() {
        let rows=[row(8,"Tooltip",layer:101),row(9,"Other document"),row()]
        #expect(matches(rows,focus()))
        #expect(!matches(rows,nil))
        #expect(!matches(rows,focus(title:"Other document")))
        #expect(!matches([row(),row(9)],focus()))
        #expect(!matches([row(),row()],focus()))
        #expect(!matches([row(7,nil)],focus()))
    }
    @Test func changedIdentityAndGeometryNeverSelectAWindow() {
        for f in [focus(pid:99),focus(uid:503),focus(birth:"new"),focus(bundle:"com.example.Other"),focus(title:""),focus(rect:CGRect(x:12,y:20,width:800,height:600))] {
            #expect(!matches([row()],f))
        }
        #expect(!matches([row(7,"Draft copy",layer:101)],focus()))
        let invalid=SessionKeyWindow(id:8,pid:42,layer:101,visible:true,alpha:.nan,bounds:bounds,title:"Tooltip")
        #expect(!matches([invalid,row()],focus()))
    }
    @Test func keyboardQualificationRechecksFocusedWindowBeforeReturning() throws {
        var reads=0
        var runtime=WindowSessionKeyRuntime(process:{_ in (502,"birth","com.example.Editor")},foreground:{42},windows:{[row(8,"Tooltip",layer:101),row()]},session:{true},secure:{false})
        runtime.focusedWindow={_ in reads+=1;return focus()}
        try qualifyWindowSessionKey(pid:42,uid:502,birth:"birth",bundle:"com.example.Editor",windowID:7,check:{},runtime:runtime)
        #expect(reads==2)
        reads=0
        runtime.focusedWindow={_ in reads+=1;return reads==1 ? focus():focus(title:"Different document")}
        #expect(throws:(any Error).self){try qualifyWindowSessionKey(pid:42,uid:502,birth:"birth",bundle:"com.example.Editor",windowID:7,check:{},runtime:runtime)}
        #expect(reads==2)
    }
}
