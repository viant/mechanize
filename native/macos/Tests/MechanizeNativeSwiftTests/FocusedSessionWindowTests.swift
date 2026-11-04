import AppKit
import Testing
import MechanizeNativeCore
@testable import MechanizeNative

struct FocusedSessionWindowTests {
    let bounds=CGRect(x:10,y:20,width:800,height:600)
    func row(_ id:UInt32=7,_ title:String?="Draft copy",layer:Int=0)->SessionKeyWindow {
        SessionKeyWindow(id:id,pid:42,layer:layer,visible:true,alpha:1,bounds:bounds,title:title)
    }
    func focus(pid:pid_t=42,uid:uid_t=502,birth:String="birth",bundle:String="com.example.Editor",title:String="Draft copy",rect:CGRect?=nil,verified:Bool=true)->FocusedSessionWindow {
        FocusedSessionWindow(pid:pid,uid:uid,birth:birth,bundle:bundle,title:title,bounds:rect ?? bounds,keyboardFocusVerified:verified)
    }
    func matches(_ rows:[SessionKeyWindow],_ f:FocusedSessionWindow?)->Bool {
        focusedSessionWindowMatches(rows,pid:42,uid:502,birth:"birth",bundle:"com.example.Editor",windowID:7,focused:f)
    }
    @Test func exactFocusDistinguishesOverlappingDocumentsBehindTooltip() {
        let rows=[row(8,"Tooltip",layer:101),row(),row(9,"Other document")]
        #expect(matches(rows,focus()))
        #expect(!matches(rows,nil))
        #expect(!matches(rows,focus(verified:false)))
        for layer in [0,3,8] { #expect(!matches([row(8,"Blocking window",layer:layer),row()],focus())) }
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


extension FocusedSessionWindowTests {
    @Test func topFloatingPanelNeedsStableExactKeyboardFocus() throws {
        let rows=[row(layer:NSWindow.Level.floating.rawValue),row(9,"Other document")]
        #expect(!NativeForegroundTarget.physicalWindowReady(rows,pid:42,windowID:7,pointerDelivery:false))
        #expect(NativeForegroundTarget.physicalWindowReady(rows,pid:42,windowID:7,pointerDelivery:true))
        for mode in ["missing","other","unverified","changed","exact"] {
            var reads=0,downs=0,ups=0
            var runtime=WindowSessionKeyRuntime(process:{_ in (502,"birth","com.example.Editor")},foreground:{42},windows:{rows},session:{true},secure:{false})
            runtime.focusedWindow={_ in
                reads += 1
                if mode=="missing" {return nil}
                if mode=="other" || mode=="changed" && reads>1 {return focus(title:"Other document")}
                return focus(verified:mode != "unverified")
            }
            let inputs=InputSafety();inputs.enable()
            let post={
                try KeyboardPosting.press(inputs:inputs,token:"key:53",delivery:.session,
                    preflight:{try qualifyWindowSessionKey(pid:42,uid:502,birth:"birth",bundle:"com.example.Editor",windowID:7,check:{},runtime:runtime)},
                    down:{_ in downs += 1;return true},up:{_ in ups += 1;return true})
            }
            if mode=="exact" {try post();#expect(downs==1);#expect(ups==1)}
            else {#expect(throws:(any Error).self){try post()};#expect(downs==0);#expect(ups==0)}
            #expect(inputs.inhibitAndRelease().unknown==0)
        }
    }
    @Test func declaredTextFieldCanUseExactKeyboardProofPastNonKeyOverlay() throws {
        let plan=try WindowTextPlan(text:"fixture",role:"AXTextArea",identifier:"editor",name:"")
        var f=focus();f.textControl=FocusedTextControl(role:"AXTextArea",identifier:"editor",name:"Public editor")
        for layer in [0,3] {
            let rows=[row(8,"Owned overlay",layer:layer),row()]
            #expect(!matches(rows,f)) // Ordinary window shortcuts retain their barrier.
            #expect(focusedSessionWindowMatches(rows,pid:42,uid:502,birth:"birth",bundle:"com.example.Editor",windowID:7,focused:f,textPlan:plan))
            for control in [nil,FocusedTextControl(role:"AXLayoutArea",identifier:"editor",name:"Public editor"),FocusedTextControl(role:"AXTextArea",identifier:"other",name:"Public editor"),FocusedTextControl(role:"AXTextArea",identifier:"editor",name:"Password")] {
                var invalid=f;invalid.textControl=control
                #expect(!focusedSessionWindowMatches(rows,pid:42,uid:502,birth:"birth",bundle:"com.example.Editor",windowID:7,focused:invalid,textPlan:plan))
            }
            var unverified=focus(verified:false);unverified.textControl=f.textControl
            #expect(!focusedSessionWindowMatches(rows,pid:42,uid:502,birth:"birth",bundle:"com.example.Editor",windowID:7,focused:unverified,textPlan:plan))
        }
        #expect(!focusedSessionWindowMatches([row(8,"Modal",layer:8),row()],pid:42,uid:502,birth:"birth",bundle:"com.example.Editor",windowID:7,focused:f,textPlan:plan))
        let canvasPlan=try WindowTextPlan(text:"fixture",role:"AXLayoutArea",identifier:"",name:"Content Area")
        var canvas=focus(bundle:"com.microsoft.Excel");canvas.textControl=FocusedTextControl(role:"AXLayoutArea",identifier:"",name:"Content Area")
        #expect(!focusedSessionWindowMatches([row(8,"Owned overlay",layer:3),row()],pid:42,uid:502,birth:"birth",bundle:"com.microsoft.Excel",windowID:7,focused:canvas,textPlan:canvasPlan))
    }
    @Test func textQualificationRechecksDeclaredFieldAndNeverChangesWindow() throws {
        let plan=try WindowTextPlan(text:"fixture",role:"AXTextArea",identifier:"editor",name:"")
        var f=focus();f.textControl=FocusedTextControl(role:"AXTextArea",identifier:"editor",name:"Public editor")
        var reads=0
        var runtime=WindowSessionKeyRuntime(process:{_ in (502,"birth","com.example.Editor")},foreground:{42},windows:{[row(8,"Owned overlay",layer:3),row()]},session:{true},secure:{false})
        runtime.focusedTextWindow={_ in reads+=1;return f}
        try qualifyWindowSessionKey(pid:42,uid:502,birth:"birth",bundle:"com.example.Editor",windowID:7,check:{},runtime:runtime,textPlan:plan)
        #expect(reads==2)
        #expect(throws:(any Error).self){try qualifyWindowSessionKey(pid:42,uid:502,birth:"birth",bundle:"com.example.Editor",windowID:7,check:{},runtime:runtime)}
        reads=0
        runtime.focusedTextWindow={_ in reads+=1;var result=f;if reads>1{result.textControl=FocusedTextControl(role:"AXTextArea",identifier:"changed",name:"Public editor")};return result}
        #expect(throws:(any Error).self){try qualifyWindowSessionKey(pid:42,uid:502,birth:"birth",bundle:"com.example.Editor",windowID:7,check:{},runtime:runtime,textPlan:plan)}
        #expect(reads==2)
    }
}
