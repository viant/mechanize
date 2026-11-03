import Testing
import AppKit
import ApplicationServices
@testable import MechanizeNative
import MechanizeNativeCore

struct FocusedRootTests {
    let pid: pid_t = 42000, uid: uid_t = 501
    let birth = "100:1", bundle = "com.fixture.editor"
    func owner(_ foreign: Bool = false) -> AXElementOwner {
        AXElementOwner(pid:foreign ? 77 : pid,uid:uid,birth:birth,bundle:bundle,status:AXError.success.rawValue)
    }
    @Test func focusedRootRequiresExactProcessAndCannotMixScopes() throws {
        let params: [String:Any] = ["rootScope":"focusedWindow","pid":42,"processStartToken":"100:1"]
        #expect(try NativeRootScope.requested(in:params,method:"elements.snapshot") == .focusedWindow)
        for key in ["pid","processStartToken"] {
            var missing=params; missing.removeValue(forKey:key)
            #expect(throws:NativeFailure.self){try NativeRootScope.requested(in:missing,method:"elements.snapshot")}
        }
        for pid in [0, -1, Int(Int32.max) + 1] {
            var invalid=params;invalid["pid"]=pid
            #expect(throws:NativeFailure.self){try NativeRootScope.requested(in:invalid,method:"elements.snapshot")}
        }
        for token in ["", "0:1", "100:-1", "100:9999999"] {
            var invalid=params;invalid["processStartToken"]=token
            #expect(throws:NativeFailure.self){try NativeRootScope.requested(in:invalid,method:"elements.snapshot")}
        }
        var mixed=params;mixed["windowScope"]=["title":"Fixture"]
        #expect(throws:NativeFailure.self){try NativeRootScope.requested(in:mixed,method:"elements.snapshot")}
        #expect(throws:NativeFailure.self){try NativeRootScope.requested(in:params,method:"windows.list")}
    }
    @Test func ownedWindowAndSheetAreRecheckedWithoutGlobalFallback() throws {
        for role in [kAXWindowRole,kAXSheetRole] {
            let app=AXUIElementCreateApplication(pid),root=AXUIElementCreateApplication(42001),other=AXUIElementCreateApplication(42002)
            var changed=false
            let runtime=ScopedNativeRootRuntime(attribute:{element,name in
                if CFEqual(element,app) {#expect(name == kAXFocusedWindowAttribute);return (.success,changed ? other : root)}
                #expect(name == kAXRoleAttribute);return (.success,role as CFString)
            },owner:{_ in owner()})
            let proof=try ScopedNativeRoot.resolve(.focusedWindow,application:app,pid:pid,uid:uid,birth:birth,bundle:bundle,check:{},runtime:runtime)
            try proof.validate(check:{},runtime:runtime)
            changed=true
            do {try proof.validate(check:{},runtime:runtime);Issue.record("Changed focused root accepted")}
            catch let failure as NativeFailure {#expect(failure.code == "staleFocus")}
        }
    }
    @Test func missingForeignAndNonWindowRootsCannotQualify() {
        for mode in ["missing","malformed","foreign","wrongRole"] {
            let app=AXUIElementCreateApplication(pid),root=AXUIElementCreateApplication(42001)
            let runtime=ScopedNativeRootRuntime(attribute:{element,name in
                if CFEqual(element,app) {
                    #expect(name == kAXFocusedWindowAttribute)
                    if mode == "missing" {return (.noValue,nil)}
                    if mode == "malformed" {return (.success,"invalid" as CFString)}
                    return (.success,root)
                }
                return (.success,(mode == "wrongRole" ? kAXGroupRole : kAXSheetRole) as CFString)
            },owner:{_ in owner(mode == "foreign")})
            #expect(throws:NativeFailure.self){try ScopedNativeRoot.resolve(.focusedWindow,application:app,pid:pid,uid:uid,birth:birth,bundle:bundle,check:{},runtime:runtime)}
        }
    }
    @Test func focusedSheetUsesSameAppChildProofWithoutAdoptingPanelService() throws {
        for absent in [false,true] {
            let app=AXUIElementCreateApplication(pid),sheet=AXUIElementCreateApplication(42001),child=AXUIElementCreateApplication(42002),helper=AXUIElementCreateApplication(42003)
            let runtime=ScopedNativeRootRuntime(attribute:{element,name in
                if name == kAXFocusedWindowAttribute {return (.success,sheet)}
                if name == kAXRoleAttribute {return (.success,(CFEqual(element,sheet) ? kAXSheetRole : kAXButtonRole) as CFString)}
                if name == kAXParentAttribute || name == kAXWindowAttribute {return (.success,helper)}
                Issue.record("Unexpected attribute");return (.noValue,nil)
            },owner:{element in
                if CFEqual(element,helper){return AXElementOwner(pid:77,uid:uid,birth:"100:2",bundle:"com.apple.appkit.xpc.openAndSavePanelService",status:AXError.success.rawValue)}
                return owner()
            },children:{element,check in
                try check();#expect(!CFEqual(element,helper))
                return BoundedSnapshotChildRead(elements:CFEqual(element,sheet) && !absent ? [child] : [],complete:true)
            })
            let proof=try ScopedNativeRoot.resolve(.focusedWindow,application:app,pid:pid,uid:uid,birth:birth,bundle:bundle,check:{},runtime:runtime)
            if absent {#expect(throws:NativeFailure.self){try proof.validate(referenceElement:child,check:{},runtime:runtime)}}
            else {
                try proof.validate(referenceElement:child,check:{},runtime:runtime)
                let recipient=try AXSemanticForegroundRecipient.bind(element:child,application:app,pid:pid,uid:uid,birth:birth,bundle:bundle,menuRoot:false,scopedWindow:proof,budget:Budget(milliseconds:1000),runtime:runtime)
                #expect(try recipient.focused(Budget(milliseconds:1000),runtime:runtime))
            }
        }
    }
}
