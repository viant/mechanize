import Testing
import AppKit
import ApplicationServices
@testable import MechanizeNative

struct TextSelectionReadTests {
    @Test func fullSelectionIsPositiveOnlyForStableNonemptyText() throws {
        for mode in ["full","partial","caret","empty","missing","invalid","negative","countChanged","rangeChanged","secure","roleChanged"] {
            let element=AXUIElementCreateApplication(42)
            var counts=0,ranges=0,roles=0,revalidations=0
            let runtime=NativeTextRuntime(attribute:{_,name in
                switch name {
                case kAXRoleAttribute:roles+=1;return (.success,(mode=="roleChanged" && roles>2 ? kAXButtonRole : kAXTextAreaRole) as CFString)
                case kAXSubroleAttribute:return mode=="secure" ? (.success,kAXSecureTextFieldSubrole as CFString) : (.noValue,nil)
                case kAXTitleAttribute:return (.success,"Public editor" as CFString)
                case kAXIdentifierAttribute:return (.success,"editor" as CFString)
                case kAXNumberOfCharactersAttribute:counts+=1;return (.success,NSNumber(value:mode=="empty" ? 0 : mode=="countChanged" && counts>1 ? 5 : 4))
                case kAXSelectedTextRangeAttribute:
                    ranges+=1
                    if mode=="missing" {return (.noValue,nil)}
                    var range=CFRange(location:mode=="negative" ? -1 : mode=="caret" ? 2 : 0,length:mode=="empty" || mode=="caret" ? 0 : mode=="invalid" ? 5 : mode=="partial" || mode=="rangeChanged" && ranges>1 ? 2 : 4)
                    return (.success,AXValueCreate(.cfRange,&range))
                default:Issue.record("Unexpected text/value read");return (.noValue,nil)
                }
            },settable:{_,_ in Issue.record("Read probed setters");return (.failure,false)},set:{_,_,_ in Issue.record("Selection mutated");return .failure})
            if ["full","partial","caret","empty"].contains(mode) {
                let selected=try nativeHasFullTextSelection(element,revalidate:{revalidations+=1},runtime:runtime)
                #expect(selected == (mode=="full"));#expect(revalidations>=4)
            } else {
                #expect(throws:(any Error).self){try nativeHasFullTextSelection(element,revalidate:{revalidations+=1},runtime:runtime)}
            }
        }
    }
    @Test func lostScopeCannotPublishSelection() {
        let element=AXUIElementCreateApplication(42)
        let runtime=NativeTextRuntime(attribute:{_,_ in Issue.record("Read after lost scope");return (.noValue,nil)},settable:{_,_ in (.failure,false)},set:{_,_,_ in .failure})
        #expect(throws:(any Error).self){try nativeHasFullTextSelection(element,revalidate:{throw NSError(domain:"fixture",code:1)},runtime:runtime)}
    }
}
