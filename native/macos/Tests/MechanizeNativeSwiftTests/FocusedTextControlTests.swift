import Testing
import AppKit
import ApplicationServices
@testable import MechanizeNative

struct FocusedTextControlTests {
    @Test func textMetadataRequiresPositiveNonsecureClassificationAndNeverReadsValues() {
        for mode in ["field","area","longName","secure","disabled","numericEnabled","unknownEnabled","missingSubrole","badRole","missingLabels","protectedName","titleFailure"] {
            let e=AXUIElementCreateApplication(42)
            let result=readFocusedTextControl(e,read:{_,attribute in
                switch attribute {
                case kAXRoleAttribute:return (.success,(mode=="badRole" ? kAXLayoutAreaRole : mode=="field" ? kAXTextFieldRole : kAXTextAreaRole) as CFString)
                case kAXEnabledAttribute:
                    if mode=="unknownEnabled"{return (.noValue,nil)}
                    if mode=="numericEnabled"{return (.success,NSNumber(value:1))}
                    return (.success,mode=="disabled" ? kCFBooleanFalse : kCFBooleanTrue)
                case kAXSubroleAttribute:
                    if mode=="missingSubrole"{return (.cannotComplete,nil)}
                    return mode=="secure" ? (.success,kAXSecureTextFieldSubrole as CFString) : (.noValue,nil)
                case kAXIdentifierAttribute:return (.success,(mode=="missingLabels" ? "" : "editor") as CFString)
                case kAXTitleAttribute:
                    if mode=="titleFailure"{return (.cannotComplete,nil)}
                    return (.success,(mode=="protectedName" ? "Password" : mode=="missingLabels" ? "" : mode=="longName" ? String(repeating:"a",count:513) : "Public editor") as CFString)
                case kAXDescriptionAttribute:return (.noValue,nil)
                default:Issue.record("Unexpected metadata/value read");return (.noValue,nil)
                }
            })
            #expect((result != nil)==["field","area","longName"].contains(mode))
        }
    }
}
