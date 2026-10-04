import ApplicationServices
import MechanizeNativeCore

func replacementClassification(_ ref: Reference) -> Bool {
    func read(_ name:String)->(AXError,CFTypeRef?) {var value:CFTypeRef?;let code=AXUIElementCopyAttributeValue(ref.element,name as CFString,&value);return(code,value)}
    let role=read(kAXRoleAttribute), subrole=read(kAXSubroleAttribute)
    let knownSubrole=(subrole.0 == .success && subrole.1 is String) || subrole.0 == .noValue || subrole.0 == .attributeUnsupported
    var settable:DarwinBoolean=false
    let settableCode=AXUIElementIsAttributeSettable(ref.element,kAXValueAttribute as CFString,&settable)
    let name=read(kAXTitleAttribute),identifier=read(kAXIdentifierAttribute)
    func known(_ code: AXError)->Bool { return code == .success || code == .noValue || code == .attributeUnsupported }
    let labelsKnown=known(name.0) && known(identifier.0)
    return labelsKnown && ReplacementProof.permitted(role:role.1 as? String,subrole:subrole.1 as? String,subroleKnown:knownSubrole,valueSettable:settableCode == .success ? settable.boolValue:nil,labels:[name.1 as? String ?? "",identifier.1 as? String ?? ""])
}
