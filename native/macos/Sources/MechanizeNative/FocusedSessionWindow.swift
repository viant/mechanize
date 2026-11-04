import AppKit
import ApplicationServices
import MechanizeNativeCore

// AX keyboard focus, rather than visual stacking alone, identifies the key
// recipient when an application has a floating non-key window. This proof never
// selects a different requested physical window or accepts a title alone.
struct FocusedSessionWindow {
    let pid:pid_t, uid:uid_t
    let birth:String, bundle:String, title:String
    let bounds:CGRect
    let keyboardFocusVerified:Bool
    var textControl: FocusedTextControl? = nil
}
private func finiteWindowBounds(_ r:CGRect)->Bool {
    [r.minX,r.minY,r.width,r.height,r.maxX,r.maxY].allSatisfy{$0.isFinite} && r.width>0 && r.height>0
}
private func sameWindowBounds(_ a:CGRect,_ b:CGRect)->Bool {
    finiteWindowBounds(a) && finiteWindowBounds(b) && abs(a.minX-b.minX)<=1 && abs(a.minY-b.minY)<=1 && abs(a.width-b.width)<=1 && abs(a.height-b.height)<=1
}
func focusedSessionWindowMatches(_ rows:[SessionKeyWindow],pid:pid_t,uid:uid_t,birth:String,bundle:String,windowID:UInt32,focused:FocusedSessionWindow?,textPlan:WindowTextPlan? = nil)->Bool {
    guard rows.count<=1000,let f=focused,f.keyboardFocusVerified,f.pid==pid,f.uid==uid,f.birth==birth,f.bundle==bundle,
          !f.title.isEmpty,f.title.utf8.count<=4096,f.title.rangeOfCharacter(from:.controlCharacters)==nil,finiteWindowBounds(f.bounds),
          rows.filter({$0.id==windowID}).count==1,
          rows.filter({$0.pid==pid && $0.visible}).allSatisfy({$0.alpha.isFinite && $0.alpha>=0 && $0.alpha<=1}) else{return false}
    guard let requestedIndex=rows.firstIndex(where:{$0.id==windowID}) else{return false}
    // Stacking remains a barrier unless the declared field has the exact
    // keyboard-recipient proof below. An overlay never supplies authority.
    let preceding=rows[..<requestedIndex].filter{$0.pid==pid && $0.visible && $0.alpha>0}
    // A declared text field may use the same exact AX keyboard-recipient proof
    // as reference-addressed keys. This admits non-key owned overlays without
    // changing the requested window. Generic shortcuts and canvases stay strict;
    // modal-panel layers remain barriers even with the field proof.
    let textMatches = textPlan.map { plan in
        guard [kAXTextFieldRole,kAXTextAreaRole].contains(plan.focusRole) else { return false }
        return f.textControl.map { plan.permits(role:$0.role,identifier:$0.identifier,name:$0.name,bundle:bundle) } == true
    } == true
    guard preceding.allSatisfy({ !supportedSessionInputWindowLayer($0.layer) ||
        textMatches && [NSWindow.Level.normal.rawValue,NSWindow.Level.floating.rawValue].contains($0.layer) }) else{return false}
    let matches=rows.filter{$0.pid==pid && $0.visible && $0.alpha>0 && supportedSessionInputWindowLayer($0.layer) && $0.title==f.title && sameWindowBounds($0.bounds,f.bounds)}
    return matches.count==1 && matches[0].id==windowID
}

func readFocusedSessionWindow(_ pid:pid_t)->FocusedSessionWindow? {
    readFocusedSessionWindowProof(pid, includeTextFocus:false)
}
func readFocusedTextSessionWindow(_ pid:pid_t)->FocusedSessionWindow? {
    readFocusedSessionWindowProof(pid, includeTextFocus:true)
}
private func readFocusedSessionWindowProof(_ pid:pid_t,includeTextFocus:Bool)->FocusedSessionWindow? {
    let app=AXUIElementCreateApplication(pid)
    AXUIElementSetMessagingTimeout(app,0.05)
    func focused()->AXUIElement? {
        var raw:CFTypeRef?
        guard AXUIElementCopyAttributeValue(app,kAXFocusedWindowAttribute as CFString,&raw) == .success,let raw,CFGetTypeID(raw)==AXUIElementGetTypeID() else{return nil}
        return (raw as! AXUIElement)
    }
    guard let window=focused() else{return nil}
    AXUIElementSetMessagingTimeout(window,0.05)
    func title()->String? {var raw:CFTypeRef?;guard AXUIElementCopyAttributeValue(window,kAXTitleAttribute as CFString,&raw) == .success else{return nil};return raw as? String}
    var role:CFTypeRef?
    guard AXUIElementCopyAttributeValue(window,kAXRoleAttribute as CFString,&role) == .success,role as? String==kAXWindowRole,
          let name=title(),let bounds=AutomationPointer.windowBounds(element:window,pid:pid) else{return nil}
    let before=inspectAXElementOwner(window)
    guard before.status==AXError.success.rawValue,before.pid==pid,before.uid==getuid(),let birth=before.birth,let bundle=before.bundle,
          let afterWindow=focused(),CFEqual(window,afterWindow),title()==name,
          let afterBounds=AutomationPointer.windowBounds(element:window,pid:pid),bounds==afterBounds else{return nil}
    // Reuse the same element/window recipient proof as reference-addressed keys.
    // AXFocusedWindow alone can still name a parent while a menu/sheet owns input.
    var rawFocus:CFTypeRef?
    guard AXUIElementCopyAttributeValue(app,kAXFocusedUIElementAttribute as CFString,&rawFocus) == .success,
          let rawFocus,CFGetTypeID(rawFocus)==AXUIElementGetTypeID() else{return nil}
    let focus=rawFocus as! AXUIElement
    AXUIElementSetMessagingTimeout(focus,0.05)
    let textBefore = includeTextFocus ? readFocusedTextControl(focus) : nil
    do {
        let budget=try Budget(milliseconds:500)
        let recipient=try AXSemanticForegroundRecipient.bind(element:focus,application:app,pid:pid,uid:getuid(),birth:birth,bundle:bundle,menuRoot:false,budget:budget)
        guard recipient.sheetPath.isEmpty,let recipientWindow=recipient.window,CFEqual(recipientWindow,window),try recipient.keyboardFocused(budget) else{return nil}
    } catch {return nil}
    let after=inspectAXElementOwner(window)
    guard after.status==before.status,after.pid==before.pid,after.uid==before.uid,after.birth==birth,after.bundle==bundle else{return nil}
    let textAfter = includeTextFocus ? readFocusedTextControl(focus) : nil
    guard !includeTextFocus || textBefore == textAfter else { return nil }
    if includeTextFocus {
        var finalFocus: CFTypeRef?, isFocused: CFTypeRef?
        guard AXUIElementCopyAttributeValue(app,kAXFocusedUIElementAttribute as CFString,&finalFocus) == .success,
              let finalFocus, CFGetTypeID(finalFocus)==AXUIElementGetTypeID(), CFEqual(finalFocus,focus),
              AXUIElementCopyAttributeValue(focus,kAXFocusedAttribute as CFString,&isFocused) == .success,
              isFocused as? Bool == true, let finalWindow=focused(), CFEqual(window,finalWindow) else { return nil }
    }
    return FocusedSessionWindow(pid:pid,uid:getuid(),birth:birth,bundle:bundle,title:name,bounds:bounds,keyboardFocusVerified:true,textControl:textAfter)
}
