import AppKit
import ApplicationServices

// AX keyboard focus, rather than visual stacking alone, identifies the key
// recipient when an application has a floating non-key window. This proof never
// selects a different requested physical window or accepts a title alone.
struct FocusedSessionWindow {
    let pid:pid_t, uid:uid_t
    let birth:String, bundle:String, title:String
    let bounds:CGRect
}
private func finiteWindowBounds(_ r:CGRect)->Bool {
    [r.minX,r.minY,r.width,r.height,r.maxX,r.maxY].allSatisfy{$0.isFinite} && r.width>0 && r.height>0
}
private func sameWindowBounds(_ a:CGRect,_ b:CGRect)->Bool {
    finiteWindowBounds(a) && finiteWindowBounds(b) && abs(a.minX-b.minX)<=1 && abs(a.minY-b.minY)<=1 && abs(a.width-b.width)<=1 && abs(a.height-b.height)<=1
}
func focusedSessionWindowMatches(_ rows:[SessionKeyWindow],pid:pid_t,uid:uid_t,birth:String,bundle:String,windowID:UInt32,focused:FocusedSessionWindow?)->Bool {
    guard rows.count<=1000,let f=focused,f.pid==pid,f.uid==uid,f.birth==birth,f.bundle==bundle,
          !f.title.isEmpty,f.title.utf8.count<=4096,f.title.rangeOfCharacter(from:.controlCharacters)==nil,finiteWindowBounds(f.bounds),
          rows.filter({$0.id==windowID}).count==1,
          rows.filter({$0.pid==pid && $0.visible}).allSatisfy({$0.alpha.isFinite && $0.alpha>=0 && $0.alpha<=1}) else{return false}
    let matches=rows.filter{$0.pid==pid && $0.visible && $0.alpha>0 && supportedSessionInputWindowLayer($0.layer) && $0.title==f.title && sameWindowBounds($0.bounds,f.bounds)}
    return matches.count==1 && matches[0].id==windowID
}

func readFocusedSessionWindow(_ pid:pid_t)->FocusedSessionWindow? {
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
    let after=inspectAXElementOwner(window)
    guard after.status==before.status,after.pid==before.pid,after.uid==before.uid,after.birth==birth,after.bundle==bundle else{return nil}
    return FocusedSessionWindow(pid:pid,uid:getuid(),birth:birth,bundle:bundle,title:name,bounds:bounds)
}
