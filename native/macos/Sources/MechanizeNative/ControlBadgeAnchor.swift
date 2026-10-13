import AppKit
import ApplicationServices
import MechanizeNativeCore

// Reads only owner, role and bounds in the exact native window's header.
// AXWebArea is opaque: no DOM descendants, titles, labels, URLs or values.
struct ControlBadgeAnchor: Equatable {
    let headerCenter: CGFloat
    let leading: CGFloat
    var size:CGSize = CGSize(width:46,height:18)
    static func measure(pid:pid_t,bounds:CGRect)->ControlBadgeAnchor? {
        guard AXIsProcessTrusted() else{return nil}
        let deadline=ProcessInfo.processInfo.systemUptime+0.15
        func read(_ element:AXUIElement,_ name:String)->CFTypeRef? {
            guard ProcessInfo.processInfo.systemUptime<deadline else{return nil}
            AXUIElementSetMessagingTimeout(element,0.02)
            var value:CFTypeRef?
            guard AXUIElementCopyAttributeValue(element,name as CFString,&value) == .success else{return nil}
            return value
        }
        func ownedBounds(_ element:AXUIElement)->CGRect? {
            var owner:pid_t=0
            guard AXUIElementGetPid(element,&owner) == .success,owner==pid,
                  let p=read(element,kAXPositionAttribute),let s=read(element,kAXSizeAttribute),CFGetTypeID(p)==AXValueGetTypeID(),CFGetTypeID(s)==AXValueGetTypeID() else{return nil}
            var point=CGPoint.zero,size=CGSize.zero
            guard AXValueGetValue(p as! AXValue,.cgPoint,&point),AXValueGetValue(s as! AXValue,.cgSize,&size),[point.x,point.y,size.width,size.height].allSatisfy({$0.isFinite}),size.width>0,size.height>0 else{return nil}
            return CGRect(origin:point,size:size)
        }
        let app=AXUIElementCreateApplication(pid)
        // Header presentation belongs to the app's actual focused window.
        // An AXWindows geometry census is ambiguous for overlapping IDE windows.
        guard NSWorkspace.shared.frontmostApplication?.processIdentifier == pid,
              let focused=read(app,kAXFocusedWindowAttribute),CFGetTypeID(focused)==AXUIElementGetTypeID(),
              let frame=ownedBounds(focused as! AXUIElement),
              abs(frame.minX-bounds.minX)<=2,abs(frame.minY-bounds.minY)<=2,
              abs(frame.width-bounds.width)<=2,abs(frame.height-bounds.height)<=2 else{return nil}
        let window=focused as! AXUIElement,header=CGRect(x:bounds.minX,y:bounds.minY,width:bounds.width,height:44)
        var lights:[CGRect]=[]
        for name in [kAXCloseButtonAttribute,kAXMinimizeButtonAttribute,kAXZoomButtonAttribute] {
            guard let value=read(window,name),CFGetTypeID(value)==AXUIElementGetTypeID(),let frame=ownedBounds(value as! AXUIElement),header.contains(frame) else{return nil}
            lights.append(frame)
        }
        var occupied:[CGRect]=[]
        func placement(_ coverageComplete:Bool)->ControlBadgeAnchor? {
            guard let frame=ControlBadgeGeometry.presentationHeaderFrame(window:bounds,trafficLights:lights,occupied:occupied,coverageComplete:coverageComplete) else{return nil}
            return ControlBadgeAnchor(headerCenter:frame.midY-bounds.minY,leading:frame.minX-bounds.minX,size:frame.size)
        }
        func incomplete()->ControlBadgeAnchor? {
            return placement(false)
        }
        guard let children=read(window,kAXChildrenAttribute) as? [AXUIElement] else{return incomplete()}
        var queue=children.map{($0,0)},seen=0
        while !queue.isEmpty {
            guard seen<128,ProcessInfo.processInfo.systemUptime<deadline else{return incomplete()}
            let (element,depth)=queue.removeFirst();seen+=1
            guard let frame=ownedBounds(element) else{return incomplete()}
            if !frame.intersects(header){continue}
            guard let role=read(element,kAXRoleAttribute) as? String else{return incomplete()}
            if role=="AXWebArea" {occupied.append(frame);continue}
            if ["AXGroup","AXToolbar","AXTabGroup","AXSplitGroup","AXScrollArea"].contains(role),depth<6 {
                guard let nested=read(element,kAXChildrenAttribute) as? [AXUIElement],nested.count+queue.count+seen<=128 else{return incomplete()}
                if !nested.isEmpty {queue.append(contentsOf:nested.map{($0,depth+1)});continue}
            }
            occupied.append(frame)
        }
        return placement(ProcessInfo.processInfo.systemUptime<deadline)
    }
}
