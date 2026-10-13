import AppKit
import QuartzCore
import ApplicationServices
import MechanizeNativeCore

// Presentation only. The marker never takes focus, receives input, stores page
// content, or grants authority. Its lifetime is bounded even if an action fails.
final class AutomationPointerPanel: NSPanel {
    override var canBecomeKey: Bool { false }
    override var canBecomeMain: Bool { false }
}

// Use the system arrow artwork at a modest logical scale. Presentation geometry
// preserves the native hotspot; it is never reused as input/hit-test geometry.
struct AutomationPointerGeometry {
    static let scale: CGFloat = 1.4
    let size: CGSize
    let hotSpot: CGPoint
    init(imageSize: CGSize, hotSpot: CGPoint) {
        size = CGSize(width:imageSize.width * Self.scale,height:imageSize.height * Self.scale)
        self.hotSpot = CGPoint(x:hotSpot.x * Self.scale,y:hotSpot.y * Self.scale)
    }
    func frame(at point: CGPoint) -> CGRect {
        CGRect(x:point.x-hotSpot.x,y:point.y-(size.height-hotSpot.y),width:size.width,height:size.height)
    }
}
final class AutomationPointerView: NSView {
    let arrow: NSImage
    init(arrow: NSImage = NSCursor.arrow.image) {
        self.arrow = arrow
        let geometry=AutomationPointerGeometry(imageSize:arrow.size,hotSpot:NSCursor.arrow.hotSpot)
        super.init(frame:CGRect(origin:.zero,size:geometry.size))
    }
    required init?(coder: NSCoder) { nil }
    override var isFlipped: Bool { true }
    override func draw(_ dirtyRect: NSRect) {
        guard let graphics=NSGraphicsContext.current else{return}
        graphics.imageInterpolation = .high
        graphics.cgContext.setShouldAntialias(true)
        arrow.draw(in:bounds,from:.zero,operation:.sourceOver,fraction:1,respectFlipped:true,hints:[.interpolation:NSImageInterpolation.high])
    }
}

enum AutomationPointer {
    // Accessed only on the main queue; a token prevents an old timer hiding a
    // newer action's marker. No caller-selected label or website data is shown.
    private static var badge: AutomationPointerPanel?
    private static var badgeLifetime = ControlBadgeLifetime()
    private static let badgeLock = NSLock()
    private static var panel: AutomationPointerPanel?
    private static var generation = 0
    private static func publish(_ state: String) {
        DistributedNotificationCenter.default().postNotificationName(.init("com.viant.mechanize.pointer.activity"), object: "\(getpid()):\(generation)", userInfo: ["state": state], deliverImmediately: true)
    }
    // Local geometry only; no AX value, label or page content is read/exported.
    static func center(of element: AXUIElement) -> CGPoint? {
        var rawPosition: CFTypeRef?, rawSize: CFTypeRef?
        guard AXUIElementCopyAttributeValue(element,kAXPositionAttribute as CFString,&rawPosition) == .success,
              AXUIElementCopyAttributeValue(element,kAXSizeAttribute as CFString,&rawSize) == .success,
              let rawPosition,let rawSize,CFGetTypeID(rawPosition) == AXValueGetTypeID(),CFGetTypeID(rawSize) == AXValueGetTypeID() else {return nil}
        var position = CGPoint.zero,size = CGSize.zero
        guard AXValueGetValue(rawPosition as! AXValue,.cgPoint,&position),AXValueGetValue(rawSize as! AXValue,.cgSize,&size),
              [position.x,position.y,size.width,size.height].allSatisfy({$0.isFinite}),size.width>0,size.height>0 else {return nil}
        return CGPoint(x:position.x+size.width/2,y:position.y+size.height/2)
    }
    static func show(at point: CGPoint) {
        DispatchQueue.main.async {
            present(at:point)
        }
    }
    private static func present(at point: CGPoint) {
            guard let screen = NSScreen.screens.first(where: {
                ($0.deviceDescription[NSDeviceDescriptionKey("NSScreenNumber")] as? NSNumber)?.uint32Value == CGMainDisplayID()
            }), let position = try? appKitMouseDownPoint(point, primaryCG: CGDisplayBounds(CGMainDisplayID()), primaryAppKit: screen.frame) else { return }
            let window = panel ?? AutomationPointerPanel(contentRect:.zero,styleMask:[.borderless,.nonactivatingPanel],backing:.buffered,defer:false)
            window.isOpaque = false; window.backgroundColor = .clear
            window.ignoresMouseEvents = true; window.hidesOnDeactivate = false
            window.level = .statusBar; window.hasShadow = false
            window.collectionBehavior = [.canJoinAllSpaces,.fullScreenAuxiliary,.ignoresCycle]
            let cursor=NSCursor.arrow
            let geometry=AutomationPointerGeometry(imageSize:cursor.image.size,hotSpot:cursor.hotSpot)
            let view = AutomationPointerView(arrow:cursor.image)
            window.contentView = view
            window.setFrame(geometry.frame(at:position),display:true)
            panel = window; generation += 1; let shown = generation
            publish("active")
            window.orderFrontRegardless()
            DispatchQueue.main.asyncAfter(deadline:.now()+0.9) {
                if generation == shown { panel?.orderOut(nil); publish("idle") }
            }
    }
    static func hide() {
        badgeLock.lock();let persistent=badgePersistent;badgeLock.unlock()
        if !persistent {stopControl()}
        DispatchQueue.main.async { publish("idle"); generation += 1; panel?.orderOut(nil) }
    }
}


extension AutomationPointer {
    private static var badgePersistent=false
    private static func badgeCurrent(_ token: UInt64) -> Bool { badgeLock.lock(); defer {badgeLock.unlock()}; return badgeLifetime.active && badgeLifetime.generation == token }
    private static func badgeActive() -> Bool { badgeLock.lock(); defer {badgeLock.unlock()}; return badgeLifetime.active }

    // Bounds only, from an already verified window/process. No labels/values.
    static func windowBounds(element: AXUIElement, pid: pid_t) -> CGRect? {
        func value(_ target: AXUIElement, _ name: String) -> CFTypeRef? {
            var result: CFTypeRef?
            guard AXUIElementCopyAttributeValue(target, name as CFString, &result) == .success else { return nil }
            return result
        }
        var window = element
        if value(element, kAXRoleAttribute) as? String != "AXWindow" {
            guard let owned = value(element, kAXWindowAttribute), CFGetTypeID(owned) == AXUIElementGetTypeID() else { return nil }
            window = owned as! AXUIElement
        }
        var owner: pid_t = 0
        guard AXUIElementGetPid(window, &owner) == .success, owner == pid,
              let p = value(window, kAXPositionAttribute), let s = value(window, kAXSizeAttribute),
              CFGetTypeID(p) == AXValueGetTypeID(), CFGetTypeID(s) == AXValueGetTypeID() else { return nil }
        var point = CGPoint.zero, size = CGSize.zero
        guard AXValueGetValue(p as! AXValue, .cgPoint, &point), AXValueGetValue(s as! AXValue, .cgSize, &size) else { return nil }
        return CGRect(origin: point, size: size)
    }
    static func ownedWindowBounds(pid: pid_t, birth: String, bundle: String, windowID: UInt32) -> CGRect? {
        let runtime = WindowSessionKeyRuntime.system
        guard let before = runtime.process(pid), before.0 == getuid(), before.1 == birth, before.2 == bundle,
              let windows = runtime.windows(), windows.count <= 1000 else { return nil }
        let matches = windows.filter { $0.id == windowID && $0.pid == pid && $0.visible && $0.alpha > 0 }
        guard matches.count == 1, let after = runtime.process(pid), after.0 == before.0, after.1 == birth, after.2 == bundle else { return nil }
        return matches[0].bounds
    }
    private static var badgeAnchor:ControlBadgeAnchor?
    static func beginControl(window: CGRect, allowCompletedPresentation: Bool = true, lifetime: TimeInterval = 5, persistent: Bool = false, anchor: ControlBadgeAnchor? = nil) -> UInt64? {
        guard lifetime.isFinite,lifetime>=0.1,lifetime<=30,let frame = ControlBadgeGeometry.frame(window: window,headerCenter:anchor?.headerCenter ?? 17,leading:anchor?.leading ?? 84,size:anchor?.size ?? CGSize(width:46,height:18)) else { return nil }
        // Request/action handling and AppKit presentation use the same main
        // queue. No activation, key-window changes or input interception.
        badgeLock.lock(); let token = badgeLifetime.begin(); badgePersistent=persistent; badgeAnchor=anchor; let revision = badgeLifetime.leaseRevision; badgeLock.unlock()
        DispatchQueue.main.async {
            guard (badgeCurrent(token) || allowCompletedPresentation && badgeCompleted(token)),
                  let screen = NSScreen.screens.first(where: { ($0.deviceDescription[NSDeviceDescriptionKey("NSScreenNumber")] as? NSNumber)?.uint32Value == CGMainDisplayID() }),
                  let topLeft = try? appKitMouseDownPoint(frame.origin, primaryCG: CGDisplayBounds(CGMainDisplayID()), primaryAppKit: screen.frame) else { return }
            let panel = badge ?? AutomationPointerPanel(contentRect: .zero, styleMask: [.borderless, .nonactivatingPanel], backing: .buffered, defer: false)
            panel.isOpaque = false; panel.backgroundColor = .clear; panel.ignoresMouseEvents = true
            panel.hidesOnDeactivate = false; panel.level = .statusBar; panel.hasShadow = false
            panel.setAccessibilityElement(false)
            panel.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary, .ignoresCycle]
            let view = (panel.contentView as? AutomationControlBadgeView) ?? AutomationControlBadgeView(frame: CGRect(origin: .zero, size: frame.size))
            view.frame=CGRect(origin:.zero,size:frame.size)
            view.active = badgeCurrent(token)
            panel.contentView = view
            panel.setFrame(CGRect(x: topLeft.x, y: topLeft.y - frame.height, width: frame.width, height: frame.height), display: true)
            badge = panel; panel.orderFrontRegardless()
            if !persistent {DispatchQueue.main.asyncAfter(deadline: .now() + lifetime) { expireControl(token, revision: revision) }}
        }
        return token
    }
    static func endControl(_ token: UInt64) {
        badgeLock.lock();let action=nativeBadgeActions.removeValue(forKey:token);badgeLock.unlock()
        if let action {DispatchQueue.main.async{_=try? BrowserControlBadge.shared.handle(method:"controlBadge.end",params:["token":action])};return}

        badgeLock.lock(); let ended = badgeLifetime.end(token); badgeLock.unlock()
        guard ended else { return }
        DispatchQueue.main.async {
            guard badgeCompleted(token) else { return }
            (badge?.contentView as? AutomationControlBadgeView)?.active = false
            DispatchQueue.main.asyncAfter(deadline: .now() + 1.2) {
                if badgeCompleted(token) && !badgeIsPersistent(token) { badge?.orderOut(nil) }
            }
        }
    }
    private static func badgeIsPersistent(_ token:UInt64)->Bool {badgeLock.lock();defer{badgeLock.unlock()};return badgeLifetime.generation==token&&badgePersistent}
    static func setControlActive(_ token:UInt64,_ active:Bool){
        badgeLock.lock();let valid=badgeLifetime.setActive(token,active);badgeLock.unlock();guard valid else{return}
        DispatchQueue.main.async{guard badgeCurrent(token)||badgeCompleted(token) else{return};(badge?.contentView as? AutomationControlBadgeView)?.active=active}
    }
    private static func badgeCompleted(_ token: UInt64) -> Bool {
        badgeLock.lock(); defer { badgeLock.unlock() }
        return !badgeLifetime.active && badgeLifetime.generation == token
    }
    private static func expireControl(_ token: UInt64, revision: UInt64) {
        badgeLock.lock(); let ended = badgeLifetime.expire(token, revision: revision); badgeLock.unlock()
        guard ended else { return }
        DispatchQueue.main.async { if badgeCompleted(token) { badge?.orderOut(nil) } }
    }
    // Only an owner retaining its begin token can renew the five-second lease.
    // A missing heartbeat, explicit stop or process exit cannot leave it active.
    static func heartbeatControl(_ token: UInt64) {
        badgeLock.lock(); let revision = badgeLifetime.renew(token); badgeLock.unlock()
        guard let revision else { return }
        DispatchQueue.main.asyncAfter(deadline: .now() + 5) { expireControl(token, revision: revision) }
    }
    static func stopControl() {
        badgeLock.lock(); badgeLifetime.stop(); badgeLock.unlock()
        DispatchQueue.main.async { if !badgeActive() { badge?.orderOut(nil) } }
    }
}

// Broker presentation token lifecycle, without the native-action completion delay.
extension AutomationPointer {
    // Focus hiding retains presentation ownership only; no activity renewal.
    static func suspendControl(_ token:UInt64) {
        DispatchQueue.main.async {if badgeCurrent(token)||badgeCompleted(token){badge?.orderOut(nil)}}
    }
    static func resumeControl(_ token:UInt64) {
        DispatchQueue.main.async {if badgeCurrent(token)||badgeCompleted(token){badge?.orderFrontRegardless()}}
    }
    static func hideControl(_ token: UInt64) {
        badgeLock.lock()
        guard badgeLifetime.generation == token else {badgeLock.unlock();return}
        badgeLifetime.stop();let stopped=badgeLifetime.generation;badgeLock.unlock()
        DispatchQueue.main.async { if badgeCompleted(stopped) {badge?.orderOut(nil)} }
    }
    static func repositionControl(_ token: UInt64, window: CGRect, allowCompleted: Bool = false, anchor:ControlBadgeAnchor? = nil) {
        badgeLock.lock();let selected=anchor ?? (badgeLifetime.generation==token ? badgeAnchor:nil);if badgeLifetime.generation==token,let anchor {badgeAnchor=anchor};badgeLock.unlock()
        guard let frame=ControlBadgeGeometry.frame(window:window,headerCenter:selected?.headerCenter ?? 17,leading:selected?.leading ?? 84,size:selected?.size ?? CGSize(width:46,height:18)) else {hideControl(token);return}
        DispatchQueue.main.async {
            guard (badgeCurrent(token) || allowCompleted && badgeCompleted(token)),let screen=NSScreen.screens.first(where:{($0.deviceDescription[NSDeviceDescriptionKey("NSScreenNumber")] as? NSNumber)?.uint32Value == CGMainDisplayID()}),
                  let point=try? appKitMouseDownPoint(frame.origin,primaryCG:CGDisplayBounds(CGMainDisplayID()),primaryAppKit:screen.frame) else {return}
            badge?.setFrame(CGRect(x:point.x,y:point.y-frame.height,width:frame.width,height:frame.height),display:true)
        }
    }
}

extension AutomationPointer {
    static func beginOwnedControl(pid: pid_t, birth: String, bundle: String, window: CGRect, windowID: UInt32? = nil, sessionToken:String? = nil, actionDeadline: TimeInterval = ProcessInfo.processInfo.systemUptime + 5) -> UInt64? {
        let runtime=WindowSessionKeyRuntime.system
        guard actionDeadline > ProcessInfo.processInfo.systemUptime,actionDeadline-ProcessInfo.processInfo.systemUptime <= 30 else {return nil}
        guard let before=runtime.process(pid),before.0 == getuid(),before.1 == birth,before.2 == bundle,
              let windows=runtime.windows(),let id=ControlBadgeScope.match(pid:pid,bounds:window,windows:windows.map {ControlBadgeWindow(id:$0.id,pid:$0.pid,layer:$0.layer,visible:$0.visible,alpha:$0.alpha,bounds:$0.bounds)},allowedLayers:[0,3,8],foregroundPID:runtime.foreground(),windowID:windowID),
              let after=runtime.process(pid),after.0 == before.0,after.1 == birth,after.2 == bundle else {return nil}
        if let sessionToken,ControlBadgeScope.validToken(sessionToken) {
            return beginSessionOwnedControl(pid:pid,birth:birth,bundle:bundle,window:window,windowID:id,session:sessionToken,deadline:actionDeadline)
        }
        guard let anchor=ControlBadgeAnchor.measure(pid:pid,bounds:window),let token=beginControl(window:window,lifetime:max(0.1,min(30,actionDeadline-ProcessInfo.processInfo.systemUptime)),anchor:anchor) else {return nil}
        trackOwnedControl(token,pid:pid,birth:birth,bundle:bundle,windowID:id,deadline:actionDeadline,anchor:anchor,windowSize:window.size)
        return token
    }
    static func beginApplicationControl(pid: pid_t, birth: String, bundle: String, sessionToken:String? = nil, actionDeadline: TimeInterval = ProcessInfo.processInfo.systemUptime + 5) -> UInt64? {
        let runtime=WindowSessionKeyRuntime.system
        guard runtime.foreground() == pid,let windows=runtime.windows(),let front=windows.first(where:{[0,3,8].contains($0.layer) && $0.visible && $0.alpha > 0}),front.pid == pid else {return nil}
        return beginOwnedControl(pid:pid,birth:birth,bundle:bundle,window:front.bounds,windowID:front.id,sessionToken:sessionToken,actionDeadline:actionDeadline)
    }
}

// Internal integration-test observation of our own panel only, never a user's
// window or page. No capture, labels or values cross this boundary.
extension AutomationPointer {
    static func controlPresentationActive() -> Bool? {(badge?.contentView as? AutomationControlBadgeView)?.active}
    static func controlPresentationVisible() -> Bool {
        guard let panel=badge,panel.isVisible,
              let windows=CGWindowListCopyWindowInfo([.optionOnScreenOnly,.excludeDesktopElements],kCGNullWindowID) as? [[String:Any]] else {return false}
        return windows.contains {($0[kCGWindowNumber as String] as? Int) == panel.windowNumber && ($0[kCGWindowOwnerPID as String] as? Int32) == getpid()}
    }
}

// Main-run-loop tracking uses only exact process/window metadata, never titles.
extension AutomationPointer {
    private static var ownedTimers: [UInt64: Timer] = [:]
    private static func trackOwnedControl(_ token: UInt64,pid:pid_t,birth:String,bundle:String,windowID:UInt32,deadline:TimeInterval,anchor:ControlBadgeAnchor,windowSize:CGSize) {
        DispatchQueue.main.async {
            guard badgeCurrent(token) || badgeCompleted(token) else {return}
            let runtime=WindowSessionKeyRuntime.system
            let timer=Timer(timeInterval:0.1,repeats:true) { timer in
                guard badgeCurrent(token) || badgeCompleted(token) else {timer.invalidate();ownedTimers.removeValue(forKey:token);return}
                guard ProcessInfo.processInfo.systemUptime < deadline+1.2,let identity=runtime.process(pid),identity.0 == getuid(),identity.1 == birth,identity.2 == bundle,runtime.foreground() == pid,
                      let windows=runtime.windows(),windows.count<=1000,let front=windows.first(where:{[0,3,8].contains($0.layer) && $0.visible && $0.alpha > 0}),front.pid == pid,front.id == windowID,
                      windows.filter({$0.id == windowID}).count == 1,ControlBadgeGeometry.frame(window:front.bounds) != nil else {hideControl(token);timer.invalidate();ownedTimers.removeValue(forKey:token);return}
                // A legacy action without session tracking has only its original
                // measured header layout. Translation is safe; resize ends that
                // presentation instead of guessing a new tab-strip placement.
                guard front.bounds.size == windowSize else {hideControl(token);timer.invalidate();ownedTimers.removeValue(forKey:token);return}
                repositionControl(token,window:front.bounds,allowCompleted:true,anchor:anchor)
            }
            ownedTimers[token]=timer;RunLoop.main.add(timer,forMode:.common)
        }
    }
}

// Native action tokens are separate from panel generations. Renewal exists
// only while this exact synchronous helper action is running, never while idle.
extension AutomationPointer {
    private static var nativeBadgeSequence:UInt64=1<<63
    private static var nativeBadgeActions:[UInt64:String]=[:]
    private static func beginSessionOwnedControl(pid:pid_t,birth:String,bundle:String,window:CGRect,windowID:UInt32,session:String,deadline:TimeInterval)->UInt64? {
        let action=(UUID().uuidString+UUID().uuidString).replacingOccurrences(of:"-",with:"").lowercased()
        badgeLock.lock();guard nativeBadgeActions.count<256 else{badgeLock.unlock();return nil};nativeBadgeSequence &+= 1;let token=nativeBadgeSequence;nativeBadgeActions[token]=action;badgeLock.unlock()
        DispatchQueue.main.async {
            let duration=max(100,min(5000,Int((deadline-ProcessInfo.processInfo.systemUptime)*1000)))
            let params:[String:Any]=["token":action,"sessionToken":session,"windowId":windowID,"expectedApp":bundle,"pid":pid,"processStartToken":birth,"windowBounds":["x":window.minX,"y":window.minY,"width":window.width,"height":window.height],"durationMs":duration]
            guard (try? BrowserControlBadge.shared.handle(method:"controlBadge.begin",params:params)) != nil else{return}
            let timer=Timer(timeInterval:1,repeats:true){timer in
                badgeLock.lock();let running=nativeBadgeActions[token]==action;badgeLock.unlock()
                guard running&&ProcessInfo.processInfo.systemUptime<deadline else{timer.invalidate();return}
                let remaining=max(100,min(3000,Int((deadline-ProcessInfo.processInfo.systemUptime)*1000)))
                Task{@MainActor in _=try? BrowserControlBadge.shared.handle(method:"controlBadge.renew",params:["token":action,"durationMs":remaining])}
            }
            RunLoop.main.add(timer,forMode:.common)
        }
        return token
    }
}
