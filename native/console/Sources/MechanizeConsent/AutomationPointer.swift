import AppKit

// Presentation only: samples cursor geometry, never AX content or input. The
// app owns this overlay so native action helpers need not wait for animations.
@MainActor final class PersistentAutomationPointer {
    static let shared = PersistentAutomationPointer()
    static let preferenceKey = "mechanize.showAutomationPointer"
    private var timer: Timer?
    private var panel: PointerPanel?
    private var lastPosition: NSPoint?
    private var activeUntil = Date.distantPast
    private var activityToken: String?
    private var activityObserver: NSObjectProtocol?
    var enabled: Bool {
        get { UserDefaults.standard.object(forKey: Self.preferenceKey) as? Bool ?? true }
        set { UserDefaults.standard.set(newValue, forKey: Self.preferenceKey); update() }
    }
    func start() {
        guard timer == nil else { return }
        activityObserver = DistributedNotificationCenter.default().addObserver(forName: .init("com.viant.mechanize.pointer.activity"), object: nil, queue: .main) { event in
            let token = event.object as? String
            let state = event.userInfo?["state"] as? String
            Task { @MainActor in
                guard let token, token.count <= 64 else { return }
                if state == "active" {
                    self.activityToken = token; self.activeUntil = Date().addingTimeInterval(0.9)
                } else if state == "idle", self.activityToken == token {
                    self.activeUntil = .distantPast; self.activityToken = nil
                }
                self.update()
            }
        }
        update()
        let timer = Timer(timeInterval: 0.04, repeats: true) { _ in
            Task { @MainActor in self.update() }
        }
        RunLoop.main.add(timer, forMode: .common)
        self.timer = timer
    }
    private func update() {
        guard enabled, Date() < activeUntil else { panel?.orderOut(nil); lastPosition = nil; return }
        let point = NSEvent.mouseLocation
        guard point.x.isFinite, point.y.isFinite else { panel?.orderOut(nil); return }
        if panel == nil {
            let window = PointerPanel(contentRect: .zero, styleMask: [.borderless, .nonactivatingPanel], backing: .buffered, defer: false)
            window.isOpaque = false; window.backgroundColor = .clear
            window.ignoresMouseEvents = true; window.hidesOnDeactivate = false
            window.level = .statusBar; window.hasShadow = false
            window.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary, .ignoresCycle]
            window.setAccessibilityElement(false)
            window.contentView = PointerView(frame: NSRect(x: 0, y: 0, width: 70, height: 78))
            panel = window
        }
        // AppKit mouse and window coordinates share a bottom-left origin,
        // including displays to the left/below the main display.
        if lastPosition != point || panel?.isVisible != true {
            panel?.setFrame(NSRect(x: point.x - 12, y: point.y - 66, width: 70, height: 78), display: true)
            panel?.orderFrontRegardless(); lastPosition = point
        }
    }
}
private final class PointerPanel: NSPanel {
    override var canBecomeKey: Bool { false }
    override var canBecomeMain: Bool { false }
}
private final class PointerView: NSView {
    override var isFlipped: Bool { true }
    override func draw(_ dirtyRect: NSRect) {
        let arrow = NSBezierPath()
        arrow.move(to: NSPoint(x: 12, y: 12)); arrow.line(to: NSPoint(x: 12, y: 52))
        arrow.line(to: NSPoint(x: 23, y: 41)); arrow.line(to: NSPoint(x: 32, y: 59))
        arrow.line(to: NSPoint(x: 41, y: 54)); arrow.line(to: NSPoint(x: 32, y: 36))
        arrow.line(to: NSPoint(x: 49, y: 36)); arrow.close()
        NSColor(calibratedRed: 0.86, green: 0.10, blue: 0.16, alpha: 0.25).setStroke()
        arrow.lineWidth = 10; arrow.stroke()
        NSColor.white.setStroke(); arrow.lineWidth = 4; arrow.stroke()
        NSColor(calibratedRed: 0.86, green: 0.10, blue: 0.16, alpha: 1).setFill(); arrow.fill()
    }
}
