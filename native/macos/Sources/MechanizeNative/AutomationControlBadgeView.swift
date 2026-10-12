import AppKit

// A transparent title-bar mark. No input handling, window activation or content reads.
final class AutomationControlBadgeView: NSView {
    var active = true { didSet { needsDisplay = true } }
    override var isFlipped: Bool { true }
    override func hitTest(_ point: NSPoint) -> NSView? { nil }
    override func draw(_ dirtyRect: NSRect) {
        NSGraphicsContext.current?.imageInterpolation = .high
        NSGraphicsContext.current?.cgContext.setShouldAntialias(true)
        let red=NSColor(calibratedRed:0.78,green:0.063,blue:0.18,alpha:1)
        let blue=NSColor(calibratedRed:0.086,green:0.44,blue:0.81,alpha:1)
        let halo=NSShadow();halo.shadowColor=NSColor.white.withAlphaComponent(0.85);halo.shadowBlurRadius=1.5;halo.shadowOffset = .zero
        let compact=bounds.width<46
        ("V" as NSString).draw(at:NSPoint(x:compact ? 1:2,y:compact ? -1:1),withAttributes:[.font:NSFont.systemFont(ofSize:compact ? 12:14,weight:.bold),.foregroundColor:red,.shadow:halo])
        ("M" as NSString).draw(at:NSPoint(x:compact ? 10:12,y:compact ? 4:7),withAttributes:[.font:NSFont.systemFont(ofSize:8,weight:.bold),.foregroundColor:blue,.shadow:halo])
        if bounds.width<46 {
            // Reduced VM-only layout uses measured free header space.
            return
        }
        let screen=NSBezierPath(roundedRect:NSRect(x:23,y:3,width:12,height:9),xRadius:1.5,yRadius:1.5)
        let stand=NSBezierPath();stand.move(to:NSPoint(x:29,y:12));stand.line(to:NSPoint(x:29,y:15));stand.move(to:NSPoint(x:25,y:15));stand.line(to:NSPoint(x:33,y:15))
        NSGraphicsContext.saveGraphicsState();halo.set()
        NSColor(calibratedWhite:0.18,alpha:1).setStroke()
        screen.lineWidth=1.1;screen.stroke();stand.lineWidth=1.1;stand.stroke()
        NSGraphicsContext.restoreGraphicsState()
        let state=NSBezierPath(ovalIn:NSRect(x:39,y:7,width:4,height:4))
        NSColor.white.withAlphaComponent(0.9).setStroke();state.lineWidth=2.5;state.stroke()
        if active {red.setFill();state.fill()}
        (active ? red : NSColor(calibratedWhite:0.35,alpha:1)).setStroke();state.lineWidth=1;state.stroke()
    }
}
