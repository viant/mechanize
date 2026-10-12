import AppKit

// Compact header capsule in the Computer-Use style: a pill attached to the
// target window's header carrying a two-letter MV mark (Viant blue M, red V).
// No label, shadow, toast or plate; the pill fills the measured header gap.
struct AutomationControlBadgeLayout: Equatable {
    static let blue=NSColor(calibratedRed:0.086,green:0.44,blue:0.81,alpha:1)
    static let red=NSColor(calibratedRed:0.78,green:0.063,blue:0.18,alpha:1)
    let pill: NSRect, radius: CGFloat, font: NSFont, m: NSRect, v: NSRect
    var compact: Bool { pill.height<16 }
    init(size: CGSize) {
        pill=NSRect(origin:.zero,size:size).insetBy(dx:0.5,dy:0.5);radius=pill.height/2
        // Heavy SF at 12pt reads at 18pt tall; 8pt keeps the 22x12 reduced mark legible.
        font=NSFont.systemFont(ofSize:size.height<16 ? 8:12,weight:.heavy)
        let gap:CGFloat=size.height<16 ? 0.5:1
        let mSize=("M" as NSString).size(withAttributes:[.font:font]),vSize=("V" as NSString).size(withAttributes:[.font:font])
        let width=mSize.width+gap+vSize.width,x=((size.width-width)/2).rounded(.down),y=((size.height-mSize.height)/2).rounded()
        m=NSRect(x:x,y:y,width:mSize.width,height:mSize.height)
        v=NSRect(x:x+mSize.width+gap,y:y,width:vSize.width,height:vSize.height)
    }
}

// A transparent title-bar mark. No input handling, window activation or content reads.
final class AutomationControlBadgeView: NSView {
    var active = true { didSet { needsDisplay = true } }
    override var isFlipped: Bool { true }
    override func hitTest(_ point: NSPoint) -> NSView? { nil }
    override func draw(_ dirtyRect: NSRect) {
        guard let graphics=NSGraphicsContext.current else{return}
        graphics.imageInterpolation = .high
        graphics.cgContext.setShouldAntialias(true)
        let layout=AutomationControlBadgeLayout(size:bounds.size)
        let pill=NSBezierPath(roundedRect:layout.pill,xRadius:layout.radius,yRadius:layout.radius)
        // Near-white capsule reads on light and dark headers alike; the idle
        // state stays present but quieter through a neutral hairline and dimmer
        // letters, while activity is a thin Viant-blue ring, never a new element.
        NSColor(calibratedWhite:0.97,alpha:active ? 0.96:0.9).setFill();pill.fill()
        (active ? AutomationControlBadgeLayout.blue.withAlphaComponent(0.85):NSColor(calibratedWhite:0,alpha:0.18)).setStroke()
        pill.lineWidth=1;pill.stroke()
        let alpha:CGFloat=active ? 1:0.75
        ("M" as NSString).draw(at:layout.m.origin,withAttributes:[.font:layout.font,.foregroundColor:AutomationControlBadgeLayout.blue.withAlphaComponent(alpha)])
        ("V" as NSString).draw(at:layout.v.origin,withAttributes:[.font:layout.font,.foregroundColor:AutomationControlBadgeLayout.red.withAlphaComponent(alpha)])
    }
}
