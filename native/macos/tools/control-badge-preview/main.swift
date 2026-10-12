import AppKit
// Disposable, offscreen AppKit fixture. Never activates or reads another app.
// Compile with AutomationControlBadgeView.swift and run with an output path.
let app = NSApplication.shared
app.setActivationPolicy(.prohibited)
let view = NSView(frame: NSRect(x:0,y:0,width:580,height:180))
view.wantsLayer = true; view.layer?.backgroundColor = NSColor(calibratedWhite:0.91,alpha:1).cgColor
for (offset, active) in [(CGFloat(98), true), (CGFloat(36), false)] {
    let badge = AutomationControlBadgeView(frame:NSRect(x:84,y:offset,width:208,height:38))
    badge.active = active; view.addSubview(badge)
}
let bitmap = view.bitmapImageRepForCachingDisplay(in:view.bounds)!
view.cacheDisplay(in:view.bounds,to:bitmap)
try bitmap.representation(using:.png,properties:[:])!.write(to:URL(fileURLWithPath:CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : "/tmp/mechanize-control-badge.png"))
