import AppKit
import Foundation
let output = URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true)
let fm = FileManager.default
try fm.createDirectory(at: output, withIntermediateDirectories: true)
let iconset = output.appendingPathComponent("Mechanize.iconset")
try fm.createDirectory(at: iconset, withIntermediateDirectories: true)
func mark(_ rect: CGRect) {
    let points: [(CGFloat, CGFloat)] = [(17.5,0),(10,0),(10,3.5),(11.5,3.5),(9,10.5),(6,3.5),(7.5,3.5),(7.5,0),(0,0),(0,3.5),(1.5,3.5),(6.5,16),(11,16),(16.5,3.5),(17.5,3.5)]
    let path = NSBezierPath()
    for (i,p) in points.enumerated() {
        let point = NSPoint(x: rect.minX+p.0/17.5*rect.width, y: rect.maxY-p.1/16*rect.height)
        if i == 0 { path.move(to: point) } else { path.line(to: point) }
    }
    path.close()
    NSColor(srgbRed: 200/255, green: 16/255, blue: 46/255, alpha: 1).setFill()
    path.fill()
}
func smallM(_ rect: CGRect) {
    let points: [(CGFloat, CGFloat)] = [(0,1),(0,0),(0.22,0),(0.5,0.42),(0.78,0),(1,0),(1,1),(0.76,1),(0.76,0.4),(0.5,0.76),(0.24,0.4),(0.24,1)]
    let path = NSBezierPath()
    for (i,p) in points.enumerated() {
        let point = NSPoint(x: rect.minX+p.0*rect.width, y: rect.maxY-p.1*rect.height)
        if i == 0 { path.move(to: point) } else { path.line(to: point) }
    }
    path.close()
    NSColor(srgbRed: 22/255, green: 113/255, blue: 206/255, alpha: 1).setFill()
    path.fill()
}
func png(_ size: Int, menu: Bool = false) throws -> Data {
    let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: size, pixelsHigh: size, bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true, isPlanar: false, colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0)!
    let ctx = NSGraphicsContext(bitmapImageRep: rep)!
    NSGraphicsContext.saveGraphicsState(); NSGraphicsContext.current = ctx
    let scale = CGFloat(size)/1024
    ctx.cgContext.scaleBy(x: scale, y: scale)
    if menu {
        mark(CGRect(x: 64, y: 220, width: 560, height: 512))
        smallM(CGRect(x: 644, y: 220, width: 290, height: 340))
    }
    else {
        NSColor(srgbRed: 0.09, green: 0.13, blue: 0.20, alpha: 0.10).setFill()
        NSBezierPath(roundedRect: CGRect(x: 100, y: 90, width: 824, height: 824), xRadius: 184, yRadius: 184).fill()
        let tile = NSBezierPath(roundedRect: CGRect(x: 100, y: 110, width: 824, height: 824), xRadius: 184, yRadius: 184)
        NSGradient(starting: .white, ending: NSColor(srgbRed: 240/255, green: 241/255, blue: 244/255, alpha: 1))!.draw(in: tile, angle: -90)
        NSColor(srgbRed: 224/255, green: 226/255, blue: 231/255, alpha: 1).setStroke(); tile.lineWidth = 2; tile.stroke()
        mark(CGRect(x: 200, y: 300, width: 455, height: 416))
        smallM(CGRect(x: 665, y: 300, width: 175, height: 220))
    }
    NSGraphicsContext.restoreGraphicsState()
    return rep.representation(using: .png, properties: [:])!
}
for size in [16,32,128,256,512] {
    try png(size).write(to: iconset.appendingPathComponent("icon_\(size)x\(size).png"))
    try png(size*2).write(to: iconset.appendingPathComponent("icon_\(size)x\(size)@2x.png"))
}
try png(36, menu: true).write(to: output.appendingPathComponent("MechanizeMenu.png"))
try png(1024).write(to: output.appendingPathComponent("MechanizePreview.png"))
