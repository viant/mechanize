import Foundation
import CoreGraphics

public struct ControlBadgeWindow {
    public let id: UInt32, pid: Int32, layer: Int
    public let visible: Bool
    public let alpha: Double
    public let bounds: CGRect
    public init(id: UInt32, pid: Int32, layer: Int, visible: Bool, alpha: Double, bounds: CGRect) {
        self.id=id; self.pid=pid; self.layer=layer; self.visible=visible; self.alpha=alpha; self.bounds=bounds
    }
}
public enum ControlBadgeScope {
    public static func validToken(_ token: String) -> Bool { token.utf8.count == 64 && token.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) } }
    public static func validDuration(_ milliseconds: Int) -> Bool { (100...5000).contains(milliseconds) }
    public static func match(pid: Int32, bounds: CGRect, windows: [ControlBadgeWindow], allowedLayers: Set<Int> = [0], foregroundPID: Int32? = nil, windowID: UInt32? = nil) -> UInt32? {
        guard pid > 0, windows.count <= 1000, ControlBadgeGeometry.frame(window: bounds) != nil else { return nil }
        let matches=windows.filter { window in
            window.pid == pid && window.id > 0 && allowedLayers.contains(window.layer) && window.visible && window.alpha.isFinite && window.alpha > 0 && window.alpha <= 1 &&
            [window.bounds.minX,window.bounds.minY,window.bounds.width,window.bounds.height].allSatisfy {$0.isFinite} &&
            abs(window.bounds.minX-bounds.minX)<=2 && abs(window.bounds.minY-bounds.minY)<=2 && abs(window.bounds.width-bounds.width)<=2 && abs(window.bounds.height-bounds.height)<=2
        }
        // OS window numbers are identity, even when an application's windows
        // share identical geometry. Duplicate numbers remain invalid.
        if let windowID {
            return matches.contains(where: {$0.id == windowID}) && windows.filter({$0.id == windowID}).count == 1 ? windowID : nil
        }
        if matches.count == 1 {
            return windows.filter({$0.id == matches[0].id}).count == 1 ? matches[0].id : nil
        }
        // Presentation-only fallback: the WindowServer list is front-to-back.
        // Never choose a same-sized background window of a different app or a
        // different leading window whose bounds do not match the requested one.
        guard foregroundPID == pid,
              let front = windows.first(where: {allowedLayers.contains($0.layer) && $0.visible && $0.alpha.isFinite && $0.alpha > 0 && $0.alpha <= 1}),
              front.pid == pid, matches.contains(where: {$0.id == front.id}),
              windows.filter({$0.id == front.id}).count == 1 else { return nil }
        return front.id
    }
}

public enum NativeControlBadgeRoutes {
    // These routes validate again after durable reservation; show only at the
    // actual posting boundary or independently confirmed lifecycle result.
    public static func delayUntilDispatch(_ method: String) -> Bool {
        ["elements.pressKey","elements.pressSessionKey","input.key","input.text","input.pointer","windows.pressSessionKey","windows.typeText","elements.setValue","app.activate","app.launch"].contains(method)
    }
}
