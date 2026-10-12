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
    public static func match(pid: Int32, bounds: CGRect, windows: [ControlBadgeWindow], allowedLayers: Set<Int> = [0]) -> UInt32? {
        guard pid > 0, windows.count <= 1000, ControlBadgeGeometry.frame(window: bounds) != nil else { return nil }
        let matches=windows.filter { window in
            window.pid == pid && window.id > 0 && allowedLayers.contains(window.layer) && window.visible && window.alpha.isFinite && window.alpha > 0 && window.alpha <= 1 &&
            [window.bounds.minX,window.bounds.minY,window.bounds.width,window.bounds.height].allSatisfy {$0.isFinite} &&
            abs(window.bounds.minX-bounds.minX)<=2 && abs(window.bounds.minY-bounds.minY)<=2 && abs(window.bounds.width-bounds.width)<=2 && abs(window.bounds.height-bounds.height)<=2
        }
        return matches.count == 1 ? matches[0].id : nil
    }
}

public enum NativeControlBadgeRoutes {
    // These routes validate again after durable reservation; show only at the
    // actual posting boundary or independently confirmed lifecycle result.
    public static func delayUntilDispatch(_ method: String) -> Bool {
        ["elements.pressKey","elements.pressSessionKey","input.key","input.text","input.pointer","windows.pressSessionKey","windows.typeText","elements.setValue","app.activate","app.launch"].contains(method)
    }
}
