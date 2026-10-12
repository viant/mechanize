import Foundation
import CoreGraphics

public enum ControlBadgeGeometry {
    /// Global top-left window coordinates; reserve traffic-light/title chrome.
    /// The default leading edge (84) clears standard traffic lights; the mark is
    /// centred on the title row and always kept inside the window's own bounds.
    public static func frame(window: CGRect, headerCenter: CGFloat = 17, leading: CGFloat = 84, size: CGSize = CGSize(width:46,height:18)) -> CGRect? {
        guard [window.minX,window.minY,window.width,window.height,headerCenter,leading].allSatisfy({$0.isFinite}),window.width>=120,window.height>=48,[size.width,size.height].allSatisfy({$0.isFinite}),size.width>=22,size.width<=46,size.height>=12,size.height<=18 else {return nil}
        let center=min(44-size.height/2,max(size.height/2+2,headerCenter)), x=min(max(6,leading),window.width-size.width-6)
        let result=CGRect(x:window.minX+x,y:window.minY+center-size.height/2,width:size.width,height:size.height)
        return window.contains(result) ? result:nil
    }

    /// The mark belongs to the window-control cluster at the top left, like a
    /// Computer-Use badge. The leading zone ends this far past the traffic
    /// lights' trailing edge: a full 46pt capsule with its 2pt clearances plus
    /// 10pt of slack. Nothing is ever placed beyond it, so the mark cannot
    /// wander after a tab strip or toolbar into the middle of the header.
    public static let leadingZoneSlack: CGFloat = 60
    /// Trailing boundary (global x) of the leading header zone for measured lights.
    public static func leadingZoneEnd(window:CGRect,trafficLights:[CGRect])->CGFloat {
        min(window.maxX-6,(trafficLights.map(\.maxX).max() ?? window.minX)+leadingZoneSlack)
    }

    /// Complete geometry-only header census. Never place a window indicator on
    /// traffic lights, tabs or another occupied control. Prefer the full 46x18
    /// MV capsule in the leading zone beside the traffic lights; if that zone is
    /// crowded, fall back to the reduced 22x12 capsule in the same leading zone
    /// (typically above or below the lights). Free space further right is never
    /// used. Both sizes are rendered by the same capsule layout.
    public static func freeHeaderFrame(window:CGRect,trafficLights:[CGRect],occupied:[CGRect])->CGRect? {
        guard frame(window:window) != nil,!trafficLights.isEmpty,trafficLights.count<=3,occupied.count<=128 else{return nil}
        let header=CGRect(x:window.minX,y:window.minY,width:window.width,height:44)
        let rectangles=trafficLights+occupied
        guard rectangles.allSatisfy({[$0.minX,$0.minY,$0.width,$0.height].allSatisfy({$0.isFinite}) && $0.width>0 && $0.height>0}),trafficLights.allSatisfy({header.contains($0)}) else{return nil}
        let center=trafficLights.map(\.midY).reduce(0,+)/CGFloat(trafficLights.count)
        let zoneEnd=leadingZoneEnd(window:window,trafficLights:trafficLights)
        for size in [CGSize(width:46,height:18),CGSize(width:22,height:12)] {
            let preferred=center-size.height/2
            let ys=[preferred]+stride(from:CGFloat(2),through:44-size.height-2,by:2).filter{abs($0+window.minY-preferred)>1}.map{$0+window.minY}
            for y in ys where y>=window.minY+2 && y+size.height<=header.maxY-2 {
                let band=CGRect(x:window.minX+6,y:y,width:zoneEnd-window.minX-6,height:size.height)
                guard band.width>=size.width else{continue}
                let blocks=rectangles.map{$0.insetBy(dx:-2,dy:-2)}.filter{$0.intersects(band)}.sorted{$0.minX<$1.minX}
                var x=band.minX
                for block in blocks {if block.maxX<=x{continue};if block.minX-x>=size.width{break};x=max(x,block.maxX)}
                let candidate=CGRect(x:x,y:y,width:size.width,height:size.height)
                if band.contains(candidate) && !blocks.contains(where:{$0.intersects(candidate)}){return candidate}
            }
        }
        return nil
    }

}

/// A stale idle timer must never hide a newer action. State is display-only.
public struct ControlBadgeLifetime {
    public private(set) var generation: UInt64 = 0
    public private(set) var active = false
    public private(set) var leaseRevision: UInt64 = 0
    public init() {}
    public mutating func begin() -> UInt64 { generation &+= 1; leaseRevision &+= 1; active = true; return generation }
    public mutating func end(_ token: UInt64) -> Bool {
        guard active, token == generation else { return false }
        active = false; return true
    }
    public mutating func renew(_ token: UInt64) -> UInt64? {
        guard active, token == generation else { return nil }
        leaseRevision &+= 1; return leaseRevision
    }
    public mutating func expire(_ token: UInt64, revision: UInt64) -> Bool {
        guard revision == leaseRevision else { return false }
        return end(token)
    }
    public mutating func setActive(_ token: UInt64, _ value: Bool) -> Bool {
        guard token==generation else{return false};active=value;return true
    }
    public mutating func stop() { generation &+= 1; active = false }
}
