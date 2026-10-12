import Foundation
import CoreGraphics

public enum ControlBadgeGeometry {
    /// Global top-left window coordinates; reserve traffic-light/title chrome.
    public static func frame(window: CGRect, headerCenter: CGFloat = 17, leading: CGFloat = 84, size: CGSize = CGSize(width:46,height:18)) -> CGRect? {
        guard [window.minX,window.minY,window.width,window.height,headerCenter,leading].allSatisfy({$0.isFinite}),window.width>=120,window.height>=48,[size.width,size.height].allSatisfy({$0.isFinite}),size.width>=22,size.width<=46,size.height>=12,size.height<=18 else {return nil}
        let center=min(44-size.height/2,max(size.height/2+2,headerCenter)), x=min(max(6,leading),window.width-size.width-6)
        let result=CGRect(x:window.minX+x,y:window.minY+center-size.height/2,width:size.width,height:size.height)
        return window.contains(result) ? result:nil
    }

    /// Complete geometry-only header census. Never place a window indicator on
    /// traffic lights, tabs or another occupied control; prefer the full mark,
    /// then a compact VM-only mark in a measured gap.
    public static func freeHeaderFrame(window:CGRect,trafficLights:[CGRect],occupied:[CGRect])->CGRect? {
        guard frame(window:window) != nil,!trafficLights.isEmpty,trafficLights.count<=3,occupied.count<=128 else{return nil}
        let header=CGRect(x:window.minX,y:window.minY,width:window.width,height:44)
        let rectangles=trafficLights+occupied
        guard rectangles.allSatisfy({[$0.minX,$0.minY,$0.width,$0.height].allSatisfy({$0.isFinite}) && $0.width>0 && $0.height>0}),trafficLights.allSatisfy({header.contains($0)}) else{return nil}
        let center=trafficLights.map(\.midY).reduce(0,+)/CGFloat(trafficLights.count)
        for size in [CGSize(width:46,height:18),CGSize(width:22,height:12)] {
            let preferred=center-size.height/2
            let ys=[preferred]+stride(from:CGFloat(2),through:44-size.height-2,by:2).filter{abs($0+window.minY-preferred)>1}.map{$0+window.minY}
            for y in ys where y>=window.minY+2 && y+size.height<=header.maxY-2 {
                let band=CGRect(x:window.minX+6,y:y,width:window.width-12,height:size.height)
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
