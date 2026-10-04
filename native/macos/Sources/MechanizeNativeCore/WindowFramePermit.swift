import Foundation
import CoreGraphics

public struct WindowFrameOwner: Equatable {
    public let namespace: String
    public let clientId: String
    public let sessionId: String
    public init(_ raw: Any?) throws {
        guard let value = raw as? [String: Any], Set(value.keys) == Set(["namespace", "clientId", "sessionId"]),
              let namespace = value["namespace"] as? String, namespace.range(of: "^[a-f0-9]{64}$", options: .regularExpression) != nil,
              let client = value["clientId"] as? String, client.utf8.count <= 256, !client.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }),
              let session = value["sessionId"] as? String, !session.isEmpty, session.utf8.count <= 256, !session.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) else {
            throw NativeFailure("invalidOwner", "Exact bounded frame owner required")
        }
        self.namespace = namespace; clientId = client; sessionId = session
    }
    public var metadata: [String: String] { ["namespace": namespace, "clientId": clientId, "sessionId": sessionId] }
}

public struct WindowFramePermit {
    public let id: String
    public let owner: WindowFrameOwner
    public let helperEpoch: String
    public let fenceGeneration: Int
    public let bundleId: String
    public let pid: Int32
    public let processStartToken: String
    public let windowId: UInt32
    public let displayId: UInt32
    public let bounds: CGRect
    public let widthPixels: Int
    public let heightPixels: Int
    public let scale: Double
    public let contentHash: String
    public let capturedAt: Date
    public let expiresAt: Date
    public let deadline: UInt64
    public init(id: String, owner: WindowFrameOwner, helperEpoch: String, fenceGeneration: Int, bundleId: String, pid: Int32,
                processStartToken: String, windowId: UInt32, displayId: UInt32, bounds: CGRect, widthPixels: Int, heightPixels: Int,
                scale: Double, contentHash: String, capturedAt: Date, uptime: UInt64) throws {
        guard id.range(of: "^[a-f0-9]{32}$", options: .regularExpression) != nil, !helperEpoch.isEmpty, fenceGeneration > 0,
              !bundleId.isEmpty, pid > 0, !processStartToken.isEmpty, windowId > 0, displayId > 0,
              [bounds.minX, bounds.minY, bounds.width, bounds.height, bounds.maxX, bounds.maxY].allSatisfy({ $0.isFinite }), bounds.width > 0, bounds.height > 0,
              widthPixels > 0, heightPixels > 0, widthPixels <= 32768, heightPixels <= 32768,
              Int64(widthPixels) * Int64(heightPixels) <= 32_000_000, scale.isFinite, scale > 0, scale <= 8,
              abs(Double(bounds.width) * scale - Double(widthPixels)) <= 0.001,
              abs(Double(bounds.height) * scale - Double(heightPixels)) <= 0.001,
              contentHash.range(of: "^[a-f0-9]{64}$", options: .regularExpression) != nil,
              uptime <= UInt64.max - 30_000_000_000 else { throw NativeFailure("invalidPermit", "Exact bounded captured frame proof required") }
        self.id = id; self.owner = owner; self.helperEpoch = helperEpoch; self.fenceGeneration = fenceGeneration
        self.bundleId = bundleId; self.pid = pid; self.processStartToken = processStartToken; self.windowId = windowId
        self.displayId = displayId; self.bounds = bounds; self.widthPixels = widthPixels; self.heightPixels = heightPixels
        self.scale = scale; self.contentHash = contentHash; self.capturedAt = capturedAt
        expiresAt = capturedAt.addingTimeInterval(30); deadline = uptime + 30_000_000_000
    }
    public func point(x: Any?, y: Any?) throws -> (Int, Int, CGPoint) {
        func pixel(_ raw: Any?, maximum: Int) throws -> Int {
            guard let number = raw as? NSNumber, CFGetTypeID(number) == CFNumberGetTypeID(), number.doubleValue.isFinite,
                  number.doubleValue.rounded(.towardZero) == number.doubleValue, number.doubleValue >= 0,
                  number.doubleValue < Double(maximum) else { throw NativeFailure("invalidPoint", "Bounded integer frame pixel required") }
            return number.intValue
        }
        let x = try pixel(x, maximum: widthPixels), y = try pixel(y, maximum: heightPixels)
        let point = CGPoint(x: Double(bounds.minX) + (Double(x) + 0.5) / scale, y: Double(bounds.minY) + (Double(y) + 0.5) / scale)
        guard bounds.contains(point) else { throw NativeFailure("invalidPoint", "Mapped pixel is outside captured window") }
        return (x, y, point)
    }
    public func metadata(format: (Date) -> String) -> [String: Any] {
        ["id": id, "owner": owner.metadata, "helperEpoch": helperEpoch, "fenceGeneration": fenceGeneration, "bundleId": bundleId,
         "pid": pid, "processStartToken": processStartToken, "windowId": windowId, "displayId": displayId,
         "bounds": ["x": bounds.minX, "y": bounds.minY, "width": bounds.width, "height": bounds.height],
         "widthPixels": widthPixels, "heightPixels": heightPixels, "scale": scale, "contentHash": contentHash,
         "capturedAt": format(capturedAt), "expiresAt": format(expiresAt)]
    }
}

// One active permit per retained helper interval. Consume before the posting
// boundary; failed dispatch, restart or renewed capture can never revive it.
public final class WindowFramePermitStore {
    private let lock = NSLock()
    private var active: WindowFramePermit?
    public init() {}
    public func install(_ permit: WindowFramePermit) { lock.lock(); active = permit; lock.unlock() }
    public func clear() { lock.lock(); active = nil; lock.unlock() }
    public func lookup(id: String, owner: WindowFrameOwner, epoch: String, generation: Int, now: UInt64) throws -> WindowFramePermit {
        lock.lock(); defer { lock.unlock() }
        guard let permit = active, permit.id == id, permit.owner == owner, permit.helperEpoch == epoch,
              permit.fenceGeneration == generation, now < permit.deadline else { throw NativeFailure("stalePermit", "Frame permit expired, consumed or belongs to another interval") }
        return permit
    }
    public func consume(id: String, owner: WindowFrameOwner, epoch: String, generation: Int, now: UInt64) throws -> WindowFramePermit {
        lock.lock(); defer { lock.unlock() }
        guard let permit = active, permit.id == id, permit.owner == owner, permit.helperEpoch == epoch,
              permit.fenceGeneration == generation, now < permit.deadline else { throw NativeFailure("stalePermit", "Frame permit expired, consumed or belongs to another interval") }
        active = nil
        return permit
    }
}
