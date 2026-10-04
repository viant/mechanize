import XCTest
import CoreGraphics
@testable import MechanizeNativeCore

final class WindowFramePermitTests: XCTestCase {
    func owner(_ session: String = "s", client: String = "c") throws -> WindowFrameOwner {
        try WindowFrameOwner(["namespace": String(repeating: "a", count: 64), "clientId": client, "sessionId": session])
    }
    func permit(_ id: String = String(repeating: "b", count: 32)) throws -> WindowFramePermit {
        try WindowFramePermit(id: id, owner: owner(), helperEpoch: "e", fenceGeneration: 2, bundleId: "com.fixture.app", pid: 42, processStartToken: "100:1", windowId: 99, displayId: 1,
                              bounds: CGRect(x: -100, y: 20, width: 100, height: 50), widthPixels: 200, heightPixels: 100, scale: 2,
                              contentHash: String(repeating: "c", count: 64), capturedAt: Date(timeIntervalSince1970: 100), uptime: 100)
    }
    func testStrictOwnerAndPixelCenterMapping() throws {
        XCTAssertThrowsError(try WindowFrameOwner(["namespace": String(repeating: "a", count: 64), "clientId": "c", "sessionId": "s", "extra": 1]))
        XCTAssertThrowsError(try owner("")); XCTAssertThrowsError(try owner("s", client: "\n"))
        let p = try permit(); let (x,y,point) = try p.point(x: 199, y: 99)
        XCTAssertEqual(x,199); XCTAssertEqual(y,99); XCTAssertEqual(point.x, -0.25); XCTAssertEqual(point.y, 69.75)
        for raw: Any in [true, -1, 200, 1.2, "1", Double.infinity] { XCTAssertThrowsError(try p.point(x: raw, y: 0)) }
        XCTAssertEqual(p.expiresAt.timeIntervalSince1970,130)
    }
    func testOneUseAndAllOwnerEpochGenerationExpiryBindings() throws {
        let store = WindowFramePermitStore(), p = try permit(); store.install(p)
        for (owner,epoch,generation,now) in [(try owner("other"),"e",2,UInt64(100)),(try owner("s",client:"other"),"e",2,100),(try owner(),"new",2,100),(try owner(),"e",3,100),(try owner(),"e",2,p.deadline)] {
            XCTAssertThrowsError(try store.lookup(id:p.id,owner:owner,epoch:epoch,generation:generation,now:now))
        }
        _ = try store.consume(id:p.id,owner:p.owner,epoch:"e",generation:2,now:101)
        XCTAssertThrowsError(try store.consume(id:p.id,owner:p.owner,epoch:"e",generation:2,now:102))
        XCTAssertThrowsError(try WindowFramePermitStore().lookup(id:p.id,owner:p.owner,epoch:"e",generation:2,now:102))
        store.install(p); store.clear(); XCTAssertThrowsError(try store.lookup(id:p.id,owner:p.owner,epoch:"e",generation:2,now:102))
        store.install(p); let replacement = try permit(String(repeating:"d",count:32)); store.install(replacement)
        XCTAssertThrowsError(try store.lookup(id:p.id,owner:p.owner,epoch:"e",generation:2,now:102))
    }
    func testAxisLimitMatchesBoundedWireCoordinates() throws {
        func elongated(_ width: Int, _ height: Int) throws -> WindowFramePermit {
            try WindowFramePermit(id:String(repeating:"b",count:32),owner:owner(),helperEpoch:"e",fenceGeneration:2,bundleId:"com.fixture.app",pid:42,processStartToken:"100:1",windowId:99,displayId:1,
                                  bounds:CGRect(x:0,y:0,width:width,height:height),widthPixels:width,heightPixels:height,scale:1,contentHash:String(repeating:"c",count:64),capturedAt:Date(),uptime:100)
        }
        let horizontal = try elongated(32768,1), vertical = try elongated(1,32768)
        XCTAssertEqual(try horizontal.point(x:32767,y:0).0,32767)
        XCTAssertEqual(try vertical.point(x:0,y:32767).1,32767)
        XCTAssertThrowsError(try elongated(32769,1)); XCTAssertThrowsError(try elongated(1,32769))
        XCTAssertThrowsError(try elongated(32768,32768))
    }
    func testConcurrentConsumeHasOneWinner() throws {
        let store = WindowFramePermitStore(), p = try permit(); store.install(p)
        let lock = NSLock(); var winners = 0
        DispatchQueue.concurrentPerform(iterations: 20) { _ in
            if (try? store.consume(id:p.id,owner:p.owner,epoch:"e",generation:2,now:101)) != nil { lock.lock(); winners += 1; lock.unlock() }
        }
        XCTAssertEqual(winners,1)
    }
}
