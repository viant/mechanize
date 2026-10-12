import XCTest
import CoreGraphics
@testable import MechanizeNativeCore

final class ControlBadgeTests: XCTestCase {
    func testBadgeUsesWindowGeometryAndAvoidsTrafficLights() {
        let window = CGRect(x: -1200, y: 80, width: 900, height: 700)
        let badge = ControlBadgeGeometry.frame(window: window)!
        XCTAssertTrue(window.contains(badge))
        XCTAssertEqual(badge.minX, window.minX + 84)
        XCTAssertEqual(badge.minY, window.minY + 8)
        XCTAssertEqual(badge.size, CGSize(width: 46, height: 18))
        XCTAssertEqual(ControlBadgeGeometry.frame(window: CGRect(x: 0, y: 0, width: 303, height: 100))?.width,46)
        XCTAssertEqual(ControlBadgeGeometry.frame(window: CGRect(x: 0, y: 0, width: 200, height: 100))?.minX,84)
        XCTAssertNil(ControlBadgeGeometry.frame(window:CGRect(x:0,y:0,width:119,height:48)))
        XCTAssertNil(ControlBadgeGeometry.frame(window: CGRect(x: CGFloat.infinity, y: 0, width: 900, height: 700)))
    }
    func testHeartbeatInvalidatesOldLeaseWithoutChangingOwner() {
        var life = ControlBadgeLifetime()
        let owner = life.begin(), firstLease = life.leaseRevision
        let renewed = life.renew(owner)!
        XCTAssertFalse(life.expire(owner, revision: firstLease))
        XCTAssertTrue(life.active)
        XCTAssertEqual(life.generation, owner)
        XCTAssertTrue(life.expire(owner, revision: renewed))
        XCTAssertNil(life.renew(owner))
        let next = life.begin()
        XCTAssertNil(life.renew(owner))
        XCTAssertTrue(life.end(next))
    }
    func testStopFailureAndOldIdleTimersCannotClaimCurrentControl() {
        var life = ControlBadgeLifetime()
        let first = life.begin()
        let second = life.begin()
        XCTAssertFalse(life.end(first))
        XCTAssertTrue(life.active)
        XCTAssertTrue(life.end(second))
        XCTAssertFalse(life.active)
        let third = life.begin()
        life.stop()
        XCTAssertFalse(life.active)
        XCTAssertFalse(life.end(third))
        let next = life.begin()
        XCTAssertFalse(life.end(second))
        XCTAssertTrue(life.end(next))
        XCTAssertFalse(life.active)
    }
}
