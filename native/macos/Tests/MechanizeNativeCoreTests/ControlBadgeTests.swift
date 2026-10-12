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
    func testMeasuredPlacementPrefersLeadingZoneAndFallsBackToReducedLeadingMark() {
        let window = CGRect(x: 300, y: 50, width: 1000, height: 700)
        let lights = (0..<3).map { CGRect(x: window.minX + 14 + CGFloat($0 * 20), y: window.minY + 18, width: 12, height: 12) }
        XCTAssertEqual(ControlBadgeGeometry.leadingZoneEnd(window: window, trafficLights: lights), window.minX + 66 + 60)
        XCTAssertEqual(ControlBadgeGeometry.freeHeaderFrame(window: window, trafficLights: lights, occupied: []), CGRect(x: window.minX + 68, y: window.minY + 15, width: 46, height: 18))
        let crowded = CGRect(x: window.minX + 80, y: window.minY, width: 200, height: 44)
        let reduced = ControlBadgeGeometry.freeHeaderFrame(window: window, trafficLights: lights, occupied: [crowded])!
        XCTAssertEqual(reduced, CGRect(x: window.minX + 6, y: window.minY + 2, width: 22, height: 12))
        // A narrow window clamps the zone to its own trailing inset.
        let narrow = CGRect(x: 0, y: 0, width: 120, height: 100), narrowLights = (0..<3).map { CGRect(x: 14 + CGFloat($0 * 20), y: 18, width: 12, height: 12) }
        XCTAssertEqual(ControlBadgeGeometry.leadingZoneEnd(window: narrow, trafficLights: narrowLights), 114)
        XCTAssertEqual(ControlBadgeGeometry.freeHeaderFrame(window: narrow, trafficLights: narrowLights, occupied: []), CGRect(x: 68, y: 15, width: 46, height: 18))
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
