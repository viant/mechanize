import XCTest
import ApplicationServices
@testable import MechanizeNative

final class BoundedSnapshotChildrenTests: XCTestCase {
    func testHugeArrayRequestsOnlyBoundedPrefixAndStaysIncomplete() throws {
        let root = AXUIElementCreateApplication(101)
        let result = try boundedSnapshotChildren(root, check: {}, count: { _ in (.success, Int.max) }, prefix: { _, amount in
            XCTAssertEqual(amount, 1001)
            return (.success, Array(repeating: root, count: amount))
        })
        XCTAssertEqual(result.elements.count, 1001)
        XCTAssertFalse(result.complete)
    }
    func testCountChangeAndShortReadCannotProveCompleteCoverage() throws {
        let root = AXUIElementCreateApplication(101)
        var calls = 0
        let changing = try boundedSnapshotChildren(root, check: {}, count: { _ in calls += 1; return (.success, calls == 1 ? 2 : 3) }, prefix: { _, _ in (.success, [root, root]) })
        XCTAssertFalse(changing.complete)
        let short = try boundedSnapshotChildren(root, check: {}, count: { _ in (.success, 2) }, prefix: { _, _ in (.success, [root]) })
        XCTAssertFalse(short.complete)
    }
    func testTransportAndMalformedResultsDoNotFallBackToFullRead() throws {
        let root = AXUIElementCreateApplication(101)
        for result in [(AXError.cannotComplete, nil as [AXUIElement]?), (.success, nil), (.success, [root, root, root]), (.noValue, [root])] {
            let read = try boundedSnapshotChildren(root, check: {}, count: { _ in (.success, 2) }, prefix: { _, _ in result })
            XCTAssertTrue(read.elements.isEmpty)
            XCTAssertFalse(read.complete)
        }
        let failed = try boundedSnapshotChildren(root, check: {}, count: { _ in (.cannotComplete, 0) }, prefix: { _, _ in XCTFail("unexpected read"); return (.success, []) })
        XCTAssertFalse(failed.complete)
    }
    func testSmallStableArrayAndExplicitLeafAreComplete() throws {
        let root = AXUIElementCreateApplication(101)
        let stable = try boundedSnapshotChildren(root, check: {}, count: { _ in (.success, 1) }, prefix: { _, _ in (.success, [root]) })
        XCTAssertTrue(stable.complete)
        let leaf = try boundedSnapshotChildren(root, check: {}, count: { _ in (.attributeUnsupported, 0) }, prefix: { _, _ in XCTFail("unexpected read"); return (.success, []) })
        XCTAssertTrue(leaf.complete)
    }
}
