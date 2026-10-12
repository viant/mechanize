import XCTest
import ApplicationServices
@testable import MechanizeNative

final class SnapshotChildrenTests: XCTestCase {
    func testSelfAndDuplicateEdgesDoNotConsumeDescendantBudget() {
        let parent = AXUIElementCreateApplication(101)
        let sameParent = AXUIElementCreateApplication(101)
        let first = AXUIElementCreateApplication(102)
        let sameFirst = AXUIElementCreateApplication(102)
        let second = AXUIElementCreateApplication(103)
        let result = snapshotChildren([parent, first, sameParent, sameFirst, second], of: parent)
        XCTAssertEqual(result.selfEdges, 2)
        XCTAssertEqual(result.duplicateEdges, 1)
        XCTAssertFalse(result.truncated)
        XCTAssertEqual(result.elements.count, 2)
        XCTAssertTrue(CFEqual(result.elements[0], first))
        XCTAssertTrue(CFEqual(result.elements[1], second))
    }
    func testLongerCyclesAreNotSilentlyRewritten() {
        let ancestor = AXUIElementCreateApplication(101)
        let parent = AXUIElementCreateApplication(102)
        let result = snapshotChildren([ancestor], of: parent)
        XCTAssertEqual(result.elements.count, 1)
        XCTAssertEqual(result.selfEdges, 0)
    }
    func testUninspectedEdgesRemainIncompleteEvenIfTheyLookLikeAliases() {
        let parent = AXUIElementCreateApplication(101)
        let result = snapshotChildren(Array(repeating: parent, count: 1002), of: parent)
        XCTAssertTrue(result.truncated)
        XCTAssertEqual(result.selfEdges, 1001)
        XCTAssertTrue(result.elements.isEmpty)
    }
}
