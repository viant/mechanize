import XCTest
@testable import MechanizeNative

final class HierarchyObserverTests: XCTestCase {
    func testRetiredSignalCannotInvalidateFutureReferences() {
        let signal = HierarchySignal()
        signal.changed()
        XCTAssertEqual(signal.revision, 1)
        signal.retire()
        signal.changed()
        signal.retire()
        XCTAssertEqual(signal.revision, 1)
    }

    func testConcurrentCallbacksPreserveEveryInvalidation() {
        let signal = HierarchySignal()
        DispatchQueue.concurrentPerform(iterations: 1000) { _ in signal.changed() }
        XCTAssertEqual(signal.revision, 1000)
        signal.retire()
        DispatchQueue.concurrentPerform(iterations: 1000) { _ in signal.changed() }
        XCTAssertEqual(signal.revision, 1000)
    }

    func testStoppedObserverCannotStartOrReuseItsCallbackContext() {
        // No AX access or process discovery is performed after stop.
        let observer = HierarchyObserver(pid: -1, birth: "synthetic")
        observer.stop()
        XCTAssertFalse(observer.start())
        XCTAssertFalse(observer.start())
        observer.signal.changed()
        XCTAssertEqual(observer.signal.revision, 0)
    }
}
