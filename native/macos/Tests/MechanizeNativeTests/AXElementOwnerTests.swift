import XCTest
import ApplicationServices
@testable import MechanizeNative
final class AXElementOwnerTests:XCTestCase {
 func testActualForeignOwnerIsMetadataNotRootRoutingSubstitution() {
  let runtime=AXElementOwnerRuntime(owner:{_ in (.success,77)},uid:{_ in 501},birth:{_ in "100:1"},bundle:{_ in "com.apple.panel.fixture"})
  let owner=inspectAXElementOwner(AXUIElementCreateApplication(42),runtime:runtime)
  let fields=owner.metadata(root:42)
  XCTAssertEqual(fields["nativeOwnerProcessId"] as? pid_t,77);XCTAssertEqual(fields["nativeOwnerMatchesRoot"] as? Bool,false)
  XCTAssertEqual(fields["nativeOwnerUid"] as? uid_t,501);XCTAssertEqual(fields["nativeOwnerStartToken"] as? String,"100:1")
 }
 func testMissingOwnerAndChangingBirthDoNotGuessIdentity() {
  let missing=AXElementOwnerRuntime(owner:{_ in (.cannotComplete,0)},uid:{_ in XCTFail("must not inspect unknown PID");return nil},birth:{_ in nil},bundle:{_ in nil})
  let fields=inspectAXElementOwner(AXUIElementCreateApplication(42),runtime:missing).metadata(root:42)
  XCTAssertNil(fields["nativeOwnerProcessId"]);XCTAssertNil(fields["nativeOwnerMatchesRoot"])
  var calls=0
  let changed=AXElementOwnerRuntime(owner:{_ in (.success,77)},uid:{_ in 501},birth:{_ in calls+=1;return calls==1 ? "100:1":"100:2"},bundle:{_ in "fixture"})
  let owner=inspectAXElementOwner(AXUIElementCreateApplication(42),runtime:changed)
  XCTAssertEqual(owner.pid,77);XCTAssertNil(owner.birth);XCTAssertNil(owner.uid);XCTAssertNil(owner.bundle)
 }
}
