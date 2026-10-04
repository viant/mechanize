import XCTest
@testable import MechanizeNativeCore
final class SessionKeyboardTests:XCTestCase {
 func validate(parents:[Int:Int],window:Int=4,owners:[Int:Int32]=[:],expired:Bool=false,recheck:Int?=nil)throws {
  try SessionWindowProof.validate(target:1,focusedWindow:window,rootPID:42,owner:{owners[$0] ?? 42},role:{_ in "AXSheet"},parent:{parents[$0]},equal:{$0==$1},recheck:{recheck ?? window},check:{if expired{throw NativeFailure("staleReference","expired")}})
 }
 func testExactSheetAncestryAndMismatchCycleForeignOwnerExpiredFail()throws {
  try validate(parents:[1:2,2:4])
  for body in [{try self.validate(parents:[1:2,2:3])},{try self.validate(parents:[1:2,2:1])},{try self.validate(parents:[1:2,2:4],owners:[2:77])},{try self.validate(parents:[1:4],expired:true)}] {XCTAssertThrowsError(try body())}
 }
 func testSameApplicationContainerSwitchDuringProofIsRejected() {
  XCTAssertThrowsError(try validate(parents:[1:2,2:4],recheck:5)) {error in XCTAssertEqual((error as? NativeFailure)?.code,"sessionWindowUnqualified")}
 }
 func testExplicitSessionRouteNeverFallsBackAndFailedKeyupRetainsSameRoute() {
  let inputs=InputSafety();inputs.enable();var routes:[KeyboardDelivery]=[];var downs=0;var release=false
  XCTAssertThrowsError(try KeyboardPosting.press(inputs:inputs,token:"session-key",delivery:.session,preflight:{},down:{route in routes.append(route);downs+=1;return true},up:{route in routes.append(route);return release}))
  XCTAssertEqual(inputs.inhibitAndRelease().unknown,1)
  XCTAssertThrowsError(try KeyboardPosting.press(inputs:inputs,token:"other",delivery:.process,preflight:{},down:{_ in downs+=1;return true},up:{_ in true}))
  release=true;XCTAssertEqual(inputs.inhibitAndRelease().released,1)
  XCTAssertEqual(downs,1);XCTAssertTrue(routes.allSatisfy{$0 == .session})
 }
 func testCanceledAdmissionCannotPostAndProcessRouteStaysProcess()throws {
  let inputs=InputSafety();inputs.enable();var routes:[KeyboardDelivery]=[]
  XCTAssertThrowsError(try KeyboardPosting.press(inputs:inputs,token:"key",delivery:.session,preflight:{throw NativeFailure("staleLease","revoked")},down:{route in routes.append(route);return true},up:{route in routes.append(route);return true}))
  XCTAssertTrue(routes.isEmpty)
  try KeyboardPosting.press(inputs:inputs,token:"key",delivery:.process,preflight:{},down:{route in routes.append(route);return true},up:{route in routes.append(route);return true})
  XCTAssertEqual(routes,[.process,.process])
 }
 func testBoundedAncestryCannotWalkForever() {
  var reads=0
  XCTAssertThrowsError(try SessionWindowProof.validate(target:0,focusedWindow:100,rootPID:42,owner:{_ in 42},role:{_ in "AXWindow"},parent:{node in reads+=1;return node+1},equal:{$0==$1},recheck:{100},check:{}))
  XCTAssertEqual(reads,16)
 }
}
