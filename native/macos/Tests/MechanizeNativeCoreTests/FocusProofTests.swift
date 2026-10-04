import XCTest
@testable import MechanizeNativeCore
final class FocusProofTests:XCTestCase {
 func testSettlesReadOnlyWithoutRepeatingSetter() throws {
  var reads=0,refreshes=0;var now:UInt64=0
  try FocusProof.settle(clock:{now},validate:{reads+=1;if reads<3{throw NativeFailure("focusNotObserved","pending")}},refresh:{refreshes+=1},pause:{now+=20_000_000})
  XCTAssertEqual(reads,3);XCTAssertEqual(refreshes,2)
 }
 func testStrictFocusedIdentityMismatchRemainsDistinctAndBounded() {
  var now:UInt64=0,reads=0
  XCTAssertThrowsError(try FocusProof.settle(maximumNanoseconds:40_000_000,clock:{now},validate:{reads+=1;throw NativeFailure("focusedIdentityMismatch","different reference")},refresh:{},pause:{now+=20_000_000})) {error in XCTAssertEqual((error as? NativeFailure)?.code,"focusedIdentityMismatch")}
  XCTAssertEqual(reads,3)
 }
 func testRevokedOrProtectedStateNeverWaitsThroughFailure() {
  for code in ["staleReference","secureInput","sessionUnqualified","targetDisabledOrUnknown","targetClassificationUnknown","deadlineExceeded"]{
   var refreshes=0
   XCTAssertThrowsError(try FocusProof.settle(validate:{throw NativeFailure(code,"fixture")},refresh:{refreshes+=1},pause:{})){error in XCTAssertEqual((error as? NativeFailure)?.code,code)}
   XCTAssertEqual(refreshes,0)
  }
 }
 func testIterationCapBoundsBrokenClockAndWorkspaceRefresh() {
  var reads=0
  XCTAssertThrowsError(try FocusProof.settle(clock:{0},validate:{reads+=1;throw NativeFailure("foregroundChanged","pending refresh")},refresh:{},pause:{}))
  XCTAssertEqual(reads,40)
 }
}

extension FocusProofTests {
 func testOnlyPositiveNonfocusEvidenceProducesFalse() {
  for code in ["focusNotObserved","focusedIdentityMismatch","foregroundChanged"] {XCTAssertTrue(FocusProof.nonfocusedReason(code))}
  for code in ["foregroundUnavailable","targetFocusUnavailable","focusedIdentityUnavailable","secureInput","targetClassificationUnknown","sessionUnqualified","staleReference"] {XCTAssertFalse(FocusProof.nonfocusedReason(code))}
 }
}
extension FocusProofTests {
 func testReadPreservesExactUnknownReasonWithoutConvertingToFalse()throws {
  XCTAssertTrue(try FocusProof.read(validate:{}))
  for code in ["focusNotObserved","focusedIdentityMismatch","foregroundChanged"] {XCTAssertFalse(try FocusProof.read(validate:{throw NativeFailure(code,"known nonfocus")}))}
  for code in ["targetFocusUnavailable","focusedIdentityUnavailable","targetClassificationUnknown","sessionUnqualified","secureInput","staleReference"] {
   XCTAssertThrowsError(try FocusProof.read(validate:{throw NativeFailure(code,"safe scalar detail")})) {error in
    XCTAssertEqual((error as? NativeFailure)?.code,code)
    XCTAssertEqual((error as? NativeFailure)?.message,"safe scalar detail")
   }
  }
 }
}
