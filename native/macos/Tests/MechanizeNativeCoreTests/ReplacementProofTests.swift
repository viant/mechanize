import XCTest
@testable import MechanizeNativeCore
final class ReplacementProofTests:XCTestCase {
 func testOnlyKnownNonsecureEditableTextClassification() {
  XCTAssertTrue(ReplacementProof.permitted(role:"AXTextField",subrole:nil,subroleKnown:true,valueSettable:true,labels:["Go to folder"]))
  for value in [("AXTextField", "AXSecureTextField",true,true,"Path"),("AXTextField","",false,true,"Path"),("AXButton","",true,true,"Path"),("AXTextArea","",true,false,"Path"),("AXTextField","",true,true,"Password")] {XCTAssertFalse(ReplacementProof.permitted(role:value.0,subrole:value.1,subroleKnown:value.2,valueSettable:value.3,labels:[value.4]))}
 }
 func testReplacementSetterOnceThenIndependentReadWithoutContents()throws{
  var writes=0,reads=0,checks=0
  let proof=try ReplacementProof.perform(expected:"/fixture/frozen",permitted:true,set:{writes+=1;return true},read:{reads+=1;return "/fixture/frozen"},revalidate:{checks+=1})
  XCTAssertEqual(proof,true);XCTAssertEqual(writes,1);XCTAssertEqual(reads,1);XCTAssertEqual(checks,2)
 }
 func testUnknownClassificationReadErrorOrChangedIdentityNeverRepeatsSetter()throws{
  for failure in ["protected","read","identity","normalized"]{
   var writes=0
   let proof=try ReplacementProof.perform(expected:"/exact/path",permitted:failure != "protected",set:{writes+=1;return true},read:{if failure=="read"{throw NativeFailure("unavailable","read unavailable")};return failure=="normalized" ? "/different/path":"/exact/path"},revalidate:{if failure=="identity"{throw NativeFailure("staleReference","birth/fence changed")}})
   XCTAssertNotEqual(proof,true);XCTAssertEqual(writes,1)
  }
 }
 func testUnicodeNormalizationDoesNotCountAsExactReplacement()throws {
  let expected="\u{e9}";let normalized="e\u{301}"
  XCTAssertEqual(expected,normalized)
  let proof=try ReplacementProof.perform(expected:expected,permitted:true,set:{true},read:{normalized},revalidate:{})
  XCTAssertEqual(proof,false)
 }
 func testExpiredPrewriteFailsWithoutWritingOrReading() {
  var writes=0,reads=0
  XCTAssertThrowsError(try ReplacementProof.perform(expected:"path",permitted:true,set:{throw NativeFailure("deadlineExceeded","expired")},read:{reads+=1;return "path"},revalidate:{}))
  XCTAssertEqual(writes,0);XCTAssertEqual(reads,0)
 }
 func testAsynchronousReplacementSettlesByReadOnlyPolling() throws {
  var clock:TimeInterval=100, writes=0, reads=0, checks=0, waits=0
  let proof=try ReplacementProof.perform(expected:"public-literal",permitted:true,set:{writes+=1;return true},read:{
   reads+=1
   return reads==1 ? "prior-value" : reads==2 ? nil : "public-literal"
  },revalidate:{checks+=1},now:{clock},wait:{delay in waits+=1;clock+=delay})
  XCTAssertEqual(proof,true);XCTAssertEqual(writes,1);XCTAssertEqual(reads,3)
  XCTAssertEqual(checks,6);XCTAssertEqual(waits,2);XCTAssertEqual(clock,100.050,accuracy:0.000_001)
 }
 func testUnchangedMismatchIsBoundedByTenReadsAndNeverRepeatsInput() throws {
  var clock:TimeInterval=0, writes=0, reads=0, waits=0
  let proof=try ReplacementProof.perform(expected:"expected",permitted:true,set:{writes+=1;return true},read:{reads+=1;return "different"},revalidate:{},now:{clock},wait:{delay in waits+=1;clock+=delay})
  XCTAssertEqual(proof,false);XCTAssertEqual(writes,1);XCTAssertEqual(reads,10);XCTAssertEqual(waits,9)
  XCTAssertLessThanOrEqual(clock,0.250)
 }
 func testTimeoutDoesNotReadOrConfirmAfterSettlingBudget() throws {
  var clock:TimeInterval=0, writes=0, reads=0
  let proof=try ReplacementProof.perform(expected:"expected",permitted:true,set:{writes+=1;return true},read:{reads+=1;return "different"},revalidate:{},timeout:0.050,now:{clock},wait:{clock+=$0})
  XCTAssertEqual(proof,false);XCTAssertEqual(writes,1);XCTAssertEqual(reads,2)
  XCTAssertEqual(clock,0.050,accuracy:0.000_001)
  let late=try ReplacementProof.perform(expected:"expected",permitted:true,set:{true},read:{clock+=0.300;return "expected"},revalidate:{},now:{clock},wait:{clock+=$0})
  XCTAssertNotEqual(late,true)
 }
 func testLeaseProcessOrClassificationChangeDuringWaitAbortsBeforeNextRead() throws {
  for authority in ["lease","process","classification","deadline"] {
   var clock:TimeInterval=0, valid=true, writes=0, reads=0, checks=0
   let proof=try ReplacementProof.perform(expected:"expected",permitted:true,set:{writes+=1;return true},read:{reads+=1;return "previous"},revalidate:{
    checks+=1
    if !valid {throw NativeFailure("replacementUnconfirmed",authority+" changed")}
   },now:{clock},wait:{clock+=$0;valid=false})
   XCTAssertNil(proof);XCTAssertEqual(writes,1);XCTAssertEqual(reads,1);XCTAssertEqual(checks,3)
  }
 }
 func testPostReadRevalidationRejectsMatchAndWaitCancellationNeverRetries() throws {
  var writes=0,reads=0,checks=0
  let changed=try ReplacementProof.perform(expected:"expected",permitted:true,set:{writes+=1;return true},read:{reads+=1;return "expected"},revalidate:{checks+=1;if checks==2 {throw NativeFailure("staleLease","lease changed")}})
  XCTAssertNil(changed);XCTAssertEqual(writes,1);XCTAssertEqual(reads,1)
  var clock:TimeInterval=0
  let cancelled=try ReplacementProof.perform(expected:"expected",permitted:true,set:{writes+=1;return true},read:{reads+=1;return "previous"},revalidate:{},now:{clock},wait:{_ in throw NativeFailure("deadlineExceeded","cancelled")})
  XCTAssertNil(cancelled);XCTAssertEqual(writes,2);XCTAssertEqual(reads,2)
  clock+=1
 }
 func testProtectedOrBoundReplacementNeverReadsComparesOrWaits() throws {
  var writes=0,reads=0,checks=0,waits=0,clockReads=0
  let proof=try ReplacementProof.perform(expected:"protected-value",permitted:false,set:{writes+=1;return true},read:{reads+=1;return "protected-value"},revalidate:{checks+=1},now:{clockReads+=1;return 0},wait:{_ in waits+=1})
  XCTAssertNil(proof);XCTAssertEqual(writes,1);XCTAssertEqual(reads,0);XCTAssertEqual(checks,0);XCTAssertEqual(waits,0);XCTAssertEqual(clockReads,0)
 }
 func testInvalidPollingBoundsCannotCreateUnboundedReadProof() throws {
  for bounds in [(0.251,0.025,10),(0.250,0.0,10),(0.250,0.025,11),(0.250,0.025,0)] {
   var writes=0,reads=0
   let proof=try ReplacementProof.perform(expected:"expected",permitted:true,set:{writes+=1;return true},read:{reads+=1;return "expected"},revalidate:{},timeout:bounds.0,pollInterval:bounds.1,maximumReads:bounds.2,now:{0},wait:{_ in XCTFail("invalid policy waited")})
   XCTAssertNil(proof);XCTAssertEqual(writes,1);XCTAssertEqual(reads,0)
  }
 }
 func testMalformedOrRegressingClockDoesNotConfirmValue() throws {
  for mode in ["oversize","nul","backwards"] {
   var clock:TimeInterval=1,reads=0
   let proof=try ReplacementProof.perform(expected:"expected",permitted:true,set:{true},read:{reads+=1;return mode=="oversize" ? String(repeating:"x",count:65_537) : mode=="nul" ? "expected\0" : "previous"},revalidate:{},now:{clock},wait:{_ in clock-=0.001})
   XCTAssertNotEqual(proof,true);XCTAssertEqual(reads,1)
  }
 }
}
