import XCTest
import Darwin
@testable import MechanizeNative
import MechanizeNativeCore
final class ForegroundProofTests:XCTestCase {
 func identity(pid:pid_t=42,uid:uid_t=getuid(),birth:String="100:1",active:Bool=true)->ForegroundIdentity {ForegroundIdentity(pid:pid,uid:uid,birth:birth,bundle:"com.fixture.app",active:active)}
 func testUnavailableSystemAXDoesNotDiscardIndependentRefreshedPublicProof()throws{
  var refreshed=0
  let runtime=ForegroundProofRuntime(refresh:{_ in refreshed+=1},current:{self.identity()},corroborate:{nil})
  let value=try qualifiedForeground(identity(),Budget(milliseconds:1000),runtime:runtime)
  XCTAssertEqual(value.pid,42);XCTAssertEqual(refreshed,1)
 }
 func testStaleDifferentUIDBirthInactiveAndConflictingAvailableCorroborationFail() {
  let cases:[(ForegroundIdentity,pid_t?,String)] = [(identity(pid:43),nil,"foregroundChanged"),(identity(uid:getuid()+1),nil,"foregroundOwnerUnqualified"),(identity(birth:"100:2"),nil,"staleReference"),(identity(active:false),nil,"foregroundNotActive"),(identity(),43,"foregroundCorroborationConflict")]
  for (current,system,code) in cases {
   let runtime=ForegroundProofRuntime(refresh:{_ in},current:{current},corroborate:{system})
   XCTAssertThrowsError(try qualifiedForeground(identity(),Budget(milliseconds:1000),runtime:runtime)){error in XCTAssertEqual((error as? NativeFailure)?.code,code)}
  }
 }
 func testAvailableMatchingCorroborationAndChangingForegroundBetweenChecks()throws{
  var reads=0
  let runtime=ForegroundProofRuntime(refresh:{_ in},current:{reads+=1;return self.identity(pid:reads==1 ? 42:43)},corroborate:{nil})
  _ = try qualifiedForeground(identity(),Budget(milliseconds:1000),runtime:runtime)
  XCTAssertThrowsError(try qualifiedForeground(identity(),Budget(milliseconds:1000),runtime:runtime))
  let agreeing=ForegroundProofRuntime(refresh:{_ in},current:{self.identity()},corroborate:{42})
  XCTAssertEqual(try qualifiedForeground(identity(),Budget(milliseconds:1000),runtime:agreeing).pid,42)
 }
 func testRefreshFailureCannotQualifyCachedFrontmost() {
  var currentReads=0
  let runtime=ForegroundProofRuntime(refresh:{_ in throw NativeFailure("foregroundRefreshUnavailable","bounded refresh failed")},current:{currentReads+=1;return self.identity()},corroborate:{nil})
  XCTAssertThrowsError(try qualifiedForeground(identity(),Budget(milliseconds:1000),runtime:runtime))
  XCTAssertEqual(currentReads,0)
 }
}
