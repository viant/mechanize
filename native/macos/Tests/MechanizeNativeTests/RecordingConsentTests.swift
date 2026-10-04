import XCTest
@testable import MechanizeNative

final class RecordingConsentTests: XCTestCase {
    func start() -> [String: Any] {
        ["recordingId":"owned-record", "namespace":String(repeating:"a",count:64), "clientId":"verified-client", "sessionId":"session", "consentNonce":String(repeating:"b",count:64), "expectedUID":NSNumber(value:501), "maxEvents":NSNumber(value:4096), "maxDurationMs":NSNumber(value:60_000), "grantRemainingMs":NSNumber(value:25_000)]
    }
    func control(_ input: [String:Any], method: String) -> [String:Any] {
        var result=input
        for key in ["expectedUID","maxEvents","maxDurationMs","grantRemainingMs"] { result.removeValue(forKey:key) }
        if method=="record.renew"{result["grantRemainingMs"]=NSNumber(value:25_000)}
        if ["record.events","record.pause","record.stop"].contains(method){result["afterSequence"]=NSNumber(value:64);result["limit"]=NSNumber(value:64)}
        return result
    }
    func testOwnedBindingRenewalAndWithdrawCannotResume() throws {
        let lease=RecordingConsentLease();let input=start()
        let options=try lease.begin(input,expectedUID:501)
        XCTAssertEqual(options.expectedUID,501);XCTAssertEqual(options.maxEvents,4096);XCTAssertTrue(lease.alive())
        XCTAssertEqual(lease.owner()?["sessionId"],"session")
        XCTAssertNil(lease.owner()?["consentNonce"])
        try lease.renew(control(input,method:"record.renew"))
        for method in ["record.events","record.pause","record.stop"]{try lease.check(control(input,method:method),method:method)}
        lease.withdraw();XCTAssertFalse(lease.alive())
        XCTAssertThrowsError(try lease.renew(control(input,method:"record.renew")))
        // Draining/stopping remains permitted for the already-bound owner.
        try lease.check(control(input,method:"record.stop"),method:"record.stop")
        XCTAssertThrowsError(try lease.begin(input,expectedUID:501))
    }
    func testForeignScopeNonceMixedKeysAndNumericBooleansFailClosed() throws {
        let lease=RecordingConsentLease();let input=start();_ = try lease.begin(input,expectedUID:501)
        for key in ["namespace","clientId","sessionId","consentNonce","recordingId"]{
            var changed=control(input,method:"record.events");changed[key]="foreign"
            XCTAssertThrowsError(try lease.check(changed,method:"record.events"))
        }
        var extra=control(input,method:"record.stop");extra["script"]="arbitrary"
        XCTAssertThrowsError(try lease.check(extra,method:"record.stop"))
        var bad=start();bad["expectedUID"]=NSNumber(value:true)
        XCTAssertThrowsError(try RecordingConsentLease().begin(bad,expectedUID:1))
        bad=start();bad["grantRemainingMs"]=NSNumber(value:30_001)
        XCTAssertThrowsError(try RecordingConsentLease().begin(bad,expectedUID:501))
        bad=start();bad["expectedUID"]=NSNumber(value:502)
        XCTAssertThrowsError(try RecordingConsentLease().begin(bad,expectedUID:501))
    }
}
