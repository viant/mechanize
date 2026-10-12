import XCTest
import Darwin
@testable import ConsentCore

private final class ReadinessSignedFixture: BrokerPeerAuthenticator {
    var calls = 0
    var rejected = false
    func authenticate(socket: Int32) throws { calls += 1; if rejected { throw MigrationConsoleError.unavailable } }
}
private final class ReadinessTransportFixture: FramedBrokerTransport {
    var closed = false
    func connectAuthenticated() throws {}
    func exchange(_ request: Data) throws -> Data { Data() }
    func close() { closed = true }
}
final class MigrationVaultReadinessTests: XCTestCase {
    func testActualSocketPIDAndBirthMustMatchBeforeSignedAdmission() throws {
        for mode in ["pid", "uid", "birth"] {
            let signed = ReadinessSignedFixture()
            let peer = MigrationExactBrokerPeer(signed: signed, pid: 123, start: "100:200", uid: 501,
                inspect: { _ in (mode == "uid" ? 502 : 501, mode == "birth" ? "100:201" : "100:200") },
                socketPID: { _ in mode == "pid" ? 124 : 123 })
            XCTAssertThrowsError(try peer.authenticate(socket: 9)); XCTAssertEqual(signed.calls, 0)
        }
    }
    func testPeerGenerationIsRecheckedAroundCodeVerification() throws {
        let signed = ReadinessSignedFixture(); var inspections = 0
        let peer = MigrationExactBrokerPeer(signed: signed, pid: 123, start: "100:200", uid: 501,
            inspect: { _ in inspections += 1; return (501, inspections == 1 ? "100:200" : "100:201") }, socketPID: { _ in 123 })
        XCTAssertThrowsError(try peer.authenticate(socket: 9)); XCTAssertEqual(signed.calls, 1)
    }
    func testPostResponseCloseChecksSamePeerOnce() throws {
        let signed = ReadinessSignedFixture(); var birth = "100:200"
        let peer = MigrationExactBrokerPeer(signed: signed, pid: 123, start: "100:200", uid: 501,
            inspect: { _ in (501, birth) }, socketPID: { _ in 123 })
        try peer.authenticate(socket: 9)
        let base = ReadinessTransportFixture(); let transport = MigrationVerifiedCloseTransport(base: base, peer: peer)
        birth = "100:201"; transport.close()
        XCTAssertFalse(transport.verifiedAfterResponse); XCTAssertTrue(base.closed)
        birth = "100:200"; transport.close(); XCTAssertFalse(transport.verifiedAfterResponse)
    }
    func testExactPostResponsePeerAllowsBooleanReadiness() throws {
        let signed = ReadinessSignedFixture()
        let peer = MigrationExactBrokerPeer(signed: signed, pid: 123, start: "100:200", uid: 501,
            inspect: { _ in (501, "100:200") }, socketPID: { _ in 123 })
        try peer.authenticate(socket: 9)
        let base = ReadinessTransportFixture(); let transport = MigrationVerifiedCloseTransport(base: base, peer: peer)
        transport.close(); XCTAssertTrue(transport.verifiedAfterResponse); XCTAssertEqual(signed.calls, 2)
    }
    func testMalformedPublicProcessArgumentsNeverReachKeychain() {
        for args in [["--check-vault"], ["--check-vault","--broker-pid","0","--broker-start","100:200"], ["--check-vault","--broker-pid","123","--broker-start","caller-claim"]] {
            let report = MigrationVaultReadiness.runCLI(arguments: args)
            XCTAssertFalse(report.succeeded); XCTAssertEqual(report.errorCode, "invalidArguments")
        }
    }
}
