import XCTest
import Darwin
import CryptoKit
@testable import ConsentCore

private final class MigrationCredentialFixture: EnrollmentCredentialProvider {
    var reads = 0
    var value = Data("synthetic-private-enrollment".utf8)
    func credential() throws -> Data { reads += 1; return value }
}
private final class MigrationWireFixture: MigrationConsoleWire {
    var authentications = 0
    var rejectAt = 0
    var input = Data()
    var writes: [Data] = []
    var closed = false
    var failWriteAt = 0
    func authenticate() throws {
        authentications += 1
        if authentications == rejectAt || closed { throw MigrationConsoleError.unavailable }
    }
    func write(_ data: Data, deadline: Date) throws {
        guard deadline > Date(), !closed else { throw MigrationConsoleError.unavailable }
        writes.append(data)
        if writes.count == failWriteAt { throw MigrationConsoleError.unavailable }
    }
    func readExactly(_ count: Int, deadline: Date) throws -> Data {
        guard !closed, deadline > Date(), input.count >= count else { throw MigrationConsoleError.unavailable }
        let result = input.prefix(count); input.removeFirst(count); return Data(result)
    }
    func close() { closed = true }
}
final class MigrationConsoleChannelTests: XCTestCase {
    private func hex(_ letter: String, _ count: Int = 64) -> String { String(repeating: letter, count: count) }
    private func fields() -> [String] {
        [hex("a"), hex("b"), hex("c"), "identifier \"com.viant.mechanize.custody-migration\" and cdhash H\"\(hex("d",40))\"", hex("e"), hex("f"), "/private/tmp/frozen/mechanize", "identifier \"com.viant.mechanize.broker\" and cdhash H\"\(hex("1",40))\"", "identifier \"com.viant.mechanize.broker\" and cdhash H\"\(hex("2",40))\"", "vault-master", "com.viant.mechanize.vault", "fixture-account", hex("e"), hex("3")]
    }
    private func record(_ fields: [String], until: Date) throws -> MigrationAuthorizationRecord {
        try MigrationAuthorizationRecord(workerSession: fields[0], optionsSHA256: fields[2], helperRequirement: fields[3], itemReferenceSHA256: fields[4], transitionID: fields[5], canonicalExecutable: fields[6], oldRequirement: fields[7], newRequirement: fields[8], alias: fields[9], service: fields[10], account: fields[11], transitionBinding: fields[13], validUntil: until)
    }
    private func payload(_ fields: [String], deadline: Date, nonce: UInt8 = 1) -> Data {
        var bytes = Data(repeating: nonce, count: 32)
        var nanos = UInt64(deadline.timeIntervalSince1970 * 1_000_000_000).bigEndian
        withUnsafeBytes(of: &nanos) { bytes.append(contentsOf: $0) }
        for field in fields { let value = Data(field.utf8); var length = UInt16(value.count).bigEndian; withUnsafeBytes(of: &length) { bytes.append(contentsOf: $0) }; bytes.append(value) }
        return bytes
    }
    private func framed(_ data: Data) -> Data {
        var result = MigrationApprovalChallenge.marker; var size = UInt32(data.count).bigEndian
        withUnsafeBytes(of: &size) { result.append(contentsOf: $0) }; result.append(data); return result
    }
    func testPeerMustVerifyBeforeCredentialLookupOrEmission() throws {
        let f = fields(); let credential = MigrationCredentialFixture(); let wire = MigrationWireFixture(); wire.rejectAt = 1
        let channel = MigrationConsoleChannel(wire: wire, credentials: credential, authorization: try record(f, until: Date().addingTimeInterval(60)))
        XCTAssertThrowsError(try channel.attestExistingAuthorization())
        XCTAssertEqual(credential.reads, 0); XCTAssertTrue(wire.writes.isEmpty); XCTAssertTrue(wire.closed)
    }
    func testPeerReverifiedAfterCredentialReadBeforeEmission() throws {
        let credential = MigrationCredentialFixture(); let wire = MigrationWireFixture(); wire.rejectAt = 2
        let channel = MigrationConsoleChannel(wire: wire, credentials: credential, authorization: try record(fields(), until: Date().addingTimeInterval(60)))
        XCTAssertThrowsError(try channel.attestExistingAuthorization())
        XCTAssertEqual(credential.reads, 1); XCTAssertTrue(wire.writes.isEmpty)
    }
    func testExactBinaryCredentialAndExistingAuthorizationAttestation() throws {
        let f = fields(); let until = Date().addingTimeInterval(60); let data = payload(f, deadline: until.addingTimeInterval(-1))
        let wire = MigrationWireFixture(); wire.input = framed(data); let credential = MigrationCredentialFixture()
        let authorization = try record(f, until: until)
        let channel = MigrationConsoleChannel(wire: wire, credentials: credential, authorization: authorization)
        try channel.attestExistingAuthorization()
        XCTAssertEqual(wire.authentications, 7); XCTAssertEqual(wire.writes.count, 2)
        XCTAssertEqual(wire.writes[0].prefix(8), Data([77,77,65,85,84,72,0,1]))
        XCTAssertEqual(wire.writes[0].dropFirst(12), credential.value)
        XCTAssertEqual(wire.writes[0].dropFirst(8).prefix(4), Data([0,0,0,UInt8(credential.value.count)]))
        XCTAssertEqual(wire.writes[1].prefix(9), Data([77,77,65,67,75,0,0,1,1]))
        XCTAssertEqual(wire.writes[1].dropFirst(9).prefix(32), data.prefix(32))
        XCTAssertEqual(wire.writes[1].suffix(32), Data(SHA256.hash(data: data)))
        XCTAssertEqual(wire.writes[1].count, 73); XCTAssertFalse(wire.closed)
        XCTAssertFalse(String(reflecting: channel).contains("synthetic-private")); XCTAssertFalse(String(reflecting: authorization).contains(f[11]))
        XCTAssertThrowsError(try channel.attestExistingAuthorization()); XCTAssertEqual(wire.writes.count, 2)
        channel.close(); XCTAssertTrue(wire.closed)
    }
    func testEveryFrozenFieldMismatchRejectsAttestation() throws {
        for index in [0,2,3,4,5,6,7,8,9,10,11,12,13] {
            let f = fields(); var changed = f; changed[index] += "changed"
            let until = Date().addingTimeInterval(60); let wire = MigrationWireFixture(); wire.input = framed(payload(changed, deadline: until.addingTimeInterval(-1)))
            let channel = MigrationConsoleChannel(wire: wire, credentials: MigrationCredentialFixture(), authorization: try record(f, until: until))
            XCTAssertThrowsError(try channel.attestExistingAuthorization(), "field \(index)"); XCTAssertEqual(wire.writes.count, 1); XCTAssertTrue(wire.closed)
        }
    }
    func testMalformedChallengeAndJSONCannotAttest() throws {
        let f = fields(); let until = Date().addingTimeInterval(60)
        let valid = payload(f, deadline: until.addingTimeInterval(-1))
        var extra = valid; extra.append(0)
        var zeroNonce = valid; zeroNonce.replaceSubrange(0..<32, with: Data(count: 32))
        var oversizeHeader = MigrationApprovalChallenge.marker; oversizeHeader.append(contentsOf: [0,0,36,1])
        for input in [Data("{\"approved\":true,\"nativeHuman\":true}".utf8), framed(extra), framed(zeroNonce), oversizeHeader, framed(Data(valid.dropLast())), framed(payload(f, deadline: Date().addingTimeInterval(-1)))] {
            let wire = MigrationWireFixture(); wire.input = input
            let channel = MigrationConsoleChannel(wire: wire, credentials: MigrationCredentialFixture(), authorization: try record(f, until: until))
            XCTAssertThrowsError(try channel.attestExistingAuthorization()); XCTAssertEqual(wire.writes.count, 1); XCTAssertTrue(wire.closed)
        }
    }
    func testRecordConsumedBeforeUncertainResponseWriteAndNotReusableByAnotherChannel() throws {
        let f = fields(); let until = Date().addingTimeInterval(60); let authorization = try record(f, until: until)
        let wire = MigrationWireFixture(); wire.input = framed(payload(f, deadline: until.addingTimeInterval(-1))); wire.failWriteAt = 2
        let first = MigrationConsoleChannel(wire: wire, credentials: MigrationCredentialFixture(), authorization: authorization)
        XCTAssertThrowsError(try first.attestExistingAuthorization())
        let retry = MigrationWireFixture(); retry.input = framed(payload(f, deadline: until.addingTimeInterval(-1), nonce: 2))
        let second = MigrationConsoleChannel(wire: retry, credentials: MigrationCredentialFixture(), authorization: authorization)
        XCTAssertThrowsError(try second.attestExistingAuthorization()); XCTAssertEqual(retry.writes.count, 1)
    }
    func testRevokedPeerAfterChallengeDoesNotAttest() throws {
        for rejectAt in [3,4] {
            let f = fields(); let until = Date().addingTimeInterval(60); let wire = MigrationWireFixture(); wire.rejectAt = rejectAt; wire.input = framed(payload(f, deadline: until.addingTimeInterval(-1)))
            let channel = MigrationConsoleChannel(wire: wire, credentials: MigrationCredentialFixture(), authorization: try record(f, until: until))
            XCTAssertThrowsError(try channel.attestExistingAuthorization()); XCTAssertEqual(wire.writes.count, 1)
        }
    }
    func testProductionConstructorRejectsWrongSignedHelperBeforeCredential() throws {
        var sockets: [Int32] = [-1,-1]
        XCTAssertEqual(socketpair(AF_UNIX, SOCK_STREAM, 0, &sockets), 0)
        defer { Darwin.close(sockets[1]) }
        let credential = MigrationCredentialFixture()
        // The fixture process is not this exact custody helper. Constructor owns
        // and closes sockets[0] after this failure; no Keychain lookup is performed.
        XCTAssertThrowsError(try MigrationConsoleChannel(connectedSocket: sockets[0], expectedUID: getuid(), credentials: credential, authorization: record(fields(), until: Date().addingTimeInterval(60))))
        XCTAssertEqual(credential.reads, 0)
    }
}

extension MigrationConsoleChannelTests {
    func testRelocationChallengeBindsBothPathsAndCannotDowngradeOrReplay() throws {
        let legacy = fields(), destination = "/fixture/Mechanize.app/Contents/Helpers/mechanize"
        let f = legacy + [destination, MigrationUpgradeIntent.relocationDomain]
        let until = Date().addingTimeInterval(60)
        func authorization() throws -> MigrationAuthorizationRecord {
            try MigrationAuthorizationRecord(workerSession:f[0], optionsSHA256:f[2], helperRequirement:f[3], itemReferenceSHA256:f[4], transitionID:f[5], canonicalExecutable:f[6], oldRequirement:f[7], newRequirement:f[8], alias:f[9], service:f[10], account:f[11], transitionBinding:f[13], validUntil:until, newCanonicalExecutable:destination)
        }
        let challenge = try MigrationApprovalChallenge.decode(payload(f, deadline:until.addingTimeInterval(-1)))
        let approved = try authorization()
        try approved.consume(challenge, now:Date())
        XCTAssertThrowsError(try approved.consume(challenge, now:Date()))
        let old = try MigrationApprovalChallenge.decode(payload(legacy, deadline:until.addingTimeInterval(-1)))
        XCTAssertThrowsError(try authorization().consume(old, now:Date()))
        XCTAssertThrowsError(try record(legacy, until:until).consume(challenge, now:Date()))
        var substituted = f; substituted[14] += "-substituted"
        XCTAssertThrowsError(try authorization().consume(MigrationApprovalChallenge.decode(payload(substituted, deadline:until.addingTimeInterval(-1))), now:Date()))
        for malformed in [legacy + [destination], legacy + [destination,"wrong-domain"], legacy + [legacy[6],MigrationUpgradeIntent.relocationDomain]] {
            XCTAssertThrowsError(try MigrationApprovalChallenge.decode(payload(malformed, deadline:until.addingTimeInterval(-1))))
        }
    }
}
