import XCTest
@testable import ConsentCore

private final class PermanentFixtureBroker: LocalConsentBroker {
    var authenticatedPeerDescription: String? = "Fixture authenticated peer"
    let request: ConsentRequest
    var grant: ConsentGrant?
    var mismatchPurpose = false
    var malformedExpiry = false

    init(_ request: ConsentRequest) { self.request = request }
    func snapshot() async throws -> ConsentSnapshot { ConsentSnapshot(requests: grant == nil ? [request] : [], grants: grant.map { [$0] } ?? []) }
    func decide(requestID: String, decision: ConsentDecision) async throws -> ConsentGrant? {
        guard requestID == request.id, decision != .deny else { return nil }
        let now = Date()
        grant = ConsentGrant(id: "permanent-grant", requestID: request.id, clientID: request.verifiedClient.id,
            scope: request.scope, modes: request.modes, purpose: mismatchPurpose ? "Changed purpose" : request.purpose,
            durationSeconds: request.durationSeconds, decision: decision, createdAt: now,
            expiresAt: malformedExpiry ? now.addingTimeInterval(60) : Date(timeIntervalSince1970: 0), state: .active,
            permanent: !malformedExpiry)
        return grant
    }
    func revoke(grantID: String) async throws -> RevokeStatus { grant = nil; return .revoked }
}

@MainActor final class PermanentConsentTests: XCTestCase {
    private func request() -> ConsentRequest {
        let now = Date()
        return ConsentRequest(id: "request-permanent", verifiedClient: VerifiedClient(id: "agent", displayName: "Agent", verification: .verified),
            scope: ConsentScope(kind: .application, bundleID: "com.example.Editor", displayName: "Editor"), modes: [.observe, .control],
            purpose: "Edit the selected document", durationSeconds: 300, createdAt: now.addingTimeInterval(-1), expiresAt: now.addingTimeInterval(120))
    }

    func testPermanentDecisionAndGrantAreAcceptedAndCanBeRevoked() async throws {
        let r = request(), broker = PermanentFixtureBroker(r), controller = ConsentController(broker: broker)
        try await controller.refresh()
        try await controller.decide(r, decision: .allowUntilRevoked)
        let grant = try XCTUnwrap(controller.grants.first)
        XCTAssertEqual(grant.decision, .allowUntilRevoked)
        XCTAssertTrue(grant.permanent)
        XCTAssertEqual(grant.expiresAt, Date(timeIntervalSince1970: 0))
        XCTAssertTrue(grant.isActive(at: Date().addingTimeInterval(10 * 365 * 24 * 60 * 60)))
        let revokeStatus = try await controller.revoke(grant)
        XCTAssertEqual(revokeStatus, .revoked)
        XCTAssertFalse(controller.grants.contains { $0.isActive(at: Date()) })
    }

    func testPermanentGrantMustExactlyMatchReviewedPurpose() async throws {
        let r = request(), broker = PermanentFixtureBroker(r), controller = ConsentController(broker: broker)
        broker.mismatchPurpose = true
        try await controller.refresh()
        do { try await controller.decide(r, decision: .allowUntilRevoked); XCTFail("Accepted a permanent grant with a different purpose") }
        catch { XCTAssertTrue(error is ConsentError) }
    }

    func testPermanentDecisionRequiresPermanentFlagAndZeroExpiry() async throws {
        let r = request(), broker = PermanentFixtureBroker(r), controller = ConsentController(broker: broker)
        broker.malformedExpiry = true
        try await controller.refresh()
        do { try await controller.decide(r, decision: .allowUntilRevoked); XCTFail("Accepted a time-limited grant as permanent") }
        catch { XCTAssertTrue(error is ConsentError) }
    }

    func testMissingPermanentFieldDecodesAsFalse() throws {
        let now = Date()
        let grant = ConsentGrant(id: "g", requestID: "r", clientID: "c", scope: request().scope, modes: [.observe], purpose: "Review",
            durationSeconds: 60, decision: .allowSession, createdAt: now, expiresAt: now.addingTimeInterval(60), state: .active)
        let encoded = try ConsentWire.encoder().encode(grant)
        var object = try XCTUnwrap(JSONSerialization.jsonObject(with: encoded) as? [String: Any])
        object.removeValue(forKey: "permanent")
        let legacy = try JSONSerialization.data(withJSONObject: object)
        let decoded = try ConsentWire.decoder().decode(ConsentGrant.self, from: legacy)
        XCTAssertFalse(decoded.permanent)
    }

    func testRevokedPermanentGrantIsInactive() {
        let now = Date()
        let grant = ConsentGrant(id: "g", requestID: "r", clientID: "c", scope: request().scope, modes: [.observe], purpose: "Review",
            durationSeconds: 60, decision: .allowUntilRevoked, createdAt: now, expiresAt: Date(timeIntervalSince1970: 0), state: .revoked, permanent: true)
        XCTAssertFalse(grant.isActive(at: now))
    }
}
