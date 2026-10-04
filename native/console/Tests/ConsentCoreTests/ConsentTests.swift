import XCTest
@testable import ConsentCore

private final class FixtureBroker: LocalConsentBroker {
    var authenticatedPeerDescription: String? = "Fixture authenticated peer"
    var requests: [ConsentRequest]
    var grants: [ConsentGrant] = []
    var revokeStatus: RevokeStatus = .revoked
    var mismatch = false
    var unchangedRevoke = false
    init(_ request: ConsentRequest) { requests = [request] }
    func snapshot() async throws -> ConsentSnapshot { ConsentSnapshot(requests: requests, grants: grants) }
    func decide(requestID: String, decision: ConsentDecision) async throws -> ConsentGrant? {
        guard let r = requests.first(where: { $0.id == requestID }) else { throw ConsentError.invalidRequest }
        requests.removeAll { $0.id == requestID }
        if decision == .deny { return nil }
        let now = Date()
        let g = ConsentGrant(id: "grant-1", requestID: r.id, clientID: r.verifiedClient.id, scope: r.scope, modes: r.modes, purpose: mismatch ? "Different purpose" : r.purpose, durationSeconds: r.durationSeconds, decision: decision, createdAt: now.addingTimeInterval(-1), expiresAt: now.addingTimeInterval(Double(r.durationSeconds - 1)), state: .active)
        grants = [g]; return g
    }
    func revoke(grantID: String) async throws -> RevokeStatus { if revokeStatus == .revoked && !unchangedRevoke { grants = [] }; return revokeStatus }
}
@MainActor final class ConsentTests: XCTestCase {
    func request(verification: ClientVerification = .verified) -> ConsentRequest {
        let now = Date()
        return ConsentRequest(id: "request-1", verifiedClient: VerifiedClient(id: "agent-1", displayName: "Verified Agent", verification: verification), scope: ConsentScope(kind: .window, bundleID: "com.apple.TextEdit", windowID: "42", displayName: "Draft"), modes: [.observe, .control, .record], purpose: "Read and edit this draft", durationSeconds: 300, createdAt: now.addingTimeInterval(-10), expiresAt: now.addingTimeInterval(120))
    }
    func testExactScopePurposeModesAndDurationRoundTrip() throws {
        let r = request(); let decoded = try ConsentWire.decoder().decode(ConsentRequest.self, from: ConsentWire.encoder().encode(r))
        XCTAssertEqual(decoded.scope, r.scope); XCTAssertEqual(decoded.purpose, r.purpose); XCTAssertEqual(decoded.durationSeconds, 300); XCTAssertEqual(decoded.modes, [.observe, .control, .record]); XCTAssertTrue(decoded.scope.exactDescription.contains("42")); XCTAssertTrue(decoded.scope.exactDescription.contains("com.apple.TextEdit"))
    }
    func testAllowOnceAndSessionAndConfirmedRevoke() async throws {
        for decision in [ConsentDecision.allowOnce, .allowSession] {
            let r = request(); let broker = FixtureBroker(r); let c = ConsentController(broker: broker)
            try await c.refresh(); try await c.decide(r, decision: decision)
            XCTAssertTrue(c.requests.isEmpty); XCTAssertEqual(c.grants.first?.decision, decision)
            let status = try await c.revoke(c.grants[0]); XCTAssertEqual(status, .revoked); XCTAssertTrue(c.grants.isEmpty)
        }
    }
    func testDenyCreatesNoGrant() async throws { let r = request(); let c = ConsentController(broker: FixtureBroker(r)); try await c.refresh(); try await c.decide(r, decision: .deny); XCTAssertTrue(c.requests.isEmpty); XCTAssertTrue(c.grants.isEmpty) }
    func testUnknownCleanupNeverReportsRevoked() async throws {
        let r = request(); let broker = FixtureBroker(r); broker.revokeStatus = .cleanupUnknown
        let c = ConsentController(broker: broker); try await c.refresh(); try await c.decide(r, decision: .allowSession)
        let status = try await c.revoke(c.grants[0]); XCTAssertEqual(status, .cleanupUnknown); XCTAssertEqual(c.grants.count, 1)
    }
    func testUnchangedGrantCannotConfirmRevocation() async throws {
        let r = request(); let broker = FixtureBroker(r); broker.unchangedRevoke = true
        let c = ConsentController(broker: broker); try await c.refresh(); try await c.decide(r, decision: .allowSession)
        do { _ = try await c.revoke(c.grants[0]); XCTFail("Confirmed unchanged active grant") } catch { XCTAssertTrue(error is ConsentError) }
        XCTAssertEqual(c.grants.count, 1)
    }
    func testUnverifiedRequestCannotGrant() async throws { let r = request(verification: .unverified); let c = ConsentController(broker: FixtureBroker(r)); try await c.refresh(); do { try await c.decide(r, decision: .allowOnce); XCTFail("Granted unverified request") } catch { XCTAssertTrue(error is ConsentError) }; XCTAssertTrue(c.grants.isEmpty) }
    func testMismatchedGrantRejected() async throws { let r = request(); let broker = FixtureBroker(r); broker.mismatch = true; let c = ConsentController(broker: broker); try await c.refresh(); do { try await c.decide(r, decision: .allowOnce); XCTFail("Accepted widened grant") } catch { XCTAssertTrue(error is ConsentError) }; XCTAssertTrue(c.grants.isEmpty) }
    func testDisconnectedCannotIssueConsent() async { let c = ConsentController(broker: DisconnectedBroker()); XCTAssertFalse(c.isConnected); do { try await c.decide(request(), decision: .allowSession); XCTFail("Preview granted consent") } catch {}; XCTAssertTrue(c.grants.isEmpty) }
    func testScopeRequiresExactIdentifiers() { XCTAssertFalse(ConsentScope(kind: .window, bundleID: "com.test", displayName: "Window").isExact); XCTAssertFalse(ConsentScope(kind: .origin, origin: "https://example.org/path", displayName: "Site").isExact); XCTAssertTrue(ConsentScope(kind: .origin, origin: "https://example.org:443", displayName: "Site").isExact) }
    func testExpiredGrantInactive() { let now = Date(); let g = ConsentGrant(id: "g", requestID: "r", clientID: "c", scope: request().scope, modes: [.observe], purpose: "Review", durationSeconds: 1, decision: .allowOnce, createdAt: now.addingTimeInterval(-2), expiresAt: now.addingTimeInterval(-1), state: .active); XCTAssertFalse(g.isActive(at: now)) }
}
