import Foundation
import Combine

/// Native approval metadata only. Credential values and record field names are
/// never part of this representation or of the binding request.
public struct NativeCredentialRequest: Identifiable, Equatable, Sendable {
    public let id: String
    public let origin: String
    public let clientId: String
    public let purpose: String
    public let expiresAt: Date
    public init(id: String, origin: String, clientId: String, purpose: String, expiresAt: Date) throws {
        guard nativeVaultEntryID(id), VaultOrigin.canonical(origin) == origin,
              !clientId.isEmpty, clientId.utf8.count <= 256,
              !purpose.isEmpty, purpose.utf8.count <= 512,
              ![clientId, purpose].contains(where: { $0.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains) }) else {
            throw BrokerTransportError.malformedResponse
        }
        self.id = id; self.origin = origin; self.clientId = clientId; self.purpose = purpose; self.expiresAt = expiresAt
    }
    public static func decode(_ data: Data) throws -> [NativeCredentialRequest] {
        try MigrationReadinessJSON.validate(data)
        guard let rows = try JSONSerialization.jsonObject(with: data) as? [[String: Any]], rows.count <= 128 else {
            throw BrokerTransportError.malformedResponse
        }
        var seen = Set<String>()
        let fractional = ISO8601DateFormatter(); fractional.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        let whole = ISO8601DateFormatter()
        return try rows.map { row in
            guard Set(row.keys) == Set(["id", "origin", "clientId", "purpose", "expiresAt"]),
                  let id = row["id"] as? String, seen.insert(id).inserted,
                  let origin = row["origin"] as? String, let client = row["clientId"] as? String,
                  let purpose = row["purpose"] as? String, let time = row["expiresAt"] as? String,
                  let expiry = fractional.date(from: time) ?? whole.date(from: time) else {
                throw BrokerTransportError.malformedResponse
            }
            return try NativeCredentialRequest(id: id, origin: origin, clientId: client, purpose: purpose, expiresAt: expiry)
        }
    }
}

public protocol NativeCredentialApprovalBroker: AnyObject {
    func pendingCredentialRequests() async throws -> [NativeCredentialRequest]
    func credentialRecordReferences() async throws -> [VaultRecordMetadata]
    func bindCredentialRequest(id: String, record: VaultRecordMetadata) async throws
    func cancelCredentialRequest(id: String) async throws
}

extension SocketConsentBroker: NativeCredentialApprovalBroker {}

@MainActor public final class CredentialDeliveryApprovalModel: ObservableObject {
    @Published public private(set) var requests: [NativeCredentialRequest] = []
    @Published public private(set) var records: [VaultRecordMetadata] = []
    @Published public private(set) var busy = false
    @Published public private(set) var message = ""
    private let broker: (any NativeCredentialApprovalBroker)?
    private var attempted = Set<String>()
    public init(broker: (any NativeCredentialApprovalBroker)?) { self.broker = broker }
    public func clear() { requests = []; records = []; message = "" }
    public func canBind(_ request: NativeCredentialRequest, record: VaultRecordMetadata?, now: Date = Date()) -> Bool {
        guard !busy, broker != nil, request.expiresAt > now, !attempted.contains(request.id),
              requests.contains(request), let record, records.contains(record) else { return false }
        return record.isValid
    }
    public func refresh() async {
        guard !busy, let broker else { return }
        busy = true; defer { busy = false }
        do {
            let pending = try await broker.pendingCredentialRequests()
            let references = pending.isEmpty ? [] : try await broker.credentialRecordReferences()
            guard Set(pending.map(\.id)).count == pending.count,
                  Set(references.map(\.id)).count == references.count,
                  references.count <= 256, references.allSatisfy(\.isValid) else { throw BrokerTransportError.malformedResponse }
            requests = pending.filter { $0.expiresAt > Date() }; records = references
            // Only a fresh signed pending response can show that a previously
            // uncertain bind is still awaiting approval. No automatic retry.
            attempted.subtract(Set(requests.map(\.id)))
            message = requests.isEmpty ? "" : (records.isEmpty ? "Create a saved credential in Vault before approving sign-in." : "")
        } catch {
            requests = []; records = []; message = "Credential approvals are unavailable. Refresh after reconnecting."
        }
    }
    public func bind(_ request: NativeCredentialRequest, record: VaultRecordMetadata) async {
        guard canBind(request, record: record), let broker else { return }
        attempted.insert(request.id); busy = true
        do {
            try await broker.bindCredentialRequest(id: request.id, record: record)
            requests.removeAll { $0.id == request.id }
            message = "Credential use approved for this request. Sign-in is not yet confirmed."
        } catch {
            message = "Approval could not be confirmed. Refresh to check the request before trying again."
        }
        busy = false
    }
    public func cancel(_ request: NativeCredentialRequest) async {
        guard !busy, requests.contains(request), !attempted.contains(request.id), let broker else { return }
        attempted.insert(request.id); busy = true
        defer { busy = false }
        do {
            try await broker.cancelCredentialRequest(id: request.id)
            requests.removeAll { $0.id == request.id }
            message = "Credential request cancelled. Uncertain browser actions remain protected."
        } catch { message = "Cancellation could not be confirmed. Refresh to check the request." }
    }
}
