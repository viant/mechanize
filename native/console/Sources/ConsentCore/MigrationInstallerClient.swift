import Foundation

public enum MigrationInstallerOperation: String { case execute, reconcile, finalize, close }
public struct MigrationInstallerRuntime: CustomStringConvertible, CustomDebugStringConvertible {
    public let brokerPID: Int32
    public let brokerStartToken: String
    public var description: String { "Verified runtime identity" }
    public var debugDescription: String { description }
    init(brokerPID: Int32, brokerStartToken: String) throws {
        let parts = brokerStartToken.split(separator: ":", omittingEmptySubsequences: false)
        guard brokerPID > 0, parts.count == 2,
              let seconds = UInt64(parts[0]), seconds > 0, String(seconds) == parts[0],
              let micros = UInt32(parts[1]), micros < 1_000_000, String(micros) == parts[1] else { throw MigrationConsoleError.unavailable }
        self.brokerPID = brokerPID; self.brokerStartToken = brokerStartToken
    }
}
public struct MigrationInstallerReply: CustomStringConvertible, CustomDebugStringConvertible {
    public let status: String
    public let transitionID: String?
    public let scope: String?
    public let runtime: MigrationInstallerRuntime?
    init(status: String, transitionID: String?, scope: String?, runtime: MigrationInstallerRuntime? = nil) {
        self.status = status; self.transitionID = transitionID; self.scope = scope; self.runtime = runtime
    }
    public var description: String { "Private installer receipt" }
    public var debugDescription: String { description }
}

/// Closed frames for the single Go installer. No journal/placement callbacks,
/// supplied success booleans or raw worker mutation verbs are encoded here.
enum MigrationInstallerWire {
    static func encode(_ operation: MigrationInstallerOperation, id: String, intent: MigrationUpgradeIntent,
                       prepared: MigrationNativePreparation) throws -> Data {
        guard MigrationAuthorizationRecord.digest(id), prepared.preparation.intentBinding == intent.binding,
              prepared.preparation.validUntil > Date(),
              MigrationUpgradeIntent.digest(prepared.itemIdentity) == prepared.preparation.itemReferenceSHA256 else { throw MigrationUpgradeError.invalidPreparation }
        var bytes = try MigrationWorkerSession.canonical(["version":1,"id":id,"session":intent.bootstrap.session,"op":operation.rawValue], order:["version","id","session","op"])
        if operation == .execute {
            let milliseconds = Int64(floor(prepared.preparation.validUntil.timeIntervalSince1970 * 1000))
            guard milliseconds > Int64(Date().timeIntervalSince1970 * 1000) else { throw MigrationUpgradeError.invalidPreparation }
            bytes.removeLast(); bytes.append(Data(",\"preparation\":".utf8)); bytes.append(prepared.canonicalEvidence)
            let tail = try MigrationWorkerSession.canonical(["identity":prepared.itemIdentity.base64EncodedString(),"deadlineUnixMilliseconds":milliseconds], order:["identity","deadlineUnixMilliseconds"])
            bytes.append(44); bytes.append(tail.dropFirst())
        }
        guard bytes.count <= 32768 else { throw MigrationConsoleError.unavailable }
        return bytes
    }
    static func decode(_ payload: Data, operation: MigrationInstallerOperation, id: String,
                       intent: MigrationUpgradeIntent, prepared: MigrationNativePreparation) throws -> MigrationInstallerReply {
        guard let fields = try JSONSerialization.jsonObject(with:payload) as? [String:Any],
              Set(fields.keys).isSubset(of:["version","id","session","status","transitionId","scope","runtime"]),
              fields["version"] as? Int == 1, fields["id"] as? String == id,
              fields["session"] as? String == intent.bootstrap.session, let status = fields["status"] as? String else { throw MigrationConsoleError.unavailable }
        var canonical = fields; canonical["version"] = 1; canonical.removeValue(forKey:"runtime")
        var encoded = try MigrationWorkerSession.canonical(canonical, order:["version","id","session","status","transitionId","scope"])
        var runtime: MigrationInstallerRuntime?
        if let raw = fields["runtime"] {
            guard operation == .finalize, status == "verified", let values = raw as? [String:Any],
                  Set(values.keys) == Set(["brokerPID","brokerStartToken"]),
                  let pid = values["brokerPID"] as? Int32, let start = values["brokerStartToken"] as? String else { throw MigrationConsoleError.unavailable }
            runtime = try MigrationInstallerRuntime(brokerPID:pid,brokerStartToken:start)
            let nested = try MigrationWorkerSession.canonical(["brokerPID":pid,"brokerStartToken":start],order:["brokerPID","brokerStartToken"])
            encoded.removeLast(); encoded.append(Data(",\"runtime\":".utf8)); encoded.append(nested); encoded.append(125)
        }
        guard encoded == payload, !(operation == .finalize && status == "verified") || runtime != nil else { throw MigrationConsoleError.unavailable }
        let transition = fields["transitionId"] as? String, scope = fields["scope"] as? String
        guard fields["transitionId"] == nil || transition != nil, fields["scope"] == nil || scope != nil else { throw MigrationConsoleError.unavailable }
        if operation == .close {
            guard status == "closed", transition == nil, scope == nil else { throw MigrationConsoleError.unavailable }
        } else {
            let expectedScope = operation == .finalize ? "runtime-artifacts" : "custody-broker-config"
            guard ["verified","unknown","unavailable"].contains(status),
                  transition == nil || transition == prepared.preparation.transitionID,
                  scope == nil || scope == expectedScope else { throw MigrationConsoleError.unavailable }
            if status == "verified" || operation == .finalize {
                guard transition == prepared.preparation.transitionID, scope == expectedScope else { throw MigrationConsoleError.unavailable }
            }
        }
        return MigrationInstallerReply(status:status, transitionID:transition, scope:scope,runtime:runtime)
    }
}

protocol MigrationInstallerTransport: AnyObject {
    func bootstrap(_ value: MigrationWorkerBootstrap) throws
    func roundTrip(_ payload: Data, closing: Bool) throws -> Data
    func cancel()
}
private final class NativeInstallerTransport: MigrationInstallerTransport {
    let session: MigrationWorkerSession
    init(_ session: MigrationWorkerSession) { self.session = session }
    func bootstrap(_ value: MigrationWorkerBootstrap) throws { try session.bootstrap(value) }
    func roundTrip(_ payload: Data, closing: Bool) throws -> Data { try session.installerRoundTrip(payload, closing:closing) }
    func cancel() { session.cancel() }
}
protocol MigrationInstallerSession: AnyObject {
    var executionMayHaveDispatched: Bool { get }
    var canReconcile: Bool { get }
    func execute() throws -> MigrationInstallerReply
    func reconcile() throws -> MigrationInstallerReply
    func finalize() throws -> MigrationInstallerReply
    func cancel()
}

/// Retains the signed channel through the exact finalize receipt. Finalize is
/// terminal for authority; cleanup never needs a new old-console authentication.
public final class NativeMigrationInstallerClient: MigrationInstallerSession, CustomStringConvertible, CustomDebugStringConvertible {
    private let calls = NSLock(), statusLock = NSLock()
    private let transport: any MigrationInstallerTransport
    private let intent: MigrationUpgradeIntent
    private let prepared: MigrationNativePreparation
    private var phase = "ready", attempted = false, reconciled = false
    private var count = 0
    public var description:String { "Private native installer client" }
    public var debugDescription:String { description }
    public var executionMayHaveDispatched:Bool { statusLock.lock();defer{statusLock.unlock()};return attempted }
    public var canReconcile:Bool { statusLock.lock();defer{statusLock.unlock()};return phase == "unknown" && !reconciled && prepared.preparation.validUntil > Date() }
    public static func launch(intent:MigrationUpgradeIntent, prepared:MigrationNativePreparation,
                              credentials:any EnrollmentCredentialProvider) throws -> NativeMigrationInstallerClient {
        guard let observer = prepared.runtimeObserver, observer.intentBinding == intent.binding else { throw MigrationUpgradeError.unavailable }
        let authorization = try prepared.preparation.authorization(intent)
        let running = try MigrationWorkerLauncher.launch(manifest:intent.worker,credentials:credentials,authorization:authorization,observer:observer)
        return try NativeMigrationInstallerClient(intent:intent,prepared:prepared,transport:NativeInstallerTransport(running))
    }
    init(intent:MigrationUpgradeIntent, prepared:MigrationNativePreparation, transport:any MigrationInstallerTransport) throws {
        guard prepared.preparation.intentBinding == intent.binding else { transport.cancel();throw MigrationUpgradeError.invalidPreparation }
        self.intent=intent;self.prepared=prepared;self.transport=transport
        do { try transport.bootstrap(intent.bootstrap) } catch { transport.cancel();throw MigrationConsoleError.unavailable }
    }
    deinit {transport.cancel()}
    public func cancel() { statusLock.lock();phase="closed";statusLock.unlock();transport.cancel() }
    public func execute() throws -> MigrationInstallerReply { try command(.execute) }
    public func reconcile() throws -> MigrationInstallerReply { try command(.reconcile) }
    public func finalize() throws -> MigrationInstallerReply { try command(.finalize) }
    public func close() throws -> MigrationInstallerReply { try command(.close) }
    private func command(_ operation:MigrationInstallerOperation) throws -> MigrationInstallerReply {
        calls.lock();defer{calls.unlock()}
        let id=MigrationUpgradeIntent.digest(Data(UUID().uuidString.utf8))
        let payload=try MigrationInstallerWire.encode(operation,id:id,intent:intent,prepared:prepared)
        statusLock.lock()
        let allowed=count<4 && ((operation == .execute && phase == "ready") ||
            (operation == .reconcile && phase == "unknown" && !reconciled) ||
            (operation == .finalize && phase == "custodyVerified") ||
            (operation == .close && ["ready","unknown","custodyVerified"].contains(phase)))
        guard allowed else {statusLock.unlock();throw MigrationUpgradeError.recoveryRequired}
        count+=1
        if operation == .execute {attempted=true}
        if operation == .reconcile {reconciled=true}
        phase="pending" // latch before any partial write; never replay
        statusLock.unlock()
        do {
            let payload=try transport.roundTrip(payload,closing:operation == .close)
            let reply=try MigrationInstallerWire.decode(payload,operation:operation,id:id,intent:intent,prepared:prepared)
            statusLock.lock()
            if phase == "closed" {statusLock.unlock();throw MigrationUpgradeError.cancelled}
            switch operation {
            case .execute,.reconcile: phase=reply.status == "verified" ? "custodyVerified" : "unknown"
            case .finalize: phase=reply.status == "verified" ? "complete" : "finalizationUnknown"
            case .close: phase="closed"
            }
            statusLock.unlock()
            if operation == .finalize || operation == .close {transport.cancel()}
            return reply
        }catch{
            statusLock.lock();phase="broken";statusLock.unlock();transport.cancel();throw MigrationUpgradeError.recoveryRequired
        }
    }
}
