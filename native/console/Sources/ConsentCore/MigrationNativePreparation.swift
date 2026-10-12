import Foundation
import Darwin

// Both channels use the same signed socket and launcher lifetime. The read-only
// variant sends authentication only; it has no approval-record or reply method.
protocol MigrationWorkerCredentialSession: AnyObject {
    func authenticateAndServe() throws
    func close()
}
extension MigrationConsoleChannel: MigrationWorkerCredentialSession {
    func authenticateAndServe() throws { try attestExistingAuthorization() }
}
final class MigrationPreparationCredentialChannel: MigrationWorkerCredentialSession {
    private let lock = NSLock()
    private let wire: any MigrationConsoleWire
    private let credentials: any EnrollmentCredentialProvider
    private let deadline: Date
    private var started = false
    convenience init(socket:Int32, requirement:String, credentials:any EnrollmentCredentialProvider, deadline:Date) throws {
        let wire = try SignedMigrationSocket(socket:socket, requirement:requirement, uid:getuid())
        self.init(wire:wire,credentials:credentials,deadline:deadline)
    }
    init(wire:any MigrationConsoleWire, credentials:any EnrollmentCredentialProvider, deadline:Date) {
        self.wire=wire;self.credentials=credentials;self.deadline=deadline
    }
    deinit {wire.close()}
    func authenticateAndServe() throws {
        lock.lock();defer{lock.unlock()}
        guard !started,deadline>Date(),deadline.timeIntervalSinceNow<=240 else{throw MigrationConsoleError.unavailable};started=true
        do {
            try wire.authenticate()
            var bytes=try credentials.credential();defer{bytes.resetBytes(in:0..<bytes.count)}
            guard !bytes.isEmpty,bytes.count<=32768 else{throw MigrationConsoleError.unavailable}
            var frame=Data([77,77,65,85,84,72,0,1]);var count=UInt32(bytes.count).bigEndian
            withUnsafeBytes(of:&count){frame.append(contentsOf:$0)};frame.append(bytes);defer{frame.resetBytes(in:0..<frame.count)}
            try wire.authenticate();try wire.write(frame,deadline:deadline)
            // Return while retaining the authenticated socket. No approval
            // challenge is read, mirrored, accepted, or answered here.
        }catch{wire.close();throw MigrationConsoleError.unavailable}
    }
    func close(){lock.lock();defer{lock.unlock()};wire.close()}
}

public final class MigrationNativePreparation: CustomStringConvertible, CustomDebugStringConvertible {
    public let preparation: MigrationUpgradePreparation
    // Private persistent item reference for the native composition bridge only.
    let itemIdentity: Data
    let canonicalEvidence: Data
    var runtimeObserver: MigrationRuntimeObserverCollector?
    public var description:String{"Authenticated read-only migration preparation"}
    public var debugDescription:String{description}
    private init(preparation:MigrationUpgradePreparation,itemIdentity:Data,canonicalEvidence:Data){self.preparation=preparation;self.itemIdentity=itemIdentity;self.canonicalEvidence=canonicalEvidence}
    static func decode(_ payload:Data,intent:MigrationUpgradeIntent,requestID:String,validUntil:Date)throws->MigrationNativePreparation{
        guard let root=try JSONSerialization.jsonObject(with:payload) as? [String:Any],
              Set(root.keys)==["version","id","session","status","identity","evidence"],
              root["version"] as? Int==1,root["id"] as? String==requestID,root["session"] as? String==intent.bootstrap.session,root["status"] as? String=="prepared",
              let encoded=root["identity"] as? String,let identity=Data(base64Encoded:encoded),!identity.isEmpty,identity.count<=16384,
              let evidence=root["evidence"] as? [String:Any],Set(evidence.keys)==["intentSHA256","configSHA256","optionsSHA256","runtimeManifestSHA256","mutationRequirement","transition"],
              evidence["intentSHA256"] as? String==intent.binding,evidence["configSHA256"] as? String==intent.bootstrap.value["configSHA256"] as? String,
              evidence["optionsSHA256"] as? String==intent.optionsSHA256,evidence["runtimeManifestSHA256"] as? String==intent.runtimeManifestSHA256,
              evidence["mutationRequirement"] as? String==intent.worker.requirement,let transition=evidence["transition"] as? [String:Any] else{throw MigrationUpgradeError.invalidPreparation}
        let names=intent.transitionNames
        guard Set(transition.keys)==Set(names),let id=transition["ID"] as? String,let binding=transition["Binding"] as? String,
              transition["ItemReferenceSHA256"] as? String==MigrationUpgradeIntent.digest(identity) else{throw MigrationUpgradeError.invalidPreparation}
        for (name,value) in zip(names[1...6],intent.options){guard transition[name] as? String==value else{throw MigrationUpgradeError.invalidPreparation}}
        if let destination = intent.newCanonicalExecutable { guard transition["NewCanonicalExecutable"] as? String == destination else { throw MigrationUpgradeError.invalidPreparation } }
        let prepared=try MigrationUpgradePreparation(intent:intent,itemReferenceSHA256:MigrationUpgradeIntent.digest(identity),transitionID:id,transitionBinding:binding,validUntil:validUntil)
        // Canonical closed nested encoding rejects duplicate keys, booleans as
        // version numbers, alternate encodings and trailing/private fields.
        let transitionBytes=try MigrationWorkerSession.canonical(transition,order:names)
        var expectedEvidence=evidence;expectedEvidence.removeValue(forKey:"transition")
        var evidenceBytes=try MigrationWorkerSession.canonical(expectedEvidence,order:["intentSHA256","configSHA256","optionsSHA256","runtimeManifestSHA256","mutationRequirement"])
        evidenceBytes.removeLast();evidenceBytes.append(Data(",\"transition\":".utf8));evidenceBytes.append(transitionBytes);evidenceBytes.append(125)
        var expectedRoot=root;expectedRoot.removeValue(forKey:"evidence");expectedRoot["version"]=1
        var canonical=try MigrationWorkerSession.canonical(expectedRoot,order:["version","id","session","status","identity"])
        canonical.removeLast();canonical.append(Data(",\"evidence\":".utf8));canonical.append(evidenceBytes);canonical.append(125)
        guard canonical==payload else{throw MigrationUpgradeError.invalidPreparation}
        return MigrationNativePreparation(preparation:prepared,itemIdentity:identity,canonicalEvidence:evidenceBytes)
    }
}

/// Concrete metadata reader for a worker whose signed enrollment selects the
/// server-side preparation-only branch. It is invoked by the already-approved
/// main-window intent, never a worker challenge or an extra permission prompt.
public final class NativeMigrationPreparationReader {
    private let manifest:MigrationWorkerManifest
    private let credentials:any EnrollmentCredentialProvider
    public init(preparationWorker:MigrationWorkerManifest,credentials:any EnrollmentCredentialProvider){manifest=preparationWorker;self.credentials=credentials}
    public func prepare(_ intent:MigrationUpgradeIntent) async throws->MigrationNativePreparation {
        let manifest=self.manifest,credentials=self.credentials
        return try await Task.detached(priority:.userInitiated){
            let deadline=Date().addingTimeInterval(120)
            let artifact=try MigrationWorkerArtifact(manifest,uid:getuid())
            let session=try MigrationWorkerLauncher.launchPrivate(executable:manifest.executable.path,deadline:deadline,revalidate:artifact.verify,connect:{socket in
                try MigrationPreparationCredentialChannel(socket:socket,requirement:manifest.requirement,credentials:credentials,deadline:deadline)
            })
            defer{session.cancel()}
            let o=intent.options
            let bootstrap=try MigrationWorkerBootstrap(session:intent.bootstrap.session,configSHA256:intent.bootstrap.value["configSHA256"] as? String ?? "",canonicalExecutable:o[0],oldRequirement:o[1],newRequirement:o[2],alias:o[3],service:o[4],account:o[5],workerRequirement:manifest.requirement,newCanonicalExecutable:intent.newCanonicalExecutable)
            try session.bootstrap(bootstrap)
            let id=MigrationUpgradeIntent.digest(Data(UUID().uuidString.utf8))
            let evidence=try session.readOnlyPreparation(intent:intent,requestID:id,validUntil:deadline)
            let closed=try session.exchange(.close,requestID:MigrationUpgradeIntent.digest(Data(UUID().uuidString.utf8)))
            guard closed.status=="closed" else{throw MigrationUpgradeError.invalidPreparation}
            return evidence
        }.value
    }
}
