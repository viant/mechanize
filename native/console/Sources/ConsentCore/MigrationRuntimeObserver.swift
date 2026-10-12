import Foundation
import AppKit
import ApplicationServices
import Darwin
import Security

enum MigrationObserverReadinessError: String, Error {
    case preservationShape, chromeIdentity, googleIdentity, accessibilityRequired
    case managementDocument, nativeObservation, loadedPath, loadedPathMismatch, chromeIdentityChanged
}

/// Retained private evidence; its original observation time is never refreshed
/// after Chrome/the broker stop. No caller can construct it from an approval bit.
struct MigrationLoadedExtensionEvidence {
    let observedAt: Date, receiptSHA256: String, path: String, extensionID: String, storageSHA256: String
}

public final class MigrationRuntimeObserverCollector {
    private let lock = NSLock()
    let intentBinding: String
    private let session: String, manifest: String
    private let plan: [String: Any]
    private let preservedChrome: MigrationInstallerRuntime?
    private let image: (Int32, String, String, String) throws -> MigrationShutdownIdentity
    private let setup: () throws -> Data
    private let observe: (Int32, String, String, Date) throws -> Data
    private let document: (Int32, String, String, String) throws -> Void
    private let loaded: (Data,Int32,String,String,String) throws -> (String,Date)
    private let stopped: ([String]) throws -> Void
    private let console: (String, String) throws -> Void
    private let profile: String, browser: String, title: String
    private let brokerIdentity: MigrationShutdownIdentity?
    private var chromeIdentity: MigrationShutdownIdentity?
    private var evidence: MigrationLoadedExtensionEvidence?
    private var captured = false
    private var nonces: Set<String> = []

    /// Called only from the approved native package composition. The enrollment
    /// binds the old broker and distinct read-only MCP resource; it grants no input.
    public convenience init(intent: MigrationUpgradeIntent, frozenPlan: Data, enrollment: MigrationObserverReaderEnrollment,
                            credentials: any EnrollmentCredentialProvider, profileChannel: String, browserInstance: String, windowTitle: String) throws {
        let reader = MigrationObserverMCPReader(enrollment)
        try self.init(intent: intent, frozenPlan: frozenPlan, profile: profileChannel, browser: browserInstance, title: windowTitle,
            setup: {
                let peer = try MigrationExactBrokerPeer(requirement: enrollment.brokerRequirement, pid: enrollment.brokerPID, start: enrollment.brokerStart, uid: getuid())
                let transport = UnixBrokerTransport(authenticator: peer)
                let broker = SocketConsentBroker(transport: transport, credentials: credentials)
                defer { transport.close() }
                try broker.connectFromUserAction()
                let result = try broker.migrationBrowserSetupMetadata(profileChannel: profileChannel, browserInstance: browserInstance)
                try peer.revalidateConnectedPeer()
                return result
            }, observe: reader.observe, document: MigrationObserverOS.managementDocument, loaded: MigrationObserverOS.loadedManagementPath,
            stopped: MigrationObserverOS.requireStopped, console: MigrationObserverOS.consoleIdentity, brokerIdentity: MigrationShutdownIdentity(pid: enrollment.brokerPID, uid: getuid(), birth: enrollment.brokerStart, executable: intent.options[0], requirement: enrollment.brokerRequirement))
    }
    public convenience init(preservingExtensionIntent intent: MigrationUpgradeIntent, frozenPlan: Data,
                            enrollment: MigrationObserverReaderEnrollment, chromePID: Int32, chromeStart: String, windowTitle: String) throws {
        let reader = MigrationObserverMCPReader(enrollment)
        try self.init(intent: intent, frozenPlan: frozenPlan, profile: "", browser: "", title: windowTitle,
            setup: { throw MigrationConsoleError.unavailable }, observe: reader.observe, document: MigrationObserverOS.managementDocument, loaded: MigrationObserverOS.loadedManagementPath,
            stopped: MigrationObserverOS.requireStopped, console: MigrationObserverOS.consoleIdentity,
            brokerIdentity: MigrationShutdownIdentity(pid: enrollment.brokerPID, uid: getuid(), birth: enrollment.brokerStart, executable: intent.options[0], requirement: enrollment.brokerRequirement),
            preservedChrome: try MigrationInstallerRuntime(brokerPID: chromePID, brokerStartToken: chromeStart))
    }
    // Injected source primitives are internal test seams, never wire fields.
    init(intent: MigrationUpgradeIntent, frozenPlan: Data, profile: String, browser: String, title: String,
         setup: @escaping () throws -> Data, observe: @escaping (Int32,String,String,Date) throws -> Data,
         document: @escaping (Int32,String,String,String) throws -> Void, loaded: ((Data,Int32,String,String,String)throws->(String,Date))? = nil,
         stopped: @escaping ([String]) throws -> Void, console: @escaping (String,String) throws -> Void, brokerIdentity: MigrationShutdownIdentity? = nil, preservedChrome: MigrationInstallerRuntime? = nil, image: @escaping (Int32,String,String,String) throws -> MigrationShutdownIdentity = MigrationObserverOS.chromeImage) throws {
        guard MigrationUpgradeIntent.digest(frozenPlan) == intent.runtimeManifestSHA256,
              (preservedChrome == nil ? [profile,browser,title] : [title]).allSatisfy({ !$0.isEmpty && $0.utf8.count <= 1024 }),
              let root = try JSONSerialization.jsonObject(with: frozenPlan) as? [String:Any],
              let runtime = root["runtime"] as? [String:Any] else { throw MigrationConsoleError.unavailable }
        try MigrationReadinessJSON.validate(frozenPlan)
        guard (["preserve-extension-v1","unified-app-v2","unified-app-update-v3"].contains(runtime["Mode"] as? String ?? "")) == (preservedChrome != nil) else { throw MigrationConsoleError.unavailable }
        if preservedChrome != nil {
            if intent.newCanonicalExecutable != nil || runtime["Mode"] as? String == "unified-app-update-v3" { _ = try MigrationUnifiedAppManifest(runtime:runtime,intent:intent) }
            else { _ = try MigrationPreservedExtensionManifest(runtime: runtime) }
        }
        self.preservedChrome = preservedChrome; self.image = image
        self.loaded = loaded ?? { data,pid,birth,title,_ in try Self.loadedPath(data,pid:pid,birth:birth,title:title) }
        self.brokerIdentity = brokerIdentity
        self.plan = runtime; session = intent.bootstrap.session; manifest = intent.runtimeManifestSHA256; intentBinding = intent.binding
        self.profile=profile;self.browser=browser;self.title=title;self.setup=setup;self.observe=observe;self.document=document;self.stopped=stopped;self.console=console
    }
    func capture() throws {
        lock.lock(); defer { lock.unlock() }
        guard !captured else { throw MigrationConsoleError.unavailable }; captured = true
        if let preservedChrome { try capturePreserved(preservedChrome); return }
        let raw = try setup()
        guard let receipt = try JSONSerialization.jsonObject(with:raw) as? [String:Any],
              receipt["profileChannel"] as? String == profile, receipt["browserInstance"] as? String == browser,
              let metadata = receipt["metadata"] as? [String:Any], metadata["version"] as? Int == 1,
              metadata["storageScope"] as? String == "extension-local-v1", metadata["storageStable"] as? Bool == true,
              metadata["nativeConnected"] as? Bool == true,
              metadata["activeCommands"] as? Int == 0, metadata["unknownAttempts"] as? Int == 0,
              metadata["mutationBusy"] as? Bool == false, receipt["brokerPending"] as? Int == 0, receipt["brokerUnknown"] as? Int == 0,
              let id = metadata["extensionId"] as? String, id == plan["ExtensionID"] as? String,
              let storage = metadata["storageSHA256"] as? String, storage == plan["ExtensionStorageSHA256"] as? String,
              MigrationAuthorizationRecord.digest(storage),
              let sourceHash = receipt["receiptSHA256"] as? String, MigrationAuthorizationRecord.digest(sourceHash),
              let observed = receipt["observedAt"] as? String, let at = Self.date(observed), Self.fresh(at),
              let chrome = receipt["chromeParent"] as? [String:Any], let pid = chrome["pid"] as? Int32, pid > 0,
              chrome["uid"] as? UInt32 == getuid(), let actualPath = chrome["executable"] as? String,
              let canonicalPath = plan["ChromeExecutable"] as? String, let requirement = receipt["chromeRequirement"] as? String,
              let birth = chrome["startToken"] as? String, MigrationExactBrokerPeer.validStart(birth) else { throw MigrationConsoleError.unavailable }
        let currentImage = try image(pid,birth,canonicalPath,requirement)
        guard currentImage.executable == actualPath else { throw MigrationConsoleError.unavailable }
        try document(pid,birth,title,id)
        let observation = try observe(pid,birth,title,min(Date().addingTimeInterval(10),at.addingTimeInterval(30)))
        let (path, nativeAt) = try loaded(observation,pid,birth,title,id)
        try document(pid,birth,title,id)
        let afterRaw = try setup()
        guard let after = try JSONSerialization.jsonObject(with: afterRaw) as? [String:Any],
              let afterMetadata = after["metadata"] as? [String:Any], let afterChrome = after["chromeParent"] as? [String:Any],
              afterMetadata["storageSHA256"] as? String == storage, afterMetadata["storageStable"] as? Bool == true,
              afterMetadata["nativeConnected"] as? Bool == true, afterMetadata["storageScope"] as? String == "extension-local-v1",
              let afterObserved = after["observedAt"] as? String, let afterAt = Self.date(afterObserved), afterAt >= at, Self.fresh(afterAt),
              afterMetadata["extensionId"] as? String == id, afterMetadata["activeCommands"] as? Int == 0,
              afterMetadata["unknownAttempts"] as? Int == 0, afterMetadata["mutationBusy"] as? Bool == false,
              after["brokerPending"] as? Int == 0, after["brokerUnknown"] as? Int == 0,
              afterChrome["pid"] as? Int32 == pid, afterChrome["startToken"] as? String == birth,
              ["profileChannel","browserInstance","brokerEpoch","channelEpoch","scopeHash"].allSatisfy({
                  guard let before = receipt[$0] as? String, !before.isEmpty else { return false }
                  return after[$0] as? String == before
              }) else { throw MigrationConsoleError.unavailable }
        let extensionArtifact = try artifact("extension")
        guard path == extensionArtifact["target"] as? String else { throw MigrationConsoleError.unavailable }
        var binding = raw;binding.append(observation);binding.append(afterRaw)
        binding.append(try MigrationWorkerSession.canonical(["path":path,"extensionID":id],order:["path","extensionID"]))
        guard try image(pid,birth,canonicalPath,requirement) == currentImage else { throw MigrationConsoleError.unavailable }
        chromeIdentity = currentImage
        evidence = MigrationLoadedExtensionEvidence(observedAt:min(at,nativeAt),receiptSHA256:MigrationUpgradeIntent.digest(binding),path:path,extensionID:id,storageSHA256:storage)
    }
    private func capturePreserved(_ chrome: MigrationInstallerRuntime) throws {
        do {
            // The immutable unified plan was independently validated at construction.
            // Preservation rechecks inspect its retained legacy artifacts, not the
            // one writable whole-app artifact.
            var preservation = plan
            if ["unified-app-v2","unified-app-update-v3"].contains(plan["Mode"] as? String ?? "") {
                preservation["Mode"] = "preserve-extension-v1"; preservation["Artifacts"] = plan["LegacyArtifacts"]
            }
            _ = try MigrationPreservedExtensionManifest(runtime:preservation)
        }
        catch { throw MigrationObserverReadinessError.preservationShape }
        func checked<T>(_ code: MigrationObserverReadinessError, _ operation: () throws -> T) throws -> T {
            do { return try operation() }
            catch MigrationObserverReadinessError.accessibilityRequired { throw MigrationObserverReadinessError.accessibilityRequired }
            catch { throw code }
        }
        guard let preserved = plan["PreservedExtension"] as? [String:Any],
              let target = preserved["path"] as? String, MigrationRuntimeConsoleManifest.path(target),
              let id = preserved["extensionID"] as? String, id == plan["ExtensionID"] as? String,
              plan["ExtensionStorageSHA256"] == nil, let canonical = plan["ChromeExecutable"] as? String,
              let requirement = plan["ChromeRequirement"] as? String, !requirement.isEmpty else { throw MigrationObserverReadinessError.preservationShape }
        let before = try checked(.chromeIdentity) { try image(chrome.brokerPID, chrome.brokerStartToken, canonical, requirement) }
        if plan["ChromeRecovery"] != nil {
            let google=try checked(.googleIdentity) { try image(chrome.brokerPID,chrome.brokerStartToken,canonical,MigrationChromeTrust.googleSignerRequirement) }
            guard google.pid==before.pid,google.birth==before.birth,google.executable==before.executable else{throw MigrationObserverReadinessError.googleIdentity}
        }
        try checked(.managementDocument) { try document(chrome.brokerPID,chrome.brokerStartToken,title,id) }
        let native = try checked(.nativeObservation) { try observe(chrome.brokerPID,chrome.brokerStartToken,title,Date().addingTimeInterval(10)) }
        let (actualPath, at) = try checked(.loadedPath) { try loaded(native,chrome.brokerPID,chrome.brokerStartToken,title,id) }
        try checked(.managementDocument) { try document(chrome.brokerPID,chrome.brokerStartToken,title,id) }
        guard actualPath == target else { throw MigrationObserverReadinessError.loadedPathMismatch }
        guard try checked(.chromeIdentityChanged, { try image(chrome.brokerPID,chrome.brokerStartToken,canonical,requirement) }) == before else { throw MigrationObserverReadinessError.chromeIdentityChanged }
        chromeIdentity = before
        var proof = native
        proof.append(try MigrationWorkerSession.canonical(["path":actualPath,"extensionID":id],order:["path","extensionID"]))
        proof.append(try MigrationWorkerSession.canonical(["pid":before.pid,"uid":before.uid,"birth":before.birth,"actualExecutable":before.executable,"canonicalExecutable":canonical,"requirement":before.requirement],order:["pid","uid","birth","actualExecutable","canonicalExecutable","requirement"]))
        evidence = MigrationLoadedExtensionEvidence(observedAt:at,receiptSHA256:MigrationUpgradeIntent.digest(proof),path:actualPath,extensionID:id,storageSHA256:"")
    }
    func makeShutdown(route: any MigrationBrokerLifecycleRoute) throws -> MigrationRuntimeShutdown {
        lock.lock(); defer { lock.unlock() }
        guard let evidence, Self.fresh(evidence.observedAt), let brokerIdentity, let chromeIdentity,
              let active = plan["ActiveHelperPath"] as? String, let activePin = plan["ActiveHelperRequirement"] as? String,
              let oldBirth = plan["OldConsoleBirth"] as? String else { throw MigrationUpgradeError.unavailable }
        var helperPins = [active: activePin]
        for role in ["helper", "native-host"] {
            let entry = try artifact(role)
            guard let path = entry["target"] as? String, let pin = entry["OldRequirement"] as? String,
                  helperPins[path] == nil || helperPins[path] == pin else { throw MigrationUpgradeError.invalidPreparation }
            helperPins[path] = pin
        }
        guard let oldPin = try artifact("console")["OldRequirement"] as? String else { throw MigrationUpgradeError.invalidPreparation }
        return try MigrationRuntimeShutdown(intentBinding: intentBinding, broker: brokerIdentity, chrome: chromeIdentity,
            helperPins: helperPins, capturedAt: evidence.observedAt, route: route,
            runtime: .system(consoleRequirement: oldPin, consoleBirth: oldBirth, canonicalChrome: plan["ChromeExecutable"] as? String, chromePID: chromeIdentity.pid))
    }
    private func artifact(_ role:String)throws->[String:Any] {
        guard let artifacts=plan[["unified-app-v2","unified-app-update-v3"].contains(plan["Mode"] as? String ?? "") ? "LegacyArtifacts" : "Artifacts"] as? [[String:Any]], artifacts.filter({$0["role"] as? String==role}).count==1,
              let artifact=artifacts.first(where:{$0["role"] as? String==role}) else{throw MigrationConsoleError.unavailable};return artifact
    }
    static func date(_ text:String)->Date? { let formatter=ISO8601DateFormatter();formatter.formatOptions=[.withInternetDateTime,.withFractionalSeconds];return formatter.date(from:text) ?? ISO8601DateFormatter().date(from:text) }
    static func fresh(_ at:Date)->Bool { at<=Date() && Date().timeIntervalSince(at)<=30 }
    /// Complete exact-window metadata only. The management-document proof is
    /// checked independently before and after this read; website AX lookalikes fail.
    static func loadedPath(_ data:Data,pid:Int32,birth:String,title:String)throws->(String,Date) {
        guard let root=try JSONSerialization.jsonObject(with:data) as? [String:Any],root["truncated"] as? Bool==false,
              (root["unavailable"] as? [String] ?? []).isEmpty, let surface=root["surface"] as? [String:Any],
              surface["kind"] as? String=="native",surface["bundleId"] as? String=="com.google.Chrome",surface["processId"] as? Int32==pid,surface["processStartToken"] as? String==birth,
              let scope=root["windowScope"] as? [String:String],scope["title"]==title,scope["role"]=="AXWindow",
              root["nativeRoot"] == nil, root["windowRootsOnly"] as? Bool != true,
              let ended=root["ended"] as? String,let finished=date(ended),fresh(finished),
              let started=root["started"] as? String,let at=date(started),at<=finished,fresh(at),
              let nodes=root["nodes"] as? [[String:Any]],!nodes.isEmpty,nodes.count<=4096 else{throw MigrationConsoleError.unavailable}
        let web=nodes.filter{$0["nativeRole"] as? String=="AXWebArea"}
        guard web.count==1,let groups=Optional(nodes.filter{$0["identifier"] as? String=="details-view"}),groups.count==1,
              let group=groups.first,let groupRef=group["ref"] as? [String:Any],let groupID=groupRef["id"] as? String else{throw MigrationConsoleError.unavailable}
        var byID:[String:[String:Any]]=[:]
        for node in nodes {
            guard let ref=node["ref"] as? [String:Any],let id=ref["id"] as? String,byID[id]==nil,
                  (node["unavailable"] as? [String] ?? []).isEmpty else{throw MigrationConsoleError.unavailable};byID[id]=node
        }
        func within(_ node:[String:Any])->Bool {
            var current=node;var visited:Set<String>=[]
            for _ in 0..<64 {guard let parent=current["parentId"] as? String,visited.insert(parent).inserted else{return false};if parent==groupID{return true};guard let next=byID[parent] else{return false};current=next};return false
        }
        guard let webRef = web.first?["ref"] as? [String:Any], let webID = webRef["id"] as? String else { throw MigrationConsoleError.unavailable }
        var ancestor = group["parentId"] as? String, seen: Set<String> = []
        while let id = ancestor, id != webID {
            guard seen.insert(id).inserted, seen.count <= 64, let parent = byID[id] else { throw MigrationConsoleError.unavailable }
            ancestor = parent["parentId"] as? String
        }
        guard ancestor == webID else { throw MigrationConsoleError.unavailable }
        let labels=nodes.filter{within($0) && $0["nativeRole"] as? String=="AXStaticText" && $0["name"] as? String=="Loaded from"}
        guard labels.count==1,let parent=labels.first?["parentId"] as? String else{throw MigrationConsoleError.unavailable}
        let paths=nodes.filter{$0["parentId"] as? String==parent && $0["nativeRole"] as? String=="AXStaticText" && ($0["name"] as? String).map(MigrationRuntimeConsoleManifest.path)==true}
        guard paths.count==1,let path=paths.first?["name"] as? String else{throw MigrationConsoleError.unavailable}
        for node in [web[0], group, labels[0], paths[0]] {
            guard node["nativeOwnerMatchesRoot"] as? Bool == true, node["nativeOwnerProcessId"] as? Int32 == pid,
                  node["nativeOwnerStartToken"] as? String == birth, node["nativeOwnerBundleId"] as? String == "com.google.Chrome",
                  node["nativeOwnerUid"] as? UInt32 == getuid() else { throw MigrationConsoleError.unavailable }
        }
        return(path,at)
    }
    func response(_ payload:Data,authorizationDeadline:Date)throws->Data {
        lock.lock();defer{lock.unlock()}
        try MigrationReadinessJSON.validate(payload)
        let mode = preservedChrome == nil ? "" : (plan["Mode"] as? String ?? "")
        let order=["version","nonce","session","manifestSHA256","deadlineUnixMilliseconds"] + (mode.isEmpty ? [] : ["mode"])
        guard let request=try JSONSerialization.jsonObject(with:payload) as? [String:Any],Set(request.keys)==Set(order),
              MigrationRuntimeConsoleManifest.integer(request["version"])==1,
              let nonce=request["nonce"] as? String,MigrationAuthorizationRecord.digest(nonce),nonce != String(repeating:"0",count:64),nonces.count<128,nonces.insert(nonce).inserted,
              request["session"] as? String==session,request["manifestSHA256"] as? String==manifest,
              (request["mode"] as? String ?? "") == mode,
              let milliseconds=MigrationRuntimeConsoleManifest.integer(request["deadlineUnixMilliseconds"]),
              try MigrationWorkerSession.canonical(request,order:order)==payload,
              let evidence,Self.fresh(evidence.observedAt) else{throw MigrationConsoleError.unavailable}
        let deadline=Date(timeIntervalSince1970:Double(milliseconds)/1000)
        guard deadline>Date(),deadline<=authorizationDeadline,deadline.timeIntervalSinceNow<=5.1 else{throw MigrationConsoleError.unavailable}
        let consoleArtifact=try artifact("console")
        guard let oldRequirement=consoleArtifact["OldRequirement"] as? String,let oldBirth=plan["OldConsoleBirth"] as? String,
              let broker=plan["BrokerPath"] as? String,let active=plan["ActiveHelperPath"] as? String,
              let helper=try artifact("helper")["target"] as? String,let host=try artifact("native-host")["target"] as? String,let chrome=plan["ChromeExecutable"] as? String else{throw MigrationConsoleError.unavailable}
        let paths=Array(Set([broker,active,helper,host,chrome])).sorted()
        try console(oldRequirement,oldBirth);try stopped(paths);try console(oldRequirement,oldBirth)
        guard deadline>Date(),Self.fresh(evidence.observedAt) else{throw MigrationConsoleError.unavailable}
        var fields: [String:Any] = ["version":1,"nonce":nonce,"session":session,"manifestSHA256":manifest,"requestSHA256":MigrationUpgradeIntent.digest(payload),"observedAtUnixMilliseconds":Int64(floor(evidence.observedAt.timeIntervalSince1970*1000)),"sourceReceiptSHA256":evidence.receiptSHA256,"loadedExtensionPath":evidence.path,"extensionID":evidence.extensionID,"storageSHA256":evidence.storageSHA256,"stoppedExecutables":paths,"oldConsoleRequirement":oldRequirement,"oldConsoleBirth":oldBirth]
        if !mode.isEmpty { fields.removeValue(forKey:"storageSHA256"); fields["mode"] = mode }
        return try MigrationWorkerSession.canonical(fields, order:["version","nonce","session","manifestSHA256","requestSHA256","observedAtUnixMilliseconds","sourceReceiptSHA256","loadedExtensionPath","extensionID","storageSHA256","stoppedExecutables","oldConsoleRequirement","oldConsoleBirth","mode"])
    }
}

/// OS evidence is derived here, never a caller-supplied quiescence flag.
enum MigrationObserverOS {
    static func birth(_ pid:pid_t)throws->String {
        var info=proc_bsdinfo();guard proc_pidinfo(pid,PROC_PIDTBSDINFO,0,&info,Int32(MemoryLayout<proc_bsdinfo>.size))==MemoryLayout<proc_bsdinfo>.size,info.pbi_pid==UInt32(pid),info.pbi_uid==getuid(),info.pbi_status != 5 else{throw MigrationConsoleError.unavailable};return "\(info.pbi_start_tvsec):\(info.pbi_start_tvusec)"
    }
    static func consoleIdentity(_ requirement:String,_ expectedBirth:String)throws {
        guard try birth(getpid())==expectedBirth,MigrationAuthorizationRecord.requirement(requirement,role:"consent") else{throw MigrationConsoleError.unavailable}
        var own:SecCode?,rule:SecRequirement?
        guard SecCodeCopySelf([], &own)==errSecSuccess,SecRequirementCreateWithString(requirement as CFString,[],&rule)==errSecSuccess,let own,let rule,SecCodeCheckValidity(own,SecCSFlags(rawValue:kSecCSStrictValidate),rule)==errSecSuccess else{throw MigrationConsoleError.unavailable}
    }
    static func requireStopped(_ paths:[String])throws {
        func pids()throws->[pid_t] {var ids=[pid_t](repeating:0,count:65536);let count=ids.withUnsafeMutableBytes{proc_listallpids($0.baseAddress,Int32($0.count))};guard count>0,count<ids.count else{throw MigrationConsoleError.unavailable};return ids.prefix(Int(count)).filter{$0>0}.sorted()}
        var targetImages: [stat] = []
        for path in paths {
            var info = stat()
            if lstat(path, &info) == 0 { guard info.st_mode & S_IFMT == S_IFREG else { throw MigrationConsoleError.unavailable }; targetImages.append(info) }
            else if errno != ENOENT { throw MigrationConsoleError.unavailable }
        }
        func snapshot() throws -> [String] {
            var result: [String] = []
            for pid in try pids() {
                var info = proc_bsdinfo()
                let count = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, Int32(MemoryLayout<proc_bsdinfo>.size))
                if count != MemoryLayout<proc_bsdinfo>.size {
                    if kill(pid, 0) == -1 && errno == ESRCH { continue }
                    throw MigrationConsoleError.unavailable
                }
                if info.pbi_uid != getuid() || info.pbi_status == 5 { continue }
                var buffer = [CChar](repeating: 0, count: 4096)
                guard proc_pidpath(pid, &buffer, UInt32(buffer.count)) > 0 else {
                    if kill(pid, 0) == -1 && errno == ESRCH { continue }
                    throw MigrationConsoleError.unavailable
                }
                let path = String(cString: buffer), token = "\(info.pbi_start_tvsec):\(info.pbi_start_tvusec)"
                var image = stat()
                let imageStatus = lstat(path, &image)
                guard imageStatus == 0, image.st_mode & S_IFMT == S_IFREG,
                      !paths.contains(path), !targetImages.contains(where: { $0.st_dev == image.st_dev && $0.st_ino == image.st_ino }),
                      try birth(pid) == token else { throw MigrationConsoleError.unavailable }
                result.append("\(pid):\(token):\(path)")
            }
            return result.sorted()
        }
        let before = try snapshot()
        guard try snapshot() == before else { throw MigrationConsoleError.unavailable }
    }
    static func managementDocument(_ pid:Int32,_ token:String,_ title:String,_ extensionID:String)throws {
        guard AXIsProcessTrusted() else { throw MigrationObserverReadinessError.accessibilityRequired }
        guard extensionID.count==32,extensionID.allSatisfy({("a"..."p").contains(String($0))}),try birth(pid)==token,
              NSRunningApplication(processIdentifier:pid)?.bundleIdentifier=="com.google.Chrome" else{throw MigrationConsoleError.unavailable}
        func attr(_ element:AXUIElement,_ name:String)throws->CFTypeRef {
            var owner: pid_t = 0
            guard AXUIElementGetPid(element, &owner) == .success, owner == pid else { throw MigrationConsoleError.unavailable }
            AXUIElementSetMessagingTimeout(element,0.05);var result:CFTypeRef?
            guard AXUIElementCopyAttributeValue(element,name as CFString,&result) == .success,let result else{throw MigrationConsoleError.unavailable};return result
        }
        let app=AXUIElementCreateApplication(pid)
        guard let windows=try attr(app,kAXWindowsAttribute) as? [AXUIElement],windows.count<=64 else{throw MigrationConsoleError.unavailable}
        let matching=try windows.filter{try attr($0,kAXTitleAttribute) as? String==title}
        guard matching.count==1,let window=matching.first else{throw MigrationConsoleError.unavailable}
        var queue=[window],web:[AXUIElement]=[],count=0
        while !queue.isEmpty {let node=queue.removeFirst();count+=1;guard count<=4096 else{throw MigrationConsoleError.unavailable}
            if try attr(node,kAXRoleAttribute) as? String=="AXWebArea" {web.append(node);continue}
            var raw:CFTypeRef?;let status=AXUIElementCopyAttributeValue(node,kAXChildrenAttribute as CFString,&raw)
            if status == .success {guard let children=raw as? [AXUIElement] else{throw MigrationConsoleError.unavailable};queue.append(contentsOf:children)} else if status != .noValue && status != .attributeUnsupported {throw MigrationConsoleError.unavailable}
        }
        guard web.count==1,let area=web.first else{throw MigrationConsoleError.unavailable}
        var raw:CFTypeRef?;let status=AXUIElementCopyAttributeValue(area,"AXURL" as CFString,&raw)
        let address:String?
        if status == .success {address=(raw as? URL)?.absoluteString ?? (raw as? String)} else {address=try attr(area,kAXDocumentAttribute) as? String}
        guard address=="chrome://extensions/?id=\(extensionID)",try birth(pid)==token else{throw MigrationConsoleError.unavailable}
    }
}
