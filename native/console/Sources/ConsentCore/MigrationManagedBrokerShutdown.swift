import Foundation
import Darwin

private final class MigrationShutdownPlistKeys: NSObject, XMLParserDelegate {
    var valid = true, depth = 0, readingKey = false
    var key = "", keys: Set<String> = []
    func parser(_ parser: XMLParser, didStartElement elementName: String, namespaceURI: String?, qualifiedName qName: String?, attributes: [String:String]) {
        depth += 1
        if depth > 8 || (elementName == "dict" && depth != 2) { valid = false; parser.abortParsing() }
        if elementName == "key" { if depth != 3 { valid = false; parser.abortParsing() }; readingKey = true; key = "" }
    }
    func parser(_ parser: XMLParser, foundCharacters string: String) { if readingKey { key += string } }
    func parser(_ parser: XMLParser, didEndElement elementName: String, namespaceURI: String?, qualifiedName qName: String?) {
        if elementName == "key" { if !keys.insert(key).inserted { valid = false; parser.abortParsing() }; readingKey = false }
        depth -= 1
    }
    static func check(_ data: Data) -> Bool {
        guard data.starts(with: Data("<?xml".utf8)) else { return false }
        let delegate = MigrationShutdownPlistKeys(), parser = XMLParser(data: data)
        parser.delegate = delegate; parser.shouldResolveExternalEntities = false
        return parser.parse() && delegate.valid && delegate.depth == 0
    }
}

/// Frozen managed launchd definition. Reading it grants no process authority;
/// the selected broker is also matched to the loaded job and kernel identity.
struct MigrationManagedShutdownPlan {
    let path: String, digest: String, broker: String, listen: String, config: String
    init(intent: MigrationUpgradeIntent, frozenPlan: Data) throws {
        guard MigrationUpgradeIntent.digest(frozenPlan) == intent.runtimeManifestSHA256,
              let root = try JSONSerialization.jsonObject(with: frozenPlan) as? [String: Any],
              let readiness = root["readiness"] as? [String: Any],
              let job = readiness["launchd"] as? [String: Any], Set(job.keys) == Set(["path", "sha256"]),
              let path = job["path"] as? String, MigrationRuntimeConsoleManifest.path(path),
              let digest = job["sha256"] as? String, MigrationAuthorizationRecord.digest(digest),
              let listen = readiness["listen"] as? String, !listen.isEmpty, listen.utf8.count <= 128 else { throw MigrationUpgradeError.invalidPreparation }
        if let runtime=root["runtime"] as? [String:Any], runtime["Mode"] as? String == "unified-app-update-v3" {
            _ = try MigrationUnifiedAppManifest(runtime:runtime,intent:intent)
            guard let frozenConfig=runtime["ConfigPath"] as? String else{throw MigrationUpgradeError.invalidPreparation};config=frozenConfig
        } else {config=URL(fileURLWithPath:intent.options[0]).deletingLastPathComponent().appendingPathComponent("config.json").path}
        self.path=path;self.digest=digest;broker=intent.options[0];self.listen=listen
    }
    var arguments: [String] { [broker,"serve","-config",config,"-listen",listen] }
    func job(_ data: Data) throws -> String {
        guard MigrationUpgradeIntent.digest(data) == digest, data.count <= 65536, MigrationShutdownPlistKeys.check(data),
              let job = try PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any],
              job["Program"] == nil, job["ProgramArguments"] as? [String] == arguments,
              let label = job["Label"] as? String, label.range(of: #"\Acom\.viant\.mechanize\.[a-z0-9.-]+\z"#, options:.regularExpression) != nil,
              Set(job.keys).isSubset(of: ["Label","ProgramArguments","KeepAlive","RunAtLoad","StandardOutPath","StandardErrorPath","WorkingDirectory","ProcessType"]) else { throw MigrationUpgradeError.invalidPreparation }
        if let raw = job["KeepAlive"] {
            guard let value = raw as? NSNumber, CFGetTypeID(value) == CFBooleanGetTypeID(), !value.boolValue else { throw MigrationUpgradeError.invalidPreparation }
        }
        return "gui/\(getuid())/\(label)"
    }
    func loadedPID(_ data: Data, service: String) throws -> Int32? {
        guard !data.isEmpty,data.count<=65536,let text=String(data:data,encoding:.utf8) else{throw MigrationUpgradeError.invalidPreparation}
        let lines=text.components(separatedBy:"\n").map{$0.trimmingCharacters(in:.whitespaces)}
        for line in lines {
            let lower = line.lowercased()
            if lower.hasPrefix("properties = ") && lower.dropFirst(13).split(separator:"|").map({$0.trimmingCharacters(in:.whitespaces)}).contains("keepalive") { throw MigrationUpgradeError.invalidPreparation }
            if lower.hasPrefix("keepalive = ") && lower != "keepalive = false" && lower != "keepalive = 0" { throw MigrationUpgradeError.invalidPreparation }
        }
        guard lines.first==service+" = {" else{throw MigrationUpgradeError.invalidPreparation}
        var paths:[String]=[],programs:[String]=[],pids:[Int32]=[],args:[String]=[],inside=false,blocks=0
        for line in lines.dropFirst() {
            if inside {if line=="}" {inside=false}else{args.append(line)};continue}
            if line=="arguments = {" {inside=true;blocks+=1}
            if line.hasPrefix("path = ") {paths.append(String(line.dropFirst(7)))}
            if line.hasPrefix("program = ") {programs.append(String(line.dropFirst(10)))}
            if line.hasPrefix("pid = ") {guard let pid=Int32(line.dropFirst(6)),pid>0 else{throw MigrationUpgradeError.invalidPreparation};pids.append(pid)}
        }
        guard paths==[path],programs==[broker],args==arguments,blocks==1,!inside,pids.count<=1 else{throw MigrationUpgradeError.invalidPreparation}
        return pids.first
    }
}
struct MigrationManagedShutdownRuntime {
    let read: (String) throws -> Data
    let status: (String, Date) throws -> Data
    let helpers: ([String:String]) throws -> [MigrationShutdownIdentity]
    let inspect: (MigrationShutdownIdentity) -> MigrationShutdownPresence
    let signal: (MigrationShutdownIdentity, Date) throws -> Void
    static let system = MigrationManagedShutdownRuntime(read: MigrationManagedShutdownOS.read,
        status: MigrationManagedShutdownOS.status, helpers: MigrationManagedShutdownOS.helpers,
        inspect: MigrationShutdownOS.inspect, signal: { identity, deadline in
            guard MigrationShutdownOS.inspect(identity) == .same, Date() < deadline, identity.pid != getpid() else { throw MigrationUpgradeError.recoveryRequired }
            guard kill(identity.pid,SIGTERM)==0 else { throw MigrationUpgradeError.recoveryRequired }
        })
}
final class MigrationManagedBrokerShutdown: MigrationBrokerLifecycleRoute {
    private let plan: MigrationManagedShutdownPlan, runtime: MigrationManagedShutdownRuntime
    private var qualified: MigrationShutdownIdentity?, service: String?, submitted=false
    init(plan: MigrationManagedShutdownPlan, runtime: MigrationManagedShutdownRuntime = .system) {self.plan=plan;self.runtime=runtime}
    func qualify(broker: MigrationShutdownIdentity, helperPins: [String:String], deadline: Date) throws -> [MigrationShutdownIdentity] {
        guard qualified==nil,!submitted,deadline>Date(),broker.executable==plan.broker,runtime.inspect(broker) == .same else{throw MigrationUpgradeError.invalidPreparation}
        let service=try plan.job(runtime.read(plan.path))
        guard try plan.loadedPID(runtime.status(service,deadline),service:service)==broker.pid,runtime.inspect(broker) == .same else{throw MigrationUpgradeError.invalidPreparation}
        let identities=try runtime.helpers(helperPins)
        _ = try plan.job(runtime.read(plan.path))
        guard deadline>Date(),runtime.inspect(broker) == .same else{throw MigrationUpgradeError.invalidPreparation}
        self.qualified=broker;self.service=service;return identities
    }
    func stop(deadline: Date, willDispatch: () throws -> Void) throws {
        guard !submitted,let identity=qualified,let service,deadline>Date(),runtime.inspect(identity) == .same else{throw MigrationUpgradeError.invalidPreparation}
        guard try plan.job(runtime.read(plan.path))==service,try plan.loadedPID(runtime.status(service,deadline),service:service)==identity.pid else{throw MigrationUpgradeError.invalidPreparation}
        try willDispatch();submitted=true
        try runtime.signal(identity,deadline)
    }
    func verifyStopped(deadline: Date) throws {
        guard submitted,let identity=qualified,let service,deadline>Date(),runtime.inspect(identity) == .gone,
              try plan.job(runtime.read(plan.path))==service,try plan.loadedPID(runtime.status(service,deadline),service:service)==nil else{throw MigrationUpgradeError.recoveryRequired}
    }
}

private final class MigrationShutdownOutput: @unchecked Sendable {
    private let lock=NSLock();private var bytes=Data();private var overflow=false
    func append(_ value:Data){lock.lock();defer{lock.unlock()};if bytes.count+value.count>65536{overflow=true}else{bytes.append(value)}}
    func result()throws->Data{lock.lock();defer{lock.unlock()};guard !overflow else{throw MigrationUpgradeError.unavailable};return bytes}
}
enum MigrationManagedShutdownOS {
    static func read(_ path:String)throws->Data {
        guard MigrationRuntimeConsoleManifest.path(path) else{throw MigrationUpgradeError.invalidPreparation}
        let parts=path.split(separator:"/");var parent=Darwin.open("/",O_RDONLY|O_DIRECTORY|O_CLOEXEC)
        guard parent>=0 else{throw MigrationUpgradeError.unavailable};defer{Darwin.close(parent)}
        for part in parts.dropLast(){let next=openat(parent,String(part),O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);guard next>=0 else{throw MigrationUpgradeError.unavailable};Darwin.close(parent);parent=next}
        var directory=stat();guard fstat(parent,&directory)==0,directory.st_uid==getuid(),directory.st_mode&0o077==0,let name=parts.last else{throw MigrationUpgradeError.unavailable}
        let fd=openat(parent,String(name),O_RDONLY|O_NOFOLLOW|O_CLOEXEC);guard fd>=0 else{throw MigrationUpgradeError.unavailable};defer{Darwin.close(fd)}
        var before=stat();guard fstat(fd,&before)==0,before.st_uid==getuid(),before.st_mode&S_IFMT==S_IFREG,before.st_mode&0o077==0,before.st_nlink==1,before.st_size>0,before.st_size<=65536 else{throw MigrationUpgradeError.unavailable}
        var data=Data(count:Int(before.st_size));let count=data.withUnsafeMutableBytes{Darwin.read(fd,$0.baseAddress,$0.count)}
        var after=stat(),entry=stat();guard count==data.count,fstat(fd,&after)==0,fstatat(parent,String(name),&entry,AT_SYMLINK_NOFOLLOW)==0,
              before.st_dev==entry.st_dev,before.st_ino==entry.st_ino,before.st_size==after.st_size,before.st_mtimespec.tv_sec==after.st_mtimespec.tv_sec,before.st_mtimespec.tv_nsec==after.st_mtimespec.tv_nsec,before.st_ctimespec.tv_sec==after.st_ctimespec.tv_sec,before.st_ctimespec.tv_nsec==after.st_ctimespec.tv_nsec else{throw MigrationUpgradeError.unavailable}
        return data
    }
    static func status(_ service:String,_ deadline:Date)throws->Data {
        guard deadline>Date(),service.hasPrefix("gui/\(getuid())/com.viant.mechanize.") else{throw MigrationUpgradeError.unavailable}
        let command=Process(),pipe=Pipe(),output=MigrationShutdownOutput(),done=DispatchSemaphore(value:0)
        command.executableURL=URL(fileURLWithPath:"/bin/launchctl");command.arguments=["print",service];command.environment=[:]
        command.standardInput=FileHandle.nullDevice;command.standardError=FileHandle.nullDevice;command.standardOutput=pipe
        pipe.fileHandleForReading.readabilityHandler={handle in output.append(handle.availableData)}
        command.terminationHandler={_ in done.signal()}
        try command.run()
        try? pipe.fileHandleForWriting.close()
        let completed=done.wait(timeout:.now()+max(0,min(3,deadline.timeIntervalSinceNow)))
        pipe.fileHandleForReading.readabilityHandler=nil
        guard completed == .success else{command.terminate();try? pipe.fileHandleForReading.close();throw MigrationUpgradeError.unavailable}
        output.append(pipe.fileHandleForReading.readDataToEndOfFile());try? pipe.fileHandleForReading.close()
        guard command.terminationStatus==0,deadline>Date() else{throw MigrationUpgradeError.unavailable};return try output.result()
    }
    static func helpers(_ pins:[String:String])throws->[MigrationShutdownIdentity] {
        var pids=[pid_t](repeating:0,count:65536)
        let count=pids.withUnsafeMutableBytes{proc_listallpids($0.baseAddress,Int32($0.count))}
        guard count>0,count<pids.count else{throw MigrationUpgradeError.unavailable}
        var result:[MigrationShutdownIdentity]=[]
        for pid in pids.prefix(Int(count)) where pid>0 && pid != getpid() {
            var info=proc_bsdinfo()
            guard proc_pidinfo(pid,PROC_PIDTBSDINFO,0,&info,Int32(MemoryLayout<proc_bsdinfo>.size))==MemoryLayout<proc_bsdinfo>.size else{if kill(pid,0)==(-1) && errno==ESRCH{continue};throw MigrationUpgradeError.unavailable}
            if info.pbi_uid != getuid() || info.pbi_status==5{continue}
            var buffer=[CChar](repeating:0,count:4096)
            guard proc_pidpath(pid,&buffer,UInt32(buffer.count))>0 else{if kill(pid,0)==(-1) && errno==ESRCH{continue};throw MigrationUpgradeError.unavailable}
            let path=String(cString:buffer);guard let pin=pins[path] else{continue}
            let identity=MigrationShutdownIdentity(pid:pid,uid:getuid(),birth:"\(info.pbi_start_tvsec):\(info.pbi_start_tvusec)",executable:path,requirement:pin)
            guard MigrationShutdownOS.inspect(identity) == .same else{throw MigrationUpgradeError.invalidPreparation}
            result.append(identity)
        }
        return result
    }
}
