import Foundation
import Darwin
import Security

struct ConsoleHelperLaunchRequest {
    let nonce: String, arguments: [String], identitySocket: String, identityNonce: String, helperRequirement: String, consoleRequirement: String
    init(_ data: Data, helperPin: String) throws {
        try MigrationReadinessJSON.validate(data)
        guard data.count <= 32768, let v=try JSONSerialization.jsonObject(with:data) as? [String:Any],
              Set(v.keys)==Set(["version","op","nonce","arguments","identitySocket","identityNonce","helperRequirement","consoleRequirement"]),
              MigrationRuntimeConsoleManifest.integer(v["version"])==1,v["op"] as? String=="launch",
              let nonce=v["nonce"] as? String,MigrationAuthorizationRecord.digest(nonce),
              let identityNonce=v["identityNonce"] as? String,MigrationAuthorizationRecord.digest(identityNonce),
              let path=v["identitySocket"] as? String,Self.identityPath(path),
              let helper=v["helperRequirement"] as? String,helper==helperPin,MigrationAuthorizationRecord.requirement(helper,role:"native"),
              let console=v["consoleRequirement"] as? String,MigrationAuthorizationRecord.requirement(console,role:"consent"),
              let args=v["arguments"] as? [String],Self.validArguments(args) else {throw BrokerTransportError.untrustedPeer}
        self.nonce=nonce;self.arguments=args;self.identitySocket=path;self.identityNonce=identityNonce;self.helperRequirement=helper;self.consoleRequirement=console
    }
    static func identityPath(_ path:String)->Bool {
        let base=path.hasPrefix("/private/tmp/") ? "/private/tmp/" : "/tmp/"
        guard path.hasPrefix(base),path.hasSuffix("/peer.sock") else{return false}
        let directory=String(path.dropFirst(base.count).dropLast("/peer.sock".count))
        let prefix="mechanize-identity-"
        return directory.hasPrefix(prefix) && !directory.dropFirst(prefix.count).isEmpty && directory.dropFirst(prefix.count).utf8.allSatisfy{(48...57).contains($0)}
    }
    static func validArguments(_ args:[String])->Bool {
        let profiles:Set<String>=["--allow-mutations","--allow-launch","--allow-semantic","--allow-recording","--private-administration"]
        let additions:Set<String>=["--allow-targeted-keyboard","--allow-session-text","--allow-session-keyboard","--allow-window-frame-click"]
        guard args.count<=9,Set(args).count==args.count,Set(args).isSubset(of:profiles.union(additions)),args.filter({profiles.contains($0)}).count<=1 else{return false}
        if args.contains("--private-administration") || args.contains("--allow-recording") || args.contains("--allow-launch") {return args.count==1}
        if !Set(args).isDisjoint(with:additions) && !args.contains("--allow-semantic") {return false}
        return true
    }
}

enum ConsoleHelperLaunchAdmission {
    static func validate(_ data:Data,helperPin:String,authenticate:()throws->Void,verifySelf:(String)throws->Void,verifyHelper:()throws->Void)throws->ConsoleHelperLaunchRequest {
        try authenticate()
        let request=try ConsoleHelperLaunchRequest(data,helperPin:helperPin)
        try verifySelf(request.consoleRequirement);try verifyHelper();try authenticate()
        return request
    }
}

/// Private fixed-purpose launcher. No command, executable, environment, credential,
/// desktop request, or helper reply is accepted through this service.
public final class ConsoleHelperLaunchService {
    private let endpoint:String,helper:URL,helperPin:String,broker:SignedBrokerPeer
    private let listener:Int32,lockFD:Int32
    private let mutex=NSLock()
    private var connections:Set<Int32>=[]
    private var used:Set<String>=[]
    private init(endpoint:String,helper:URL,helperPin:String,broker:SignedBrokerPeer,listener:Int32,lockFD:Int32){self.endpoint=endpoint;self.helper=helper;self.helperPin=helperPin;self.broker=broker;self.listener=listener;self.lockFD=lockFD}
    public static func startEnrolled() throws -> ConsoleHelperLaunchService? {
        let metadata=Bundle.main.infoDictionary ?? [:]
        guard metadata["MechanizeHelperLaunchTransport"] != nil else{return nil}
        guard metadata["MechanizeHelperLaunchTransport"] as? String=="console-v1",Bundle.main.bundleIdentifier=="com.viant.mechanize.consent",
              let brokerPin=metadata["MechanizeBrokerRequirement"] as? String,MigrationAuthorizationRecord.requirement(brokerPin,role:"broker"),
              let helperPin=metadata["MechanizeHelperRequirement"] as? String,MigrationAuthorizationRecord.requirement(helperPin,role:"native") else{throw BrokerTransportError.untrustedPeer}
        let paths=try HelperInstallation.runtimePaths(appURL:Bundle.main.bundleURL,metadata:metadata)
        guard paths.embedded else{throw BrokerTransportError.unsafeEndpoint}
        try signature(Bundle.main.bundleURL,nil);try signature(paths.helper,helperPin)
        let home=FileManager.default.homeDirectoryForCurrentUser.path
        let directory=home+"/Library/Application Support/Mechanize/runtime"
        try validateDirectory(home:home,directory:directory)
        let endpoint=directory+"/consent.sock.helper"
        guard endpoint.utf8.count<104 else{throw BrokerTransportError.unsafeEndpoint}
        let lockFD=Darwin.open(endpoint+".lock",O_RDWR|O_CREAT|O_NOFOLLOW|O_CLOEXEC,0o600)
        guard lockFD>=0 else{throw BrokerTransportError.unavailable}
        var lockInfo=stat();guard fstat(lockFD,&lockInfo)==0,lockInfo.st_uid==getuid(),lockInfo.st_mode&S_IFMT==S_IFREG,lockInfo.st_mode&0o077==0,lockInfo.st_nlink==1,flock(lockFD,LOCK_EX|LOCK_NB)==0 else{Darwin.close(lockFD);throw BrokerTransportError.unsafeEndpoint}
        do {
            var old=stat()
            if lstat(endpoint,&old)==0 {
                guard old.st_uid==getuid(),old.st_mode&S_IFMT==S_IFSOCK,old.st_mode&0o077==0 else{throw BrokerTransportError.unsafeEndpoint}
                let probe=socket(AF_UNIX,SOCK_STREAM,0);guard probe>=0 else{throw BrokerTransportError.unavailable}
                guard fcntl(probe,F_SETFL,O_NONBLOCK)==0 else{Darwin.close(probe);throw BrokerTransportError.unavailable}
                let result=withAddress(endpoint){Darwin.connect(probe,$0,$1)};let code=errno;Darwin.close(probe)
                guard result<0,code==ECONNREFUSED,unlink(endpoint)==0 else{throw BrokerTransportError.unavailable}
            } else if errno != ENOENT {throw BrokerTransportError.unsafeEndpoint}
            let fd=socket(AF_UNIX,SOCK_STREAM,0);guard fd>=0 else{throw BrokerTransportError.unavailable}
            guard fcntl(fd,F_SETFD,FD_CLOEXEC)==0,withAddress(endpoint,{Darwin.bind(fd,$0,$1)})==0,chmod(endpoint,0o600)==0,listen(fd,16)==0 else{Darwin.close(fd);throw BrokerTransportError.unavailable}
            let service=try ConsoleHelperLaunchService(endpoint:endpoint,helper:paths.helper,helperPin:helperPin,broker:SignedBrokerPeer(designatedRequirement:brokerPin,expectedUID:getuid()),listener:fd,lockFD:lockFD)
            DispatchQueue.global(qos:.userInitiated).async{service.acceptLoop()};return service
        } catch {Darwin.close(lockFD);throw error}
    }
    static func validateDirectory(home:String,directory:String)throws {
        guard directory==home+"/Library/Application Support/Mechanize/runtime" else{throw BrokerTransportError.unsafeEndpoint}
        var path=home
        for part in ["","Library","Application Support","Mechanize","runtime"] {
            if !part.isEmpty{path+="/"+part};var info=stat()
            guard lstat(path,&info)==0,info.st_uid==getuid(),info.st_mode&S_IFMT==S_IFDIR,info.st_mode&0o022==0 else{throw BrokerTransportError.unsafeEndpoint}
            if part=="runtime" && info.st_mode&0o077 != 0 {throw BrokerTransportError.unsafeEndpoint}
        }
    }
    private func acceptLoop(){while true {let fd=Darwin.accept(listener,nil,nil);if fd<0{if errno==EINTR{continue};return};_ = fcntl(fd,F_SETFD,FD_CLOEXEC)
        mutex.lock();let admitted=connections.count<16;if admitted{connections.insert(fd)};mutex.unlock()
        if !admitted{Darwin.close(fd);continue}
        DispatchQueue.global(qos:.userInitiated).async{self.serve(fd);self.mutex.lock();self.connections.remove(fd);self.mutex.unlock();Darwin.close(fd)}
    }}
    private func serve(_ fd:Int32){
        var rights:[Int32]=[];var child:pid_t=0;var reaped=false
        defer{for value in rights{Darwin.close(value)};if child>0 && !reaped{_ = Self.reap(child,stop:true)}}
        do {
            var timeout=timeval(tv_sec:5,tv_usec:0),one:Int32=1
            guard setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,socklen_t(MemoryLayout<timeval>.size))==0,setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&timeout,socklen_t(MemoryLayout<timeval>.size))==0,setsockopt(fd,SOL_SOCKET,SO_NOSIGPIPE,&one,4)==0 else{throw BrokerTransportError.unavailable}
            try broker.authenticate(socket:fd)
            rights=try Self.receiveRights(fd)
            let request=try ConsoleHelperLaunchAdmission.validate(Self.readFrame(fd),helperPin:helperPin,authenticate:{try self.broker.authenticate(socket:fd)},verifySelf:Self.ownSignature,verifyHelper:{try Self.signature(self.helper,self.helperPin)})
            try broker.authenticate(socket:fd);let brokerPID=try Self.peerPID(fd)
            try Self.ownSignature(request.consoleRequirement);try Self.signature(helper,helperPin)
            try Self.identityEndpoint(request.identitySocket)
            mutex.lock();let fresh=used.count<4096 && used.insert(request.nonce).inserted;mutex.unlock()
            guard fresh else{throw BrokerTransportError.untrustedPeer}
            try broker.authenticate(socket:fd)
            child=try Self.spawn(helper,request,rights,brokerPID)
            for value in rights{Darwin.close(value)};rights=[]
            try Self.signature(helper,helperPin);try broker.authenticate(socket:fd)
            try Self.writeFrame(fd,["version":1,"nonce":request.nonce,"state":"launched","pid":child])
            while true {
                var status:Int32=0;let result=waitpid(child,&status,WNOHANG)
                if result==child {reaped=true;try Self.finishReapedChild(fd,nonce:request.nonce,pid:child,status:status,authenticate:{try self.broker.authenticate(socket:fd)});return}
                guard result==0 else{throw BrokerTransportError.unavailable}
                var poller=pollfd(fd:fd,events:Int16(POLLIN),revents:0)
                let ready=poll(&poller,1,20);if ready<0{if errno==EINTR{continue};throw BrokerTransportError.unavailable};if ready==0{continue}
                try broker.authenticate(socket:fd)
                let raw=try Self.readFrame(fd);try MigrationReadinessJSON.validate(raw)
                guard let stop=try JSONSerialization.jsonObject(with:raw) as? [String:Any],Set(stop.keys)==Set(["version","op","nonce","pid"]),MigrationRuntimeConsoleManifest.integer(stop["version"])==1,stop["op"] as? String=="stop",stop["nonce"] as? String==request.nonce,MigrationRuntimeConsoleManifest.integer(stop["pid"])==Int(child) else{throw BrokerTransportError.untrustedPeer}
                let terminal=Self.reap(child,stop:true);reaped=terminal != nil
                guard let terminal else{throw BrokerTransportError.unavailable}
                try Self.finishReapedChild(fd,nonce:request.nonce,pid:child,status:terminal,authenticate:{try self.broker.authenticate(socket:fd)});return
            }
        } catch {return}
    }
    // Darwin's socket audit identity expires at peer EOF. Keep our endpoint
    // alive until the broker has verified this terminal receipt and acknowledged
    // it. The child is already reaped; failure cannot trigger another launch/kill.
    static func finishReapedChild(_ fd:Int32,nonce:String,pid:pid_t,status:Int32,authenticate:()throws->Void)throws {
        try authenticate()
        try writeFrame(fd,["version":1,"nonce":nonce,"state":"exited","pid":pid,"status":status])
        let deadline=Date().addingTimeInterval(5)
        func terminalMessage()throws->Data {
            let header=try readUntil(fd,4,deadline),count=header.reduce(0){($0<<8)|Int($1)}
            guard count>0,count<=512 else{throw BrokerTransportError.malformedFrame}
            return try readUntil(fd,count,deadline)
        }
        var payload=try terminalMessage()
        // Closing stdin may reap the child before the broker's stop reaches us.
        // Consume at most that one identity-bound stop without acting on the
        // already reaped PID. It is never an acknowledgement or exit proof.
        if (try? validateTerminalMessage(payload,nonce:nonce,pid:pid,operation:"stop")) != nil {
            payload=try terminalMessage()
        }
        try validateReapedAcknowledgment(payload,nonce:nonce,pid:pid)
        // No peer reauthentication here: the authenticated broker may close
        // immediately after sending its ACK, making LOCAL_PEERTOKEN unavailable.
    }
    static func validateReapedAcknowledgment(_ data:Data,nonce:String,pid:pid_t)throws {
        try validateTerminalMessage(data,nonce:nonce,pid:pid,operation:"reaped")
    }
    private static func validateTerminalMessage(_ data:Data,nonce:String,pid:pid_t,operation:String)throws {
        try MigrationReadinessJSON.validate(data)
        guard let value=try JSONSerialization.jsonObject(with:data) as? [String:Any],Set(value.keys)==Set(["version","op","nonce","pid"]),
              MigrationRuntimeConsoleManifest.integer(value["version"])==1,value["op"] as? String==operation,value["nonce"] as? String==nonce,
              MigrationRuntimeConsoleManifest.integer(value["pid"])==Int(pid) else{throw BrokerTransportError.malformedFrame}
    }
    private static func readUntil(_ fd:Int32,_ count:Int,_ deadline:Date)throws->Data {
        var data=Data(count:count),offset=0
        while offset<count {
            let remaining=deadline.timeIntervalSinceNow;guard remaining>0 else{throw BrokerTransportError.unavailable}
            var item=pollfd(fd:fd,events:Int16(POLLIN),revents:0)
            let ready=poll(&item,1,Int32(max(1,min(5000,ceil(remaining*1000)))))
            if ready<0 && errno==EINTR{continue}
            guard ready>0 else{throw BrokerTransportError.unavailable}
            let n=data.withUnsafeMutableBytes{recv(fd,$0.baseAddress!.advanced(by:offset),count-offset,MSG_DONTWAIT)}
            if n<0 && (errno==EINTR || errno==EAGAIN){continue}
            guard n>0 else{throw BrokerTransportError.unavailable};offset+=n
        }
        return data
    }
    private static func reap(_ child:pid_t,stop:Bool)->Int32? {
        var status:Int32=0;let deadline=Date().addingTimeInterval(0.3)
        repeat{let r=waitpid(child,&status,WNOHANG);if r==child{return status};if r<0{return nil};usleep(10000)}while Date()<deadline
        guard stop else{return nil};guard kill(child,SIGKILL)==0 || errno==ESRCH else{return nil}
        while true{let r=waitpid(child,&status,0);if r==child{return status};if r<0 && errno==EINTR{continue};return nil}
    }
    static func receiveRights(_ fd:Int32)throws->[Int32]{
        var marker:UInt8=0,control=[UInt8](repeating:0,count:256),message=msghdr();var descriptors:[Int32]=[]
        let count=withUnsafeMutablePointer(to:&marker){pointer in var vector=iovec(iov_base:pointer,iov_len:1)
            return withUnsafeMutablePointer(to:&vector){vector in control.withUnsafeMutableBytes{bytes in message.msg_iov=vector;message.msg_iovlen=1;message.msg_control=bytes.baseAddress;message.msg_controllen=socklen_t(bytes.count);return recvmsg(fd,&message,0)}}}
        let size=MemoryLayout<cmsghdr>.size
        var headers=0,offset=0
        control.withUnsafeBytes { raw in
            while offset+size<=Int(message.msg_controllen) {
                let header=raw.loadUnaligned(fromByteOffset:offset,as:cmsghdr.self),length=Int(header.cmsg_len)
                guard length>=size,offset+length<=Int(message.msg_controllen) else{break}
                headers+=1
                if header.cmsg_level==SOL_SOCKET && header.cmsg_type==SCM_RIGHTS {
                    for cursor in stride(from:offset+size,to:offset+length,by:4) where cursor+4<=offset+length {descriptors.append(raw.loadUnaligned(fromByteOffset:cursor,as:Int32.self))}
                }
                offset += (length+3) & ~3
            }
        }
        do {guard count==1,marker==1,message.msg_flags&(MSG_CTRUNC|MSG_TRUNC)==0,message.msg_controllen==size+20,descriptors.count==5,headers==1 else{throw BrokerTransportError.malformedFrame}
            for (index,value) in descriptors.enumerated(){var info=stat();guard value>=0,fcntl(value,F_SETFD,FD_CLOEXEC)==0,fstat(value,&info)==0 else{throw BrokerTransportError.malformedFrame};if [0,1,3].contains(index){let access=fcntl(value,F_GETFL)&O_ACCMODE;guard info.st_mode&S_IFMT==S_IFIFO,access==(index==1 ? O_WRONLY:O_RDONLY) else{throw BrokerTransportError.malformedFrame}}}
            return descriptors
        }catch{for value in descriptors{Darwin.close(value)};throw error}
    }
    static func duplicateLaunchDescriptors(_ values:[Int32])throws->[Int32] {
        guard values.count==5 else{throw BrokerTransportError.malformedFrame}
        var copied:[Int32]=[]
        do {for value in values {let descriptor=fcntl(value,F_DUPFD_CLOEXEC,10);guard descriptor>=10 else{throw BrokerTransportError.unavailable};copied.append(descriptor)};return copied}
        catch {for descriptor in copied{Darwin.close(descriptor)};throw error}
    }
    private static func spawn(_ helper:URL,_ r:ConsoleHelperLaunchRequest,_ fds:[Int32],_ brokerPID:pid_t)throws->pid_t {
        let safeDescriptors=try duplicateLaunchDescriptors(fds);defer{for descriptor in safeDescriptors{Darwin.close(descriptor)}}
        var actions:posix_spawn_file_actions_t?,attributes:posix_spawnattr_t?
        guard posix_spawn_file_actions_init(&actions)==0,posix_spawnattr_init(&attributes)==0 else{throw BrokerTransportError.unavailable}
        defer{posix_spawn_file_actions_destroy(&actions);posix_spawnattr_destroy(&attributes)}
        let null=Darwin.open("/dev/null",O_WRONLY|O_CLOEXEC);guard null>=0 else{throw BrokerTransportError.unavailable};defer{Darwin.close(null)}
        for (source,target) in zip(safeDescriptors,[0,1,3,4,5] as [Int32]){guard posix_spawn_file_actions_adddup2(&actions,source,target)==0 else{throw BrokerTransportError.unavailable}}
        guard posix_spawn_file_actions_adddup2(&actions,null,2)==0,posix_spawnattr_setflags(&attributes,Int16(POSIX_SPAWN_CLOEXEC_DEFAULT))==0 else{throw BrokerTransportError.unavailable}
        let arguments=[helper.path]+r.arguments+["--console-owned","--console-parent-requirement",r.consoleRequirement,"--console-broker-pid",String(brokerPID)]
        let environment=["MECHANIZE_IDENTITY_SOCKET="+r.identitySocket,"MECHANIZE_IDENTITY_NONCE="+r.identityNonce]
        let argv=arguments.map{strdup($0)}+[nil],env=environment.map{strdup($0)}+[nil];defer{for p in argv+env{free(p)}}
        var child:pid_t=0
        let status=argv.withUnsafeBufferPointer{a in env.withUnsafeBufferPointer{e in posix_spawn(&child,helper.path,&actions,&attributes,UnsafeMutablePointer(mutating:a.baseAddress!),UnsafeMutablePointer(mutating:e.baseAddress!))}}
        guard status==0,child>0 else{throw BrokerTransportError.unavailable};return child
    }
    private static func peerPID(_ fd:Int32)throws->pid_t {var pid:pid_t=0,size=socklen_t(MemoryLayout<pid_t>.size);guard getsockopt(fd,SOL_LOCAL,LOCAL_PEERPID,&pid,&size)==0,pid>1 else{throw BrokerTransportError.untrustedPeer};return pid}
    private static func ownSignature(_ pin:String)throws{var code:SecCode?,rule:SecRequirement?;guard SecCodeCopySelf([], &code)==errSecSuccess,SecRequirementCreateWithString(pin as CFString,[],&rule)==errSecSuccess,let code,let rule,SecCodeCheckValidity(code,SecCSFlags(rawValue:kSecCSStrictValidate),rule)==errSecSuccess else{throw BrokerTransportError.untrustedPeer}}
    private static func signature(_ path:URL,_ pin:String?)throws{var code:SecStaticCode?,rule:SecRequirement?;if let pin {guard SecRequirementCreateWithString(pin as CFString,[],&rule)==errSecSuccess else{throw BrokerTransportError.untrustedPeer}}
        var info=stat();guard lstat(path.path,&info)==0,info.st_mode&S_IFMT != S_IFLNK,info.st_uid==getuid(),info.st_mode&0o022==0,SecStaticCodeCreateWithPath(path as CFURL,[],&code)==errSecSuccess,let code,SecStaticCodeCheckValidity(code,SecCSFlags(rawValue:kSecCSStrictValidate|kSecCSCheckAllArchitectures),rule)==errSecSuccess else{throw BrokerTransportError.untrustedPeer}}
    private static func identityEndpoint(_ path:String)throws{var directory=stat(),entry=stat();guard lstat(URL(fileURLWithPath:path).deletingLastPathComponent().path,&directory)==0,directory.st_uid==getuid(),directory.st_mode&S_IFMT==S_IFDIR,directory.st_mode&0o077==0,lstat(path,&entry)==0,entry.st_uid==getuid(),entry.st_mode&S_IFMT==S_IFSOCK,entry.st_mode&0o077==0 else{throw BrokerTransportError.unsafeEndpoint}}
    private static func withAddress<T>(_ path:String,_ body:(UnsafePointer<sockaddr>,socklen_t)->T)->T {var address=sockaddr_un();address.sun_family=sa_family_t(AF_UNIX);address.sun_len=UInt8(MemoryLayout<sockaddr_un>.size);let bytes=Array(path.utf8)+[0];precondition(bytes.count<=MemoryLayout.size(ofValue:address.sun_path));withUnsafeMutableBytes(of:&address.sun_path){$0.copyBytes(from:bytes)};return withUnsafePointer(to:&address){$0.withMemoryRebound(to:sockaddr.self,capacity:1){body($0,socklen_t(MemoryLayout<sockaddr_un>.size))}}}
    private static func readFrame(_ fd:Int32)throws->Data{let header=try read(fd,4),count=header.reduce(0){($0<<8)|Int($1)};guard count>0,count<=32768 else{throw BrokerTransportError.malformedFrame};return try read(fd,count)}
    private static func read(_ fd:Int32,_ count:Int)throws->Data{var data=Data(count:count),offset=0;while offset<count {let n=data.withUnsafeMutableBytes{Darwin.read(fd,$0.baseAddress!.advanced(by:offset),count-offset)};guard n>0 else{throw BrokerTransportError.unavailable};offset+=n};return data}
    private static func writeFrame(_ fd:Int32,_ value:[String:Any])throws{let frame=try BrokerFrame.encode(JSONSerialization.data(withJSONObject:value,options:[.sortedKeys]));var offset=0;while offset<frame.count{let n=frame.withUnsafeBytes{Darwin.write(fd,$0.baseAddress!.advanced(by:offset),frame.count-offset)};guard n>0 else{throw BrokerTransportError.unavailable};offset+=n}}
}
