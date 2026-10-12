import Foundation
import Darwin
import Security

/// Frozen by the signed upgrade enrollment. This is a distinct desktop-read
/// credential resource; the native-human console enrollment is never accepted.
public struct MigrationObserverConsentBinding {
    let sessionID: String, purpose: String
    let grantID: String?
    public init(sessionID: String, purpose: String, grantID: String? = nil) throws {
        for value in [sessionID, purpose] + (grantID.map { [$0] } ?? []) {
            guard !value.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty, value.utf8.count <= 1024,
                  !value.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) else { throw MigrationConsoleError.unavailable }
        }
        self.sessionID = sessionID; self.purpose = purpose; self.grantID = grantID
    }
    init(_ raw: Any?) throws {
        guard let fields = raw as? [String: Any], Set(fields.keys) == Set(["sessionID", "purpose"] + (fields["grantID"] == nil ? [] : ["grantID"])),
              let session = fields["sessionID"] as? String, let purpose = fields["purpose"] as? String,
              fields["grantID"] == nil || fields["grantID"] is String else { throw MigrationConsoleError.unavailable }
        try self.init(sessionID: session, purpose: purpose, grantID: fields["grantID"] as? String)
    }
    var arguments: [String: Any] {
        var result: [String: Any] = ["sessionId": sessionID, "purpose": purpose]
        if let grantID { result["grantId"] = grantID }; return result
    }
}

public struct MigrationObserverReaderEnrollment {
    let consentBinding: MigrationObserverConsentBinding
    let port: UInt16
    let brokerPID: Int32
    let brokerStart: String
    let brokerRequirement: String
    let credentialURL: URL
    let credentialSHA256: String
    public init(port: UInt16, brokerPID: Int32, brokerStart: String, brokerRequirement: String,
                credentialURL: URL, credentialSHA256: String, consentBinding: MigrationObserverConsentBinding) throws {
        guard port > 0, brokerPID > 0, MigrationExactBrokerPeer.validStart(brokerStart),
              MigrationAuthorizationRecord.requirement(brokerRequirement,role:"broker"),
              credentialURL.isFileURL, credentialURL.path.hasPrefix("/"),
              !credentialURL.pathComponents.contains(".."), MigrationAuthorizationRecord.digest(credentialSHA256) else { throw MigrationConsoleError.unavailable }
        self.consentBinding=consentBinding
        self.port=port;self.brokerPID=brokerPID;self.brokerStart=brokerStart;self.brokerRequirement=brokerRequirement
        self.credentialURL=credentialURL;self.credentialSHA256=credentialSHA256
    }
}

/// Narrow HTTP reader: fixed numeric loopback, fixed /mcp, exactly
/// mechanize_observe with a native PID/birth and exact window scope. No input,
/// arbitrary tools, redirects, proxies, process spawning or credential output.
enum MigrationObserverReadPhase: String {
    case validation, listener, connection, peer, credential, send, receive, peerRecheck, decode
}

final class MigrationObserverMCPReader {
    private let enrollment: MigrationObserverReaderEnrollment
    init(_ enrollment: MigrationObserverReaderEnrollment) { self.enrollment=enrollment }
    func observe(chromePID:Int32, chromeStart:String, windowTitle:String, deadline:Date) throws -> Data {
        try observe(chromePID:chromePID,chromeStart:chromeStart,windowTitle:windowTitle,deadline:deadline,onPhase:nil)
    }
    // Closed local progress only; never carries request/response or credential bytes.
    func observe(chromePID:Int32, chromeStart:String, windowTitle:String, deadline:Date,
                 onPhase:((MigrationObserverReadPhase)->Void)?) throws -> Data {
        onPhase?(.validation)
        guard chromePID>0, MigrationExactBrokerPeer.validStart(chromeStart), !windowTitle.isEmpty,
              windowTitle.utf8.count<=1024, deadline>Date(), deadline.timeIntervalSinceNow<=30 else { throw MigrationConsoleError.unavailable }
        onPhase?(.listener)
        let listener=try listenerIdentity()
        onPhase?(.connection)
        let fd=socket(AF_INET,SOCK_STREAM,0);guard fd>=0 else {throw MigrationConsoleError.unavailable}
        defer{Darwin.close(fd)}
        var one:Int32=1;guard setsockopt(fd,SOL_SOCKET,SO_NOSIGPIPE,&one,socklen_t(MemoryLayout<Int32>.size))==0,
              fcntl(fd,F_SETFL,O_NONBLOCK)==0 else {throw MigrationConsoleError.unavailable}
        var address=sockaddr_in();address.sin_len=UInt8(MemoryLayout<sockaddr_in>.size);address.sin_family=sa_family_t(AF_INET)
        address.sin_port=enrollment.port.bigEndian;address.sin_addr.s_addr=inet_addr("127.0.0.1")
        let connected=withUnsafePointer(to:&address){$0.withMemoryRebound(to:sockaddr.self,capacity:1){Darwin.connect(fd,$0,socklen_t(MemoryLayout<sockaddr_in>.size))}}
        guard connected==0 || errno==EINPROGRESS else {throw MigrationConsoleError.unavailable}
        try Self.wait(fd,Int16(POLLOUT),deadline)
        var socketError:Int32=0,size=socklen_t(MemoryLayout<Int32>.size)
        guard getsockopt(fd,SOL_SOCKET,SO_ERROR,&socketError,&size)==0,socketError==0 else {throw MigrationConsoleError.unavailable}
        var local=sockaddr_in();var localSize=socklen_t(MemoryLayout<sockaddr_in>.size)
        guard withUnsafeMutablePointer(to:&local,{$0.withMemoryRebound(to:sockaddr.self,capacity:1){getsockname(fd,$0,&localSize)}})==0 else {throw MigrationConsoleError.unavailable}
        // Go's accept loop may not yet expose the connected descriptor. Only
        // kernel reads repeat; no HTTP bytes or credentials have been emitted.
        onPhase?(.peer)
        let acceptDeadline=min(deadline,Date().addingTimeInterval(1))
        var peer: SocketIdentity?
        while Date()<acceptDeadline {
            peer=try sockets().first{ $0.state==TSI_S_ESTABLISHED && $0.localPort==enrollment.port && $0.remotePort==UInt16(bigEndian:local.sin_port) && $0.loopbackPair }
            if peer != nil {break};usleep(1000)
        }
        guard let peer,try listenerIdentity()==listener else {throw MigrationConsoleError.unavailable}
        onPhase?(.credential)
        var token=try credential();defer{token.resetBytes(in:0..<token.count)}
        guard try listenerIdentity()==listener,try sockets().contains(peer) else {throw MigrationConsoleError.unavailable}
        let id=UUID().uuidString
        var arguments = enrollment.consentBinding.arguments
        arguments["surface"] = ["kind":"native","bundleId":"com.google.Chrome","processId":chromePID,"processStartToken":chromeStart]
        arguments["windowScope"] = ["title":windowTitle,"role":"AXWindow"]
        let body=try JSONSerialization.data(withJSONObject:["jsonrpc":"2.0","id":id,"method":"tools/call","params":["name":"mechanize_observe","arguments":arguments,"_meta":["io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":[:]]]])
        var request=Data("POST /mcp HTTP/1.1\r\nHost: 127.0.0.1:\(enrollment.port)\r\nConnection: close\r\nContent-Type: application/json\r\nAccept: application/json, text/event-stream\r\nMcp-Protocol-Version: 2026-07-28\r\nMcp-Method: tools/call\r\nMcp-Name: mechanize_observe\r\nAuthorization: Bearer ".utf8)
        request.append(token);request.append(Data("\r\nContent-Length: \(body.count)\r\n\r\n".utf8));request.append(body)
        defer{request.resetBytes(in:0..<request.count)}
        onPhase?(.send)
        var offset=0
        while offset<request.count {try Self.wait(fd,Int16(POLLOUT),deadline);let n=request.withUnsafeBytes{Darwin.send(fd,$0.baseAddress!.advanced(by:offset),request.count-offset,0)};guard n>0 else {throw MigrationConsoleError.unavailable};offset+=n}
        onPhase?(.receive)
        var response=Data(), buffer=[UInt8](repeating:0,count:8192)
        while true {try Self.wait(fd,Int16(POLLIN),deadline);let n=Darwin.recv(fd,&buffer,buffer.count,0);if n==0{break};guard n>0,response.count+n<=4*1024*1024 else {throw MigrationConsoleError.unavailable};response.append(contentsOf:buffer.prefix(n))}
        onPhase?(.peerRecheck)
        guard try listenerIdentity()==listener else {throw MigrationConsoleError.unavailable}
        onPhase?(.decode)
        return try Self.response(response,id:id)
    }
    private static func wait(_ fd:Int32,_ events:Int16,_ deadline:Date)throws {
        let remaining=deadline.timeIntervalSinceNow;guard remaining>0 else{throw MigrationConsoleError.unavailable}
        var item=pollfd(fd:fd,events:events,revents:0)
        guard poll(&item,1,Int32(min(30000,ceil(remaining*1000))))>0,item.revents & (events|Int16(POLLHUP)) != 0 else {throw MigrationConsoleError.unavailable}
    }
    private func credential()throws->Data {
        // Scy local unencrypted file-resource subset only. No inline, fallback,
        // environment or native-human credential lookup is supported.
        let components=enrollment.credentialURL.path.split(separator:"/")
        var parent=Darwin.open("/",O_RDONLY|O_DIRECTORY|O_CLOEXEC);guard parent>=0 else{throw MigrationConsoleError.unavailable}
        defer{Darwin.close(parent)}
        for component in components.dropLast(){
            guard component != ".",component != ".." else{throw MigrationConsoleError.unavailable}
            let next=openat(parent,String(component),O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);guard next>=0 else{throw MigrationConsoleError.unavailable};Darwin.close(parent);parent=next
        }
        var directory=stat();guard fstat(parent,&directory)==0,directory.st_uid==getuid(),directory.st_mode&0o077==0,
              let name=components.last else{throw MigrationConsoleError.unavailable}
        let fd=openat(parent,String(name),O_RDONLY|O_NOFOLLOW|O_CLOEXEC);guard fd>=0 else{throw MigrationConsoleError.unavailable};defer{Darwin.close(fd)}
        var before=stat();guard fstat(fd,&before)==0,before.st_uid==getuid(),before.st_mode&S_IFMT==S_IFREG,before.st_mode&0o077==0,before.st_nlink==1,before.st_size>0,before.st_size<=32768 else{throw MigrationConsoleError.unavailable}
        var bytes=Data(count:Int(before.st_size));let count=bytes.withUnsafeMutableBytes{Darwin.read(fd,$0.baseAddress,$0.count)}
        var after=stat();guard count==bytes.count,fstat(fd,&after)==0,before.st_size==after.st_size,before.st_mtimespec.tv_sec==after.st_mtimespec.tv_sec,before.st_mtimespec.tv_nsec==after.st_mtimespec.tv_nsec,before.st_ctimespec.tv_sec==after.st_ctimespec.tv_sec,before.st_ctimespec.tv_nsec==after.st_ctimespec.tv_nsec,
              MigrationUpgradeIntent.digest(bytes)==enrollment.credentialSHA256 else{bytes.resetBytes(in:0..<bytes.count);throw MigrationConsoleError.unavailable}
        while bytes.last==10 || bytes.last==13 {bytes.removeLast()}
        guard !bytes.isEmpty,bytes.allSatisfy({$0>=33 && $0<=126}) else{bytes.resetBytes(in:0..<bytes.count);throw MigrationConsoleError.unavailable}
        return bytes
    }
    struct SocketIdentity:Equatable {let fd:Int32;let socket:UInt64;let generation:UInt64;let state:Int32;let localPort:UInt16;let remotePort:UInt16;let loopbackPair:Bool}
    private func process()throws {
        var info=proc_bsdinfo()
        guard proc_pidinfo(enrollment.brokerPID,PROC_PIDTBSDINFO,0,&info,Int32(MemoryLayout<proc_bsdinfo>.size))==MemoryLayout<proc_bsdinfo>.size,
              info.pbi_uid==getuid(),info.pbi_status != 5,"\(info.pbi_start_tvsec):\(info.pbi_start_tvusec)"==enrollment.brokerStart else{throw MigrationConsoleError.unavailable}
        var requirement:SecRequirement?,code:SecCode?
        guard SecRequirementCreateWithString(enrollment.brokerRequirement as CFString,[],&requirement)==errSecSuccess,let requirement,
              SecCodeCopyGuestWithAttributes(nil,[kSecGuestAttributePid:enrollment.brokerPID] as CFDictionary,[],&code)==errSecSuccess,let code,
              SecCodeCheckValidity(code,SecCSFlags(rawValue:kSecCSStrictValidate),requirement)==errSecSuccess else{throw MigrationConsoleError.unavailable}
    }
    private func sockets()throws->[SocketIdentity] {
        try process()
        let needed=proc_pidinfo(enrollment.brokerPID,PROC_PIDLISTFDS,0,nil,0)
        guard needed>0,needed<=1024*1024 else{throw MigrationConsoleError.unavailable}
        var fds=[proc_fdinfo](repeating:proc_fdinfo(),count:Int(needed)/MemoryLayout<proc_fdinfo>.size+32)
        let capacity=fds.count*MemoryLayout<proc_fdinfo>.size
        let count=fds.withUnsafeMutableBytes{proc_pidinfo(enrollment.brokerPID,PROC_PIDLISTFDS,0,$0.baseAddress,Int32($0.count))}
        guard count>0,count<capacity,Int(count)%MemoryLayout<proc_fdinfo>.size==0 else{throw MigrationConsoleError.unavailable}
        var result:[SocketIdentity]=[]
        for entry in fds.prefix(Int(count)/MemoryLayout<proc_fdinfo>.size) where entry.proc_fdtype==PROX_FDTYPE_SOCKET {
            var value=socket_fdinfo()
            guard proc_pidfdinfo(enrollment.brokerPID,entry.proc_fd,PROC_PIDFDSOCKETINFO,&value,Int32(MemoryLayout<socket_fdinfo>.size))==MemoryLayout<socket_fdinfo>.size else{throw MigrationConsoleError.unavailable}
            let socket=value.psi;guard socket.soi_family==AF_INET,socket.soi_kind==SOCKINFO_TCP else{continue}
            let tcp=socket.soi_proto.pri_tcp,ip=tcp.tcpsi_ini
            let loopback=ip.insi_laddr.ina_46.i46a_addr4.s_addr==inet_addr("127.0.0.1")
            guard loopback else{continue}
            result.append(SocketIdentity(fd:entry.proc_fd,socket:socket.soi_so,generation:ip.insi_gencnt,state:tcp.tcpsi_state,localPort:UInt16(bigEndian:UInt16(truncatingIfNeeded:ip.insi_lport)),remotePort:UInt16(bigEndian:UInt16(truncatingIfNeeded:ip.insi_fport)),loopbackPair:ip.insi_faddr.ina_46.i46a_addr4.s_addr==inet_addr("127.0.0.1")))
        }
        try process();return result
    }
    private func listenerIdentity()throws->SocketIdentity {
        let matches=try sockets().filter{$0.state==TSI_S_LISTEN && $0.localPort==enrollment.port}
        guard matches.count==1 else{throw MigrationConsoleError.unavailable};return matches[0]
    }
    static func response(_ raw:Data,id:String)throws->Data {
        guard let separator=raw.range(of:Data("\r\n\r\n".utf8)),separator.lowerBound<=16384,
              let header=String(data:raw[..<separator.lowerBound],encoding:.utf8) else{throw MigrationConsoleError.unavailable}
        let lines=header.components(separatedBy:"\r\n")
        guard lines.first=="HTTP/1.1 200 OK" else{throw MigrationConsoleError.unavailable}
        var headers:[String:String]=[:]
        for line in lines.dropFirst(){guard let colon=line.firstIndex(of:":") else{throw MigrationConsoleError.unavailable};let key=line[..<colon].lowercased();guard headers[key]==nil else{throw MigrationConsoleError.unavailable};headers[key]=line[line.index(after:colon)...].trimmingCharacters(in:.whitespaces)}
        var body=Data(raw[separator.upperBound...])
        if headers["transfer-encoding"]=="chunked" {
            guard headers["content-length"]==nil else{throw MigrationConsoleError.unavailable}
            var decoded=Data()
            while true {
                guard let end=body.range(of:Data("\r\n".utf8)),end.lowerBound<=16,let line=String(data:body[..<end.lowerBound],encoding:.utf8),let length=Int(line,radix:16),length>=0,length<=4*1024*1024 else{throw MigrationConsoleError.unavailable}
                body=Data(body[end.upperBound...]);guard body.count>=length+2,body[length..<length+2]==Data("\r\n".utf8) else{throw MigrationConsoleError.unavailable}
                decoded.append(body.prefix(length));body=Data(body.dropFirst(length+2));if length==0{guard body.isEmpty else{throw MigrationConsoleError.unavailable};break}
            };body=decoded
        } else {guard headers["transfer-encoding"]==nil,let length=headers["content-length"].flatMap(Int.init),length==body.count else{throw MigrationConsoleError.unavailable}}
        let packets:[Data]
        if headers["content-type"]?.hasPrefix("text/event-stream")==true {
            guard let text=String(data:body,encoding:.utf8) else{throw MigrationConsoleError.unavailable}
            packets=text.components(separatedBy:"\n").filter{$0.hasPrefix("data:")}.map{Data($0.dropFirst(5).trimmingCharacters(in:.whitespacesAndNewlines).utf8)}
        } else {guard headers["content-type"]?.hasPrefix("application/json")==true else{throw MigrationConsoleError.unavailable};packets=[body]}
        guard packets.count==1,let packet=packets.first,let root=try JSONSerialization.jsonObject(with:packet) as? [String:Any],root["jsonrpc"] as? String=="2.0",root["id"] as? String==id,root["error"]==nil,
              let result=root["result"] as? [String:Any],result["isError"] as? Bool != true,let observation=result["structuredContent"] as? [String:Any] else{throw MigrationConsoleError.unavailable}
        return try JSONSerialization.data(withJSONObject:observation,options:.sortedKeys)
    }
}
