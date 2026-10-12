import XCTest
import Darwin
@testable import ConsentCore

final class ConsoleHelperLaunchTests: XCTestCase {
    let helper="identifier \"com.viant.mechanize.native\" and cdhash H\""+String(repeating:"a",count:40)+"\""
    let console="identifier \"com.viant.mechanize.consent\" and cdhash H\""+String(repeating:"b",count:40)+"\""
    func request(_ edit: (inout [String:Any])->Void = {_ in})throws->Data {
        var value:[String:Any]=["version":1,"op":"launch","nonce":String(repeating:"c",count:64),"arguments":[],"identitySocket":"/tmp/mechanize-identity-123/peer.sock","identityNonce":String(repeating:"d",count:64),"helperRequirement":helper,"consoleRequirement":console]
        edit(&value);return try JSONSerialization.data(withJSONObject:value)
    }
    func testClosedArgumentsPathsAndPinsRejectCallerLaunchAuthority() throws {
        XCTAssertNoThrow(try ConsoleHelperLaunchRequest(request(),helperPin:helper))
        for mode in ["extra","path","nonce","pin","self","args","profiles","duplicate","privateExtras","orphanAddition","boolVersion"] {
            let data=try request {v in switch mode {
            case "extra":v["executable"]="/bin/sh"
            case "path":v["identitySocket"]="/tmp/mechanize-identity-123/../other.sock"
            case "nonce":v["identityNonce"]="bad"
            case "pin":v["helperRequirement"]=self.console
            case "self":v["consoleRequirement"]="identifier \"com.viant.mechanize.consent\""
            case "args":v["arguments"]=["--console-owned"]
            case "profiles":v["arguments"]=["--allow-semantic","--allow-mutations"]
            case "duplicate":v["arguments"]=["--allow-semantic","--allow-semantic"]
            case "privateExtras":v["arguments"]=["--private-administration","--allow-session-text"]
            case "orphanAddition":v["arguments"]=["--allow-session-text"]
            default:v["version"]=true
            }}
            XCTAssertThrowsError(try ConsoleHelperLaunchRequest(data,helperPin:helper),mode)
        }
    }
    func testUnauthorizedPeerAndUntrustedSelfNeverReachHelperAdmission() throws {
        var checks:[String]=[]
        XCTAssertThrowsError(try ConsoleHelperLaunchAdmission.validate(request(),helperPin:helper,authenticate:{checks.append("peer");throw BrokerTransportError.untrustedPeer},verifySelf:{_ in checks.append("self")},verifyHelper:{checks.append("helper")}))
        XCTAssertEqual(checks,["peer"]);checks=[]
        XCTAssertThrowsError(try ConsoleHelperLaunchAdmission.validate(request(),helperPin:helper,authenticate:{checks.append("peer")},verifySelf:{_ in checks.append("self");throw BrokerTransportError.untrustedPeer},verifyHelper:{checks.append("helper")}))
        XCTAssertEqual(checks,["peer","self"]);checks=[]
        _=try ConsoleHelperLaunchAdmission.validate(request(),helperPin:helper,authenticate:{checks.append("peer")},verifySelf:{pin in XCTAssertEqual(pin,self.console);checks.append("self")},verifyHelper:{checks.append("helper")})
        XCTAssertEqual(checks,["peer","self","helper","peer"])
    }
    func testRuntimeEndpointRequiresOwnedPrivateDirectoryWithoutSymlinks() throws {
        let home=FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer{try? FileManager.default.removeItem(at:home)}
        let runtime=home.appendingPathComponent("Library/Application Support/Mechanize/runtime")
        try FileManager.default.createDirectory(at:runtime,withIntermediateDirectories:true,attributes:[.posixPermissions:0o700])
        XCTAssertNoThrow(try ConsoleHelperLaunchService.validateDirectory(home:home.path,directory:runtime.path))
        XCTAssertThrowsError(try ConsoleHelperLaunchService.validateDirectory(home:home.path,directory:runtime.path+"-other"))
        try FileManager.default.setAttributes([.posixPermissions:0o755],ofItemAtPath:runtime.path)
        XCTAssertThrowsError(try ConsoleHelperLaunchService.validateDirectory(home:home.path,directory:runtime.path))
    }
    func testSpawnSourcesAreDuplicatedAboveEveryTargetWithoutClobbering() throws {
        let fd=Darwin.open("/dev/null",O_RDWR);defer{Darwin.close(fd)}
        let copied=try ConsoleHelperLaunchService.duplicateLaunchDescriptors([fd,fd,fd,fd,fd]);defer{for value in copied{Darwin.close(value)}}
        XCTAssertEqual(Set(copied).count,5);XCTAssertTrue(copied.allSatisfy{$0>=10})
        var original=stat();XCTAssertEqual(fstat(fd,&original),0)
        for value in copied{var info=stat();XCTAssertEqual(fstat(value,&info),0);XCTAssertEqual(info.st_ino,original.st_ino);XCTAssertEqual(fcntl(value,F_GETFD)&FD_CLOEXEC,FD_CLOEXEC)}
        XCTAssertThrowsError(try ConsoleHelperLaunchService.duplicateLaunchDescriptors([fd,fd,-1,fd,fd]))
    }
    func testRightsTransportRequiresExactlyFiveAndCorrectStdioDirections() throws {
        for count in [5,6] {
            var pair=[Int32](repeating:0,count:2);XCTAssertEqual(socketpair(AF_UNIX,SOCK_STREAM,0,&pair),0)
            defer{Darwin.close(pair[0]);Darwin.close(pair[1])}
            var input=[Int32](repeating:0,count:2),output=[Int32](repeating:0,count:2),watch=[Int32](repeating:0,count:2)
            XCTAssertEqual(pipe(&input),0);XCTAssertEqual(pipe(&output),0);XCTAssertEqual(pipe(&watch),0)
            let null=Darwin.open("/dev/null",O_RDWR);defer{for fd in input+output+watch+[null]{Darwin.close(fd)}}
            var fds=[input[0],output[1],null,watch[0],null];if count==6{fds.append(null)}
            var marker:UInt8=1,control=[UInt8](repeating:0,count:MemoryLayout<cmsghdr>.size+fds.count*4),message=msghdr()
            control.withUnsafeMutableBytes{raw in var header=cmsghdr();header.cmsg_len=socklen_t(raw.count);header.cmsg_level=SOL_SOCKET;header.cmsg_type=SCM_RIGHTS;raw.storeBytes(of:header,as:cmsghdr.self);for (i,fd) in fds.enumerated(){raw.storeBytes(of:fd,toByteOffset:MemoryLayout<cmsghdr>.size+i*4,as:Int32.self)}}
            let sent=withUnsafeMutablePointer(to:&marker){m in var vector=iovec(iov_base:m,iov_len:1);return withUnsafeMutablePointer(to:&vector){v in control.withUnsafeMutableBytes{c in message.msg_iov=v;message.msg_iovlen=1;message.msg_control=c.baseAddress;message.msg_controllen=socklen_t(c.count);return sendmsg(pair[0],&message,0)}}}
            XCTAssertEqual(sent,1)
            if count==5{let received=try ConsoleHelperLaunchService.receiveRights(pair[1]);XCTAssertEqual(received.count,5);for fd in received{Darwin.close(fd)}}
            else{XCTAssertThrowsError(try ConsoleHelperLaunchService.receiveRights(pair[1]))}
        }
    }
}

private final class TerminalReceiptState: @unchecked Sendable {
    let lock=NSLock()
    var failed=false
    var authentications=0
}
extension ConsoleHelperLaunchTests {
    func testReapedAckRejectsWrongIdentityUnknownKeysAndDuplicateFields() throws {
        let nonce=String(repeating:"a",count:64)
        let valid:[String:Any]=["version":1,"op":"reaped","nonce":nonce,"pid":42]
        XCTAssertNoThrow(try ConsoleHelperLaunchService.validateReapedAcknowledgment(JSONSerialization.data(withJSONObject:valid),nonce:nonce,pid:42))
        for mode in ["nonce","pid","op","version","extra"] {
            var value=valid
            switch mode {case "nonce":value["nonce"]=String(repeating:"b",count:64);case "pid":value["pid"]=43;case "op":value["op"]="stop";case "version":value["version"]=true;default:value["replay"]=true}
            XCTAssertThrowsError(try ConsoleHelperLaunchService.validateReapedAcknowledgment(JSONSerialization.data(withJSONObject:value),nonce:nonce,pid:42))
        }
        let duplicate=Data(("{\"version\":1,\"op\":\"reaped\",\"nonce\":\""+nonce+"\",\"pid\":42,\"pid\":42}").utf8)
        XCTAssertThrowsError(try ConsoleHelperLaunchService.validateReapedAcknowledgment(duplicate,nonce:nonce,pid:42))
    }
    func testTerminalSocketStaysAliveUntilAckAndNeverAuthenticatesAfterAck() throws {
        try terminalFixture(sendAck:true)
    }
    func testTerminalEOFFailsWithoutReauthOrProcessAction() throws {
        try terminalFixture(sendAck:false)
    }
    func testNaturalExitAcceptsOneIdentityBoundStopAlreadyInFlightBeforeAck() throws {
        try terminalFixture(sendAck:true,inFlightStops:1)
    }
    func testNaturalExitRejectsRepeatedStopInsteadOfTerminalAck() throws {
        try terminalFixture(sendAck:true,inFlightStops:2,expectedFailure:true)
    }
    func testInFlightStopCannotReplaceAckOrChangeTerminalIdentity() throws {
        try terminalFixture(sendAck:false,inFlightStops:1)
        for field in ["nonce","pid","version","extra"] {
            var stop:[String:Any]=["version":1,"op":"stop","nonce":String(repeating:"a",count:64),"pid":42]
            switch field {case "nonce":stop[field]=String(repeating:"b",count:64);case "pid":stop[field]=43;case "version":stop[field]=true;default:stop[field]=true}
            try terminalFixture(sendAck:true,inFlightStops:1,expectedFailure:true,stopOverride:stop)
        }
    }
    private func terminalFixture(sendAck:Bool,inFlightStops:Int=0,expectedFailure:Bool=false,stopOverride:[String:Any]?=nil)throws {
        var pair=[Int32](repeating:0,count:2);XCTAssertEqual(socketpair(AF_UNIX,SOCK_STREAM,0,&pair),0)
        let server=pair[0],client=pair[1],state=TerminalReceiptState(),done=DispatchSemaphore(value:0),nonce=String(repeating:"a",count:64)
        var one:Int32=1;_ = setsockopt(client,SOL_SOCKET,SO_NOSIGPIPE,&one,4);_ = setsockopt(server,SOL_SOCKET,SO_NOSIGPIPE,&one,4)
        DispatchQueue.global().async {
            defer{Darwin.close(server);done.signal()}
            do {try ConsoleHelperLaunchService.finishReapedChild(server,nonce:nonce,pid:42,status:0,authenticate:{state.lock.lock();state.authentications+=1;state.lock.unlock()})}
            catch {state.lock.lock();state.failed=true;state.lock.unlock()}
        }
        func readExact(_ count:Int)throws->Data {
            var data=Data(count:count),offset=0
            while offset<count {let n=data.withUnsafeMutableBytes{Darwin.read(client,$0.baseAddress!.advanced(by:offset),count-offset)};guard n>0 else{throw BrokerTransportError.unavailable};offset+=n};return data
        }
        let header=try readExact(4),length=header.reduce(0){($0<<8)|Int($1)},body=try readExact(length)
        let receipt=try JSONSerialization.jsonObject(with:body) as! [String:Any]
        XCTAssertEqual(receipt["state"] as? String,"exited");XCTAssertEqual(receipt["pid"] as? Int,42)
        XCTAssertEqual(done.wait(timeout:.now()+0.05),.timedOut)
        var byte:UInt8=0;XCTAssertEqual(recv(client,&byte,1,MSG_PEEK|MSG_DONTWAIT),-1);XCTAssertEqual(errno,EAGAIN)
        var frames=Data()
        for _ in 0..<inFlightStops {
            let raw=try JSONSerialization.data(withJSONObject:stopOverride ?? ["version":1,"op":"stop","nonce":nonce,"pid":42])
            frames.append(try BrokerFrame.encode(raw))
        }
        if sendAck {
            let raw=try JSONSerialization.data(withJSONObject:["version":1,"op":"reaped","nonce":nonce,"pid":42])
            frames.append(try BrokerFrame.encode(raw))
        }
        if !frames.isEmpty {let count=frames.withUnsafeBytes{Darwin.write(client,$0.baseAddress,frames.count)};XCTAssertEqual(count,frames.count)}
        // Close immediately: a post-ACK peer-token query would race this EOF.
        Darwin.close(client)
        XCTAssertEqual(done.wait(timeout:.now()+2),.success)
        state.lock.lock();let failed=state.failed,authentications=state.authentications;state.lock.unlock()
        XCTAssertEqual(authentications,1);XCTAssertEqual(failed,expectedFailure || !sendAck)
    }
}
