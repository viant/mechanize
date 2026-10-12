import XCTest
import Darwin
import CryptoKit
@testable import ConsentCore

final class MigrationWorkerLauncherTests: XCTestCase {
    func hex(_ value: String, _ count: Int = 64) -> String { String(repeating: value, count: count) }
    func requirement(_ role: String, _ value: String) -> String { "identifier \"com.viant.mechanize.\(role)\" and cdhash H\"\(hex(value,40))\"" }
    func bootstrap(reconciliation: Bool = false) throws -> MigrationWorkerBootstrap {
        try MigrationWorkerBootstrap(session: hex("a"), configSHA256: hex("b"), canonicalExecutable: "/private/fixture/mechanize", oldRequirement: requirement("broker","1"), newRequirement: requirement("broker","2"), alias: "vault-master", service: "com.viant.mechanize.vault", account: "fixture", workerRequirement: requirement("custody-migration","3"), expectedIdentity: reconciliation ? Data("reference".utf8) : nil)
    }
    func fixture() throws -> (MigrationWorkerSession, Int32, Int32) {
        var input:[Int32]=[-1,-1]; var output:[Int32]=[-1,-1]
        guard pipe(&input)==0, pipe(&output)==0 else {throw MigrationConsoleError.unavailable}
        let session = MigrationWorkerSession(child: 0, input: input[1], output: output[0], cancellationSocket: -1, deadline: Date().addingTimeInterval(2))
        addTeardownBlock { session.cancel(); Darwin.close(input[0]); Darwin.close(output[1]) }
        return (session,input[0],output[1])
    }
    func readExactly(_ fd:Int32,_ count:Int) -> Data {
        var data=Data(count:count); var offset=0
        data.withUnsafeMutableBytes { raw in
            while offset<count { let n=Darwin.read(fd,raw.baseAddress!.advanced(by:offset),count-offset); if n<=0 {break};offset+=n }
        }
        return data.prefix(offset)
    }
    func frame(_ fd:Int32) -> Data { let prefix=readExactly(fd,4); let n=prefix.reduce(0){($0<<8)|Int($1)};return readExactly(fd,n) }
    func send(_ fd:Int32,_ payload:Data) {var n=UInt32(payload.count).bigEndian;var data=Data();withUnsafeBytes(of:&n){data.append(contentsOf:$0)};data.append(payload);_ = data.withUnsafeBytes{Darwin.write(fd,$0.baseAddress,$0.count)}}
    func reply(_ status:String,id:String,identity:String? = nil) throws -> Data {
        var value:[String:Any] = ["version":1,"id":id,"session":hex("a"),"status":status]
        if let identity {value["identity"]=identity}
        return try MigrationWorkerSession.canonical(value,order:["version","id","session","status","identity"])
    }
    func testCanonicalProtocolPreservesGoFieldOrderAndEscaping() throws {
        let data = try MigrationWorkerSession.canonical(["version":1,"id":"<&>","session":"s","op":"prepare"],order:["version","id","session","op"])
        XCTAssertEqual(String(data:data,encoding:.utf8),#"{"version":1,"id":"\u003c\u0026\u003e","session":"s","op":"prepare"}"#)
        let (session,input,_) = try fixture();try session.bootstrap(bootstrap())
        let wire=frame(input)
        XCTAssertTrue(String(data:wire,encoding:.utf8)!.hasPrefix("{\"version\":1,\"op\":\"bootstrap\",\"session\":"))
        XCTAssertThrowsError(try session.bootstrap(bootstrap()))
    }
    func testPhasesAndUnknownCommitNeverReplay() throws {
        let (session,input,output)=try fixture();try session.bootstrap(bootstrap());_ = frame(input)
        XCTAssertThrowsError(try session.exchange(.commit,requestID:hex("c")))
        send(output,try reply("prepared",id:hex("1"),identity:Data("reference".utf8).base64EncodedString()))
        XCTAssertEqual(try session.exchange(.prepare,requestID:hex("1")).status,"prepared");_ = frame(input)
        send(output,try reply("checked",id:hex("2")))
        XCTAssertEqual(try session.exchange(.verify,requestID:hex("2")).status,"checked");_ = frame(input)
        send(output,try reply("unknown",id:hex("3")))
        XCTAssertEqual(try session.exchange(.commit,requestID:hex("3")).status,"unknown");_ = frame(input)
        XCTAssertTrue(session.commitMayHaveDispatched)
        XCTAssertThrowsError(try session.exchange(.commit,requestID:hex("4")))
        send(output,try reply("verified",id:hex("5")))
        XCTAssertEqual(try session.exchange(.inspect,requestID:hex("5")).status,"verified")
        XCTAssertThrowsError(try session.exchange(.inspect,requestID:hex("5")))
    }
    func testReconciliationAndMalformedReplyCannotMutateOrRetry() throws {
        let (session,input,output)=try fixture();try session.bootstrap(bootstrap(reconciliation:true));_ = frame(input)
        XCTAssertThrowsError(try session.exchange(.prepare,requestID:hex("1")))
        send(output,Data("{\"version\":1,\"version\":1}".utf8))
        XCTAssertThrowsError(try session.exchange(.inspect,requestID:hex("2")))
        XCTAssertThrowsError(try session.exchange(.inspect,requestID:hex("3")))
    }
    func testSyntheticChildHasExactKernelPeerAndFailureStopsItBeforeCredentials() throws {
        let folder=FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at:folder,withIntermediateDirectories:false,attributes:[.posixPermissions:0o700])
        defer {try? FileManager.default.removeItem(at:folder)}
        let helper=folder.appendingPathComponent("synthetic-worker")
        let source = folder.appendingPathComponent("fixture.c")
        try Data("#include <sys/socket.h>\n#include <sys/un.h>\n#include <unistd.h>\nint main(void) { int p=0; socklen_t n=sizeof(p); getsockopt(3,SOL_LOCAL,LOCAL_PEERPID,&p,&n); char peek; recv(3,&peek,1,MSG_PEEK|MSG_DONTWAIT); if(write(4,\"MMREADY1\",8)!=8)return 2; close(4); char b[64]; while(read(0,b,sizeof(b))>0){} return 0; }\n".utf8).write(to:source)
        let compiler = Process(); compiler.executableURL = URL(fileURLWithPath:"/usr/bin/clang"); compiler.arguments = [source.path,"-o",helper.path]; compiler.standardError = FileHandle.nullDevice
        try compiler.run(); compiler.waitUntilExit(); XCTAssertEqual(compiler.terminationStatus,0)
        try FileManager.default.setAttributes([.posixPermissions:0o700],ofItemAtPath:helper.path)
        var calls=0;var peer:pid_t=0
        XCTAssertThrowsError(try MigrationWorkerLauncher.launchPrivate(executable:helper.path,deadline:Date().addingTimeInterval(2),revalidate:{},connect:{socket in
            calls+=1;var size=socklen_t(MemoryLayout<pid_t>.size)
            XCTAssertEqual(getsockopt(socket,SOL_LOCAL,LOCAL_PEERPID,&peer,&size),0)
            Darwin.close(socket);throw MigrationConsoleError.unavailable
        }))
        XCTAssertEqual(calls,1);XCTAssertGreaterThan(peer,0)
        guard peer > 0 else { return }
        let until=Date().addingTimeInterval(2)
        while kill(peer,0)==0 && Date()<until {usleep(1000)}
        XCTAssertEqual(kill(peer,0),-1)
    }
    func testProcessExitDoesNotDiscardBufferedTerminalReceipt() throws {
        let (session,input,output)=try fixture();try session.bootstrap(bootstrap());_ = frame(input)
        send(output,try reply("closed",id:hex("1")))
        session.reapExited()
        session.attestationFailed()
        XCTAssertEqual(try session.exchange(.close,requestID:hex("1")).status,"closed")
    }
    func testReadinessRequiresExactMarkerAndEOF() throws {
        for text in ["MMREADY1", "MMREADY1x", "wrong", ""] {
            var descriptors: [Int32] = [-1,-1]; XCTAssertEqual(pipe(&descriptors),0)
            defer { Darwin.close(descriptors[0]) }
            let bytes = Data(text.utf8); _ = bytes.withUnsafeBytes { Darwin.write(descriptors[1], $0.baseAddress, $0.count) }; Darwin.close(descriptors[1])
            if text == "MMREADY1" { XCTAssertNoThrow(try MigrationWorkerLauncher.requireReady(descriptors[0], deadline:Date().addingTimeInterval(1))) }
            else { XCTAssertThrowsError(try MigrationWorkerLauncher.requireReady(descriptors[0], deadline:Date().addingTimeInterval(1))) }
        }
    }
    func testUntrustedManifestFailsBeforeSpawnOrCredentialLookup() throws {
        XCTAssertThrowsError(try MigrationWorkerManifest(executable:URL(fileURLWithPath:"/private/fixture"),requirement:requirement("broker","1"),sha256:hex("a")))
        var started=false
        XCTAssertThrowsError(try MigrationWorkerLauncher.launchPrivate(executable:"/no/such/worker",deadline:Date().addingTimeInterval(-1),revalidate:{started=true},connect:{_ in fatalError("must not connect")}))
        XCTAssertFalse(started)
    }

    func testExistingPhysicalPrivateTmpPathIsAdmittedAsMetadata() throws {
        let directory = URL(fileURLWithPath: "/private/tmp").appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false,
                                                attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: directory) }
        let artifact = directory.appendingPathComponent("fixture-worker")
        try Data("inert fixture".utf8).write(to: artifact)
        // Metadata admission must not rewrite a physical path to a symlink
        // alias. Actual launch still requires descriptor custody and signature.
        let manifest = try MigrationWorkerManifest(executable: artifact,
            requirement: requirement("custody-migration", "1"), sha256: hex("a"))
        XCTAssertEqual(manifest.executable.path, artifact.path)
    }
}
