import XCTest
import Darwin
@testable import ConsentCore

final class MigrationRuntimeReadinessProbeTests: XCTestCase {
    func hex(_ c: String) -> String { String(repeating:c,count:64) }
    func pin(_ role: String,_ c: String) -> String { "identifier \"com.viant.mechanize.\(role)\" and cdhash H\"\(String(repeating:c,count:40))\"" }
    func success() -> Data { var bytes = VaultDiagnosticReport(stage:"complete",authenticated:true,keyReady:true,inventoryReadable:true).json(); bytes.append(10); return bytes }
    func folder() throws -> URL {
        let value=URL(fileURLWithPath:"/private/tmp").appendingPathComponent("readiness-fixture-"+UUID().uuidString)
        try FileManager.default.createDirectory(at:value,withIntermediateDirectories:false,attributes:[.posixPermissions:0o700])
        addTeardownBlock{try? FileManager.default.removeItem(at:value)};return value
    }
    func compile(_ directory: URL, binary: URL? = nil) throws -> URL {
        let executable=binary ?? directory.appendingPathComponent("inert-diagnostic")
        let literal=String(data:try JSONSerialization.data(withJSONObject:String(data:success(),encoding:.utf8)!,options:.fragmentsAllowed),encoding:.utf8)!
        let source=directory.appendingPathComponent("fixture.c")
        let program="""
        #include <unistd.h>
        #include <string.h>
        #include <stdlib.h>
        extern char **environ;
        int main(int argc,char **argv) {
          if(environ[0]!=0 || argc<2)return 12;
          const char *good=\(literal);
          if(!strcmp(argv[1],"hang")){for(;;)pause();}
          if(!strcmp(argv[1],"private")){write(1,"{\\\"credential\\\":\\\"private-output-canary\\\"}\\n",39);return 0;}
          if(!strcmp(argv[1],"huge")){char b[8192];memset(b,'x',sizeof(b));write(1,b,sizeof(b));return 0;}
          if(!strcmp(argv[1],"--check-vault") && (argc!=6 || strcmp(argv[2],"--broker-pid") || strcmp(argv[3],"123") || strcmp(argv[4],"--broker-start") || strcmp(argv[5],"100:2")))return 13;
          write(2,"private-stderr-canary",20);
          write(1,good,strlen(good));
          if(!strcmp(argv[1],"linger")){close(1);for(;;)pause();}
          return !strcmp(argv[1],"nonzero") ? 9:0;
        }
        """
        try Data(program.utf8).write(to:source)
        let process=Process();process.executableURL=URL(fileURLWithPath:"/usr/bin/clang");process.arguments=[source.path,"-o",executable.path];process.standardError=FileHandle.nullDevice
        try process.run();process.waitUntilExit();guard process.terminationStatus==0 else{throw MigrationConsoleError.unavailable}
        try FileManager.default.setAttributes([.posixPermissions:0o755],ofItemAtPath:executable.path)
        return executable
    }
    func signedBundle() throws -> (URL,URL,String) {
        let root=try folder(),bundle=root.appendingPathComponent("Mechanize Permissions.app"),mac=bundle.appendingPathComponent("Contents/MacOS")
        try FileManager.default.createDirectory(at:mac,withIntermediateDirectories:true,attributes:[.posixPermissions:0o755])
        for dir in [bundle,bundle.appendingPathComponent("Contents"),mac]{try FileManager.default.setAttributes([.posixPermissions:0o755],ofItemAtPath:dir.path)}
        let binary=try compile(root,binary:mac.appendingPathComponent("MechanizeConsent"))
        let info:[String:Any]=["CFBundleIdentifier":"com.viant.mechanize.consent","CFBundleExecutable":"MechanizeConsent","CFBundlePackageType":"APPL","CFBundleName":"Public readiness fixture","MechanizeBrokerRequirement":pin("broker","2")]
        try PropertyListSerialization.data(fromPropertyList:info,format:.xml,options:0).write(to:bundle.appendingPathComponent("Contents/Info.plist"))
        let sign=Process();sign.executableURL=URL(fileURLWithPath:"/usr/bin/codesign");sign.arguments=["--force","--sign","-","--identifier","com.viant.mechanize.consent",bundle.path];sign.standardError=FileHandle.nullDevice
        try sign.run();sign.waitUntilExit();guard sign.terminationStatus==0 else{throw MigrationConsoleError.unavailable}
        let display=Process(),pipe=Pipe();display.executableURL=URL(fileURLWithPath:"/usr/bin/codesign");display.arguments=["--display","--verbose=4",bundle.path];display.standardError=pipe;display.standardOutput=FileHandle.nullDevice
        try display.run();let bytes=pipe.fileHandleForReading.readDataToEndOfFile();display.waitUntilExit()
        guard let text=String(data:bytes,encoding:.utf8),let line=text.split(separator:"\n").first(where:{$0.hasPrefix("CDHash=")}) else{throw MigrationConsoleError.unavailable}
        let rule="identifier \"com.viant.mechanize.consent\" and cdhash H\""+line.dropFirst(7)+"\""
        return (root,binary,rule)
    }
    func plan(root: URL, binary: URL? = nil, requirement: String? = nil) throws -> Data {
        let entry:[String:Any]=["kind":"file","mode":0o755,"size":try binary.map{try Data(contentsOf:$0).count} ?? 1,"sha256":try binary.map{MigrationUpgradeIntent.digest(try Data(contentsOf:$0))} ?? hex("d")]
        let directory:[String:Any]=["kind":"directory","mode":0o755,"size":0,"sha256":""]
        let inventory:[String:Any]=[".":directory,"Contents":directory,"Contents/MacOS":directory,"Contents/MacOS/MechanizeConsent":entry]
        let runtime:[String:Any]=["BrokerPath":root.appendingPathComponent("mechanize").path,"OldBrokerRequirement":pin("broker","1"),"NewBrokerRequirement":pin("broker","2"),"Artifacts":[["role":"console","target":root.appendingPathComponent("Mechanize Permissions.app").path,"NewRequirement":requirement ?? pin("consent","3"),"New":inventory]]]
        return try JSONSerialization.data(withJSONObject:["version":1,"runtime":runtime],options:[.sortedKeys,.withoutEscapingSlashes])
    }
    func intent(_ raw: Data, root: URL) throws -> MigrationUpgradeIntent {
        let worker=try MigrationWorkerManifest(executable:root.appendingPathComponent("mutation"),requirement:pin("custody-migration","4"),sha256:hex("d"))
        let bootstrap=try MigrationWorkerBootstrap(session:hex("a"),configSHA256:hex("b"),canonicalExecutable:root.appendingPathComponent("mechanize").path,oldRequirement:pin("broker","1"),newRequirement:pin("broker","2"),alias:"vault-master",service:"com.viant.mechanize.vault",account:"public-fixture",workerRequirement:worker.requirement)
        return try MigrationUpgradeIntent(worker:worker,bootstrap:bootstrap,runtimeManifestSHA256:MigrationUpgradeIntent.digest(raw))
    }
    func preparation(_ intent:MigrationUpgradeIntent) throws -> MigrationNativePreparation {
        let identity=Data("public-persistent-reference".utf8),id=hex("f"),item=MigrationUpgradeIntent.digest(Data("public-persistent-reference".utf8))
        let names=["ID","CanonicalExecutable","OldRequirement","NewRequirement","Alias","Service","Account","ItemReferenceSHA256","Binding"]
        let values=[id]+intent.options+[item,try intent.transitionBinding(id:id,itemSHA256:item)]
        let transition=try MigrationWorkerSession.canonical(Dictionary(uniqueKeysWithValues:zip(names,values)),order:names)
        var evidence=try MigrationWorkerSession.canonical(["intentSHA256":intent.binding,"configSHA256":intent.bootstrap.value["configSHA256"]!,"optionsSHA256":intent.optionsSHA256,"runtimeManifestSHA256":intent.runtimeManifestSHA256,"mutationRequirement":intent.worker.requirement],order:["intentSHA256","configSHA256","optionsSHA256","runtimeManifestSHA256","mutationRequirement"])
        evidence.removeLast();evidence.append(Data(",\"transition\":".utf8));evidence.append(transition);evidence.append(125)
        var packet=try MigrationWorkerSession.canonical(["version":1,"id":hex("1"),"session":intent.bootstrap.session,"status":"prepared","identity":identity.base64EncodedString()],order:["version","id","session","status","identity"])
        packet.removeLast();packet.append(Data(",\"evidence\":".utf8));packet.append(evidence);packet.append(125)
        return try MigrationNativePreparation.decode(packet,intent:intent,requestID:hex("1"),validUntil:Date().addingTimeInterval(20))
    }
    func run(_ binary:URL,_ mode:String,deadline:TimeInterval=2,revalidate:@escaping ()throws->Void={},inspect:((pid_t)throws->MigrationReadinessProcessIdentity)?=nil,verify:@escaping (pid_t)throws->Void={_ in})throws{
        try MigrationRuntimeReadinessProbe.runPrivate(executable:binary.path,arguments:[mode],deadline:Date().addingTimeInterval(deadline),cancelled:{false},revalidate:revalidate,verifyRunning:verify,inspect:inspect ?? MigrationRuntimeReadinessProbe.identity)
    }
    func testOnlyExactScalarSuccessIsConsumedAndPrivateOrMalformedOutputRefuses()throws{
        XCTAssertNoThrow(try MigrationRuntimeReadinessProbe.diagnostic(success()))
        let valid=String(data:success(),encoding:.utf8)!
        for raw in ["",valid+"{}",valid.replacingOccurrences(of:"true",with:"1"),valid.replacingOccurrences(of:"\"stage\":",with:"\"stage\":\"complete\",\"stage\":"),valid.replacingOccurrences(of:"{",with:"{\"credential\":\"private-canary\","),String(repeating:"x",count:8192)]{
            XCTAssertThrowsError(try MigrationRuntimeReadinessProbe.diagnostic(Data(raw.utf8))){error in XCTAssertFalse(String(describing:error).contains("private-canary"))}
        }
    }
    func testSealedPlanRequiresExactDigestTargetRoleReversePinAndUniqueFields()throws{
        let root=try folder(),raw=try plan(root:root),intent=try intent(raw,root:root)
        _ = try MigrationRuntimeConsoleManifest(frozenPlan:raw,intent:intent)
        XCTAssertThrowsError(try MigrationRuntimeConsoleManifest(frozenPlan:raw+Data(" ".utf8),intent:intent))
        let text=String(data:raw,encoding:.utf8)!
        for changed in [text.replacingOccurrences(of:"\"version\":1",with:"\"version\":1,\"version\":1"),text.replacingOccurrences(of:"\"version\":1",with:"\"version\":true"),text.replacingOccurrences(of:"Mechanize Permissions.app",with:"Other.app"),text.replacingOccurrences(of:pin("consent","3").replacingOccurrences(of:"\"",with:"\\\""),with:pin("broker","3").replacingOccurrences(of:"\"",with:"\\\""))]{
            let bytes=Data(changed.utf8),changedIntent=try self.intent(bytes,root:root)
            XCTAssertThrowsError(try MigrationRuntimeConsoleManifest(frozenPlan:bytes,intent:changedIntent))
        }
    }
    func testSignedBundleArtifactAndReversePinAreCheckedWithoutCredentialLookup()throws{
        let (root,binary,rule)=try signedBundle(),raw=try plan(root:root,binary:binary,requirement:rule),intent=try intent(raw,root:root)
        let manifest=try MigrationRuntimeConsoleManifest(frozenPlan:raw,intent:intent)
        let artifact=try MigrationWorkerArtifact(executable:manifest.executable,requirement:manifest.requirement,sha256:manifest.sha256,uid:getuid(),consoleBundle:manifest.bundle)
        try artifact.verify();try MigrationRuntimeReadinessProbe.bundleContract(manifest)
        XCTAssertThrowsError(try MigrationWorkerManifest(executable:binary,requirement:rule,sha256:manifest.sha256))
        let info=manifest.bundle.appendingPathComponent("Contents/Info.plist")
        var plist=try PropertyListSerialization.propertyList(from:Data(contentsOf:info),format:nil) as! [String:Any]
        plist["MechanizeBrokerRequirement"]=pin("broker","9")
        try PropertyListSerialization.data(fromPropertyList:plist,format:.xml,options:0).write(to:info)
        XCTAssertThrowsError(try MigrationRuntimeReadinessProbe.bundleContract(manifest))
    }
    func testSignedCodeOnlyFixtureChecksArgumentsEnvironmentAndOwnedProcessBirth()throws{
        let (root,binary,rule)=try signedBundle(),raw=try plan(root:root,binary:binary,requirement:rule),intent=try intent(raw,root:root)
        let manifest=try MigrationRuntimeConsoleManifest(frozenPlan:raw,intent:intent)
        let artifact=try MigrationWorkerArtifact(executable:binary,requirement:rule,sha256:manifest.sha256,uid:getuid(),consoleBundle:manifest.bundle)
        var checks=0,child:pid_t=0
        try MigrationRuntimeReadinessProbe.runPrivate(executable:binary.path,arguments:["--check-vault","--broker-pid","123","--broker-start","100:2"],deadline:Date().addingTimeInterval(3),cancelled:{false},revalidate:{checks+=1;try artifact.verify();try MigrationRuntimeReadinessProbe.bundleContract(manifest)},verifyRunning:{pid in child=pid;try MigrationRuntimeReadinessProbe.verifyProcess(pid,executable:binary.path,requirement:rule,expectedStart:nil)})
        XCTAssertEqual(checks,3);XCTAssertGreaterThan(child,0);XCTAssertEqual(kill(child,0),-1)
    }
    func testPrivateOutputOversizeNonzeroAndLifetimeFailuresAlwaysReapOwnedChild()throws{
        let binary=try compile(folder())
        for mode in ["private","huge","nonzero","hang","linger"]{
            var child:pid_t=0;let began=Date()
            XCTAssertThrowsError(try run(binary,mode,deadline:0.25,verify:{child=$0}))
            XCTAssertLessThan(Date().timeIntervalSince(began),1.5);XCTAssertGreaterThan(child,0);XCTAssertEqual(kill(child,0),-1)
        }
    }
    func testIdentityDriftAndPostResultArtifactDriftRefuse()throws{
        let binary=try compile(folder());var calls=0;var child:pid_t=0;var first:MigrationReadinessProcessIdentity?
        XCTAssertThrowsError(try run(binary,"valid",inspect:{pid in calls+=1;if calls==3,let real=first{return MigrationReadinessProcessIdentity(pid:real.pid,uid:real.uid,seconds:real.seconds+1,microseconds:real.microseconds)};let real=try MigrationRuntimeReadinessProbe.identity(pid);first=real;return real},verify:{child=$0}))
        XCTAssertEqual(kill(child,0),-1)
        var validations=0
        XCTAssertThrowsError(try run(binary,"valid",revalidate:{validations+=1;if validations==3{throw MigrationConsoleError.unavailable}}))
        XCTAssertEqual(validations,3)
    }
    func testCancellationAndIndependentWatchdogStopOnlyOwnedChild()throws{
        let binary=try compile(folder()),cancellation=MigrationReadinessCancellation();var child:pid_t=0
        XCTAssertThrowsError(try MigrationRuntimeReadinessProbe.runPrivate(executable:binary.path,arguments:["hang"],deadline:Date().addingTimeInterval(2),cancelled:{cancellation.isCancelled},revalidate:{},verifyRunning:{pid in child=pid;cancellation.cancel()},installCancellation:cancellation.install))
        XCTAssertGreaterThan(child,0);XCTAssertEqual(kill(child,0),-1)
        var count=0;child=0
        XCTAssertThrowsError(try MigrationRuntimeReadinessProbe.runPrivate(executable:binary.path,arguments:["hang"],deadline:Date().addingTimeInterval(0.1),cancelled:{false},revalidate:{count+=1;if count==2{usleep(250000)}},verifyRunning:{child=$0}))
        XCTAssertGreaterThan(child,0);XCTAssertEqual(kill(child,0),-1)
    }
    func testRefusalBeforeSpawnAndFrozenArtifactInodeDrift()throws{
        var launched=false
        XCTAssertThrowsError(try MigrationRuntimeReadinessProbe.runPrivate(executable:"/must-not-run",arguments:[],deadline:Date().addingTimeInterval(-1),cancelled:{false},revalidate:{launched=true},verifyRunning:{_ in launched=true}))
        XCTAssertFalse(launched)
        let (root,binary,rule)=try signedBundle(),raw=try plan(root:root,binary:binary,requirement:rule),intent=try intent(raw,root:root)
        let manifest=try MigrationRuntimeConsoleManifest(frozenPlan:raw,intent:intent)
        let artifact=try MigrationWorkerArtifact(executable:binary,requirement:rule,sha256:manifest.sha256,uid:getuid(),consoleBundle:manifest.bundle)
        let bytes=try Data(contentsOf:binary);try FileManager.default.moveItem(at:binary,to:binary.appendingPathExtension("old"));try bytes.write(to:binary);try FileManager.default.setAttributes([.posixPermissions:0o755],ofItemAtPath:binary.path)
        XCTAssertThrowsError(try artifact.verify())
    }
    func testPublicProbeRejectsSubstitutedTerminalTransitionBeforeAnyRuntimeAccess()async throws{
        let root=try folder(),raw=try plan(root:root),intent=try intent(raw,root:root),prepared=try preparation(intent)
        let probe=MigrationRuntimeReadinessProbe(manifest:try MigrationRuntimeConsoleManifest(frozenPlan:raw,intent:intent))
        for reply in [MigrationInstallerReply(status:"verified",transitionID:hex("0"),scope:"runtime-artifacts",runtime:try MigrationInstallerRuntime(brokerPID:123,brokerStartToken:"100:2")),MigrationInstallerReply(status:"verified",transitionID:prepared.preparation.transitionID,scope:"runtime-artifacts")]{
            do {try await probe.verify(intent:intent,preparation:prepared,terminal:reply);XCTFail("unbound terminal accepted")}catch{}
        }
    }
}
