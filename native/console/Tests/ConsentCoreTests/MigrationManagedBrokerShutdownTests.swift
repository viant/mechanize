import XCTest
@testable import ConsentCore

final class MigrationManagedBrokerShutdownTests: XCTestCase {
    func fixture(extra: [String:Any] = [:]) throws -> (MigrationManagedShutdownPlan,Data,MigrationShutdownIdentity) {
        let base=try MigrationNativePreparationTests().intent(),broker=base.options[0]
        let arguments=[broker,"serve","-config","/private/fixture/config.json","-listen","127.0.0.1:4987"]
        var job:[String:Any]=["Label":"com.viant.mechanize.broker","ProgramArguments":arguments,"KeepAlive":false,"RunAtLoad":true]
        extra.forEach{job[$0.key]=$0.value}
        let bytes=try PropertyListSerialization.data(fromPropertyList:job,format:.xml,options:0)
        let plan=try JSONSerialization.data(withJSONObject:["readiness":["launchd":["path":"/private/fixture/broker.plist","sha256":MigrationUpgradeIntent.digest(bytes)],"listen":"127.0.0.1:4987"]])
        let intent=try MigrationUpgradeIntent(worker:base.worker,bootstrap:base.bootstrap,runtimeManifestSHA256:MigrationUpgradeIntent.digest(plan))
        return(try MigrationManagedShutdownPlan(intent:intent,frozenPlan:plan),bytes,MigrationShutdownIdentity(pid:41,uid:getuid(),birth:"1790000000:1",executable:broker,requirement:base.options[1]))
    }
    func status(_ plan:MigrationManagedShutdownPlan,_ pid:Int32?)->Data {
        Data(("gui/\(getuid())/com.viant.mechanize.broker = {\npath = \(plan.path)\nprogram = \(plan.broker)\narguments = {\n"+plan.arguments.joined(separator:"\n")+"\n}\n"+(pid.map{"pid = \($0)\n"} ?? "")+"}\n").utf8)
    }
    func testExactManagedSIGTERMRouteSignalsOnceAndVerifiesPhysicalAbsence() throws {
        let (plan,data,identity)=try fixture();var running=true,signals=0,dispatches=0
        let runtime=MigrationManagedShutdownRuntime(read:{path in XCTAssertEqual(path,plan.path);return data},status:{_,_ in self.status(plan,running ? identity.pid:nil)},helpers:{_ in []},inspect:{actual in XCTAssertEqual(actual,identity);return running ? .same:.gone},signal:{actual,_ in XCTAssertEqual(actual,identity);signals+=1;running=false})
        let route=MigrationManagedBrokerShutdown(plan:plan,runtime:runtime)
        _ = try route.qualify(broker:identity,helperPins:[:],deadline:Date().addingTimeInterval(5))
        try route.stop(deadline:Date().addingTimeInterval(5)){dispatches+=1}
        try route.verifyStopped(deadline:Date().addingTimeInterval(5))
        XCTAssertThrowsError(try route.stop(deadline:Date().addingTimeInterval(5)){dispatches+=1})
        XCTAssertEqual(signals,1);XCTAssertEqual(dispatches,1)
        running=true
        XCTAssertThrowsError(try route.verifyStopped(deadline:Date().addingTimeInterval(5)))
        XCTAssertEqual(signals,1)
    }
    func testKeepAliveAlternateProgramTriggersAndSubstitutionRefuseBeforeSignal() throws {
        for extra:[String:Any] in [["KeepAlive":true],["KeepAlive":0],["Program":"/private/other"],["WatchPaths":["/private/trigger"]]] {
            let (plan,data,_)=try fixture(extra:extra)
            XCTAssertThrowsError(try plan.job(data))
        }
        let (plan,data,identity)=try fixture();var substituted=false,signals=0,dispatched=false
        let runtime=MigrationManagedShutdownRuntime(read:{_ in data},status:{_,_ in self.status(plan,substituted ? 99:identity.pid)},helpers:{_ in []},inspect:{_ in .same},signal:{_,_ in signals+=1})
        let route=MigrationManagedBrokerShutdown(plan:plan,runtime:runtime)
        _ = try route.qualify(broker:identity,helperPins:[:],deadline:Date().addingTimeInterval(5));substituted=true
        XCTAssertThrowsError(try route.stop(deadline:Date().addingTimeInterval(5)){dispatched=true})
        XCTAssertFalse(dispatched);XCTAssertEqual(signals,0)
    }
    func testLoadedJobMustRetainDefinitionProgramArgumentsAndSinglePID() throws {
        let (plan,_,_)=try fixture();let service="gui/\(getuid())/com.viant.mechanize.broker"
        let good=String(data:status(plan,41),encoding:.utf8)!
        for text in [good.replacingOccurrences(of:plan.path,with:"/private/other.plist"),good.replacingOccurrences(of:"pid = 41",with:"pid = 41\npid = 42"),good.replacingOccurrences(of:"serve",with:"doctor"),good+"properties = keepalive\n"] {
            XCTAssertThrowsError(try plan.loadedPID(Data(text.utf8),service:service))
        }
    }
}
