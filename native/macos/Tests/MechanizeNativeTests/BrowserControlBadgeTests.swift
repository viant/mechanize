import XCTest
import AppKit
import MechanizeNativeCore
@testable import MechanizeNative
final class BrowserControlBadgeTests: XCTestCase {
    func testTrackedWindowMovesHidesExpiresAndRejectsStaleEnd() async throws {
        try await MainActor.run {
            var time=100.0,front:pid_t?=42,birth="100:1"
            var rows=[SessionKeyWindow(id:7,pid:42,layer:0,visible:true,alpha:1,bounds:CGRect(x:0,y:26,width:900,height:700))]
            var shown:[CGRect]=[],moved:[CGRect]=[],hidden:[UInt64]=[];var generation:UInt64=0
            let runtime=WindowSessionKeyRuntime(process:{_ in (getuid(),birth,"com.fixture.app")},foreground:{front},windows:{rows},session:{true},secure:{false})
            let view=BrowserBadgePresentation(begin:{shown.append($0);generation+=1;return generation},move:{_,bounds in moved.append(bounds)},hide:{hidden.append($0)},renew:{_ in})
            let badge=BrowserControlBadge(runtime:runtime,now:{time},schedule:false,presentation:view)
            let first=String(repeating:"a",count:64),second=String(repeating:"b",count:64)
            func params(_ token:String)->[String:Any] {["token":token,"expectedApp":"com.fixture.app","pid":Int32(42),"processStartToken":"100:1","windowBounds":["x":0.0,"y":26.0,"width":900.0,"height":700.0],"durationMs":1000]}
            XCTAssertEqual(try badge.handle(method:"controlBadge.begin",params:params(first))["status"] as? String,"shown")
            rows=[SessionKeyWindow(id:7,pid:42,layer:0,visible:true,alpha:1,bounds:CGRect(x:100,y:126,width:900,height:700))]
            XCTAssertEqual(badge.refresh(),"shown");XCTAssertEqual(moved.last?.minX,100)
            front=99;XCTAssertEqual(badge.refresh(),"hidden");XCTAssertEqual(hidden.count,1)
            front=42;XCTAssertEqual(badge.refresh(),"shown")
            rows=[SessionKeyWindow(id:7,pid:42,layer:0,visible:true,alpha:1,bounds:CGRect(x:0,y:26,width:900,height:700))]
            _=try badge.handle(method:"controlBadge.begin",params:params(second));let before=hidden.count
            _=try badge.handle(method:"controlBadge.end",params:["token":first]);XCTAssertEqual(hidden.count,before);XCTAssertEqual(badge.refresh(),"shown")
            time=102;XCTAssertEqual(badge.refresh(),"unavailable");XCTAssertEqual(hidden.count,before+1)
            time=103;XCTAssertThrowsError(try badge.handle(method:"controlBadge.begin",params:params(first)));_=try badge.handle(method:"controlBadge.begin",params:params(String(repeating:"c",count:64)));birth="101:1";XCTAssertEqual(badge.refresh(),"unavailable")
            XCTAssertEqual(shown.count,3,"A new action on the same window reuses the panel")
        }
    }
}

extension BrowserControlBadgeTests {
    // Isolated fixture geometry and our own NSPanel. No user browser or profile,
    // screenshots, focus activation, key events, or bank state is involved.
    func testRealPanelExpiresWhileFramedInputWaits() async throws {
        let pipe=Pipe(),reader=MechanizeNativeCore.FramedInputReader(pipe.fileHandleForReading)
        let pending=Task {try await reader.read()}
        let badge=await MainActor.run { () -> BrowserControlBadge in
            _=NSApplication.shared.setActivationPolicy(.accessory)
            let bounds=CGRect(x:320,y:220,width:900,height:700)
            let runtime=WindowSessionKeyRuntime(process:{_ in (getuid(),"fixture-birth","com.fixture.app")},foreground:{getpid()},windows:{[SessionKeyWindow(id:7,pid:getpid(),layer:0,visible:true,alpha:1,bounds:bounds)]},session:{true},secure:{false})
            var presentation=BrowserBadgePresentation.system
            presentation.measure={_,_ in ControlBadgeAnchor(headerCenter:17,leading:84)} // Own synthetic panel geometry only.
            return BrowserControlBadge(runtime:runtime,presentation:presentation)
        }
        let token=String(repeating:"d",count:64)
        let started=try await MainActor.run {try badge.handle(method:"controlBadge.begin",params:["token":token,"expectedApp":"com.fixture.app","pid":getpid(),"processStartToken":"fixture-birth","windowBounds":["x":320.0,"y":220.0,"width":900.0,"height":700.0],"durationMs":300])}
        XCTAssertEqual(started["status"] as? String,"shown")
        try await Task.sleep(nanoseconds:100_000_000)
        let visible=await MainActor.run {AutomationPointer.controlPresentationVisible()}
        XCTAssertTrue(visible,"Our badge must be present in WindowServer while stdin remains idle")
        try await Task.sleep(nanoseconds:350_000_000)
        let expired=await MainActor.run {AutomationPointer.controlPresentationVisible()}
        XCTAssertFalse(expired,"The main run-loop timer must hide the badge while stdin is still waiting")
        _=try await MainActor.run {try badge.handle(method:"controlBadge.end",params:["token":token])}
        try pipe.fileHandleForWriting.close();_=try await pending.value
    }
}

extension BrowserControlBadgeTests {
    func testSub100msNormalEndShowsIdleAndStopHidesImmediately() async throws {
        let badge=await MainActor.run { () -> BrowserControlBadge in
            _=NSApplication.shared.setActivationPolicy(.accessory)
            let bounds=CGRect(x:320,y:220,width:900,height:700)
            let runtime=WindowSessionKeyRuntime(process:{_ in (getuid(),"fixture-birth","com.fixture.app")},foreground:{getpid()},windows:{[SessionKeyWindow(id:7,pid:getpid(),layer:0,visible:true,alpha:1,bounds:bounds)]},session:{true},secure:{false})
            var presentation=BrowserBadgePresentation.system
            presentation.measure={_,_ in ControlBadgeAnchor(headerCenter:17,leading:84)} // Own synthetic panel geometry only.
            return BrowserControlBadge(runtime:runtime,presentation:presentation)
        }
        let token=String(repeating:"e",count:64)
        _=try await MainActor.run {
            _=try badge.handle(method:"controlBadge.begin",params:["token":token,"expectedApp":"com.fixture.app","pid":getpid(),"processStartToken":"fixture-birth","windowBounds":["x":320.0,"y":220.0,"width":900.0,"height":700.0],"durationMs":300])
            return try badge.handle(method:"controlBadge.end",params:["token":token])
        }
        try await Task.sleep(nanoseconds:100_000_000)
        let idle=await MainActor.run {(AutomationPointer.controlPresentationVisible(),AutomationPointer.controlPresentationActive())}
        XCTAssertTrue(idle.0);XCTAssertEqual(idle.1,false,"Normal completion must never retain a Controlling claim")
        _=try await MainActor.run {try badge.handle(method:"controlBadge.stop",params:["token":token])}
        try await Task.sleep(nanoseconds:30_000_000)
        let stopped=await MainActor.run {AutomationPointer.controlPresentationVisible()};XCTAssertFalse(stopped)
    }
}

extension BrowserControlBadgeTests {
    func testCompletedBadgeNeverReactivatesAfterFocusReturn() async throws {
        try await MainActor.run {
            var front:pid_t?=42,time=100.0,generation:UInt64=0
            let bounds=CGRect(x:0,y:26,width:900,height:700)
            let runtime=WindowSessionKeyRuntime(process:{_ in (getuid(),"100:1","com.fixture.app")},foreground:{front},windows:{[SessionKeyWindow(id:7,pid:42,layer:0,visible:true,alpha:1,bounds:bounds)]},session:{true},secure:{false})
            var renderedActive:[Bool]=[]
            let presentation=BrowserBadgePresentation(begin:{_ in generation+=1;renderedActive.append(true);return generation},move:{_,_ in},hide:{_ in},renew:{_ in},complete:{_ in renderedActive.append(false)})
            let badge=BrowserControlBadge(runtime:runtime,now:{time},schedule:false,presentation:presentation),token=String(repeating:"f",count:64)
            _=try badge.handle(method:"controlBadge.begin",params:["token":token,"expectedApp":"com.fixture.app","pid":Int32(42),"processStartToken":"100:1","windowBounds":["x":0.0,"y":26.0,"width":900.0,"height":700.0],"durationMs":3000])
            _=try badge.handle(method:"controlBadge.end",params:["token":token]);XCTAssertEqual(renderedActive.last,false)
            front=99;XCTAssertEqual(badge.refresh(),"hidden")
            time+=0.2;front=42;_=badge.refresh()
            XCTAssertEqual(renderedActive.last,false,"A finished action must not revive a Controlling presentation")
        }
    }
    func testHeartbeatKeepsActualControlActivePastCompletionDelay() async throws {
        try await MainActor.run {
            var time=100.0,shown=0,hidden=0,completed=0
            let bounds=CGRect(x:0,y:26,width:900,height:700)
            let runtime=WindowSessionKeyRuntime(process:{_ in (getuid(),"100:1","com.fixture.app")},foreground:{42},windows:{[SessionKeyWindow(id:7,pid:42,layer:0,visible:true,alpha:1,bounds:bounds)]},session:{true},secure:{false})
            let presentation=BrowserBadgePresentation(begin:{_ in shown+=1;return UInt64(shown)},move:{_,_ in},hide:{_ in hidden+=1},renew:{_ in},complete:{_ in completed+=1})
            let badge=BrowserControlBadge(runtime:runtime,now:{time},schedule:false,presentation:presentation),token=String(repeating:"c",count:64)
            _=try badge.handle(method:"controlBadge.begin",params:["token":token,"expectedApp":"com.fixture.app","pid":Int32(42),"processStartToken":"100:1","windowBounds":["x":0.0,"y":26.0,"width":900.0,"height":700.0],"durationMs":3000])
            for _ in 0..<6 {time+=1;XCTAssertEqual(try badge.handle(method:"controlBadge.renew",params:["token":token,"durationMs":3000])["status"] as? String,"shown")}
            XCTAssertEqual(shown,1);XCTAssertEqual(hidden,0);XCTAssertEqual(completed,0)
            _=try badge.handle(method:"controlBadge.end",params:["token":token]);XCTAssertEqual(completed,1)
            time+=1.3;XCTAssertEqual(badge.refresh(),"unavailable");XCTAssertEqual(hidden,1)
        }
    }
}
