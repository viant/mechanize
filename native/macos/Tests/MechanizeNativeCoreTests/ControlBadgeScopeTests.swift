import XCTest
import CoreGraphics
@testable import MechanizeNativeCore
final class ControlBadgeScopeTests: XCTestCase {
    func testExactUniqueWindowGeometryOnly() {
        let bounds=CGRect(x:-900,y:27,width:800,height:600)
        let exact=ControlBadgeWindow(id:7,pid:42,layer:0,visible:true,alpha:1,bounds:bounds)
        XCTAssertEqual(ControlBadgeScope.match(pid:42,bounds:bounds,windows:[exact]),7)
        XCTAssertNil(ControlBadgeScope.match(pid:42,bounds:bounds,windows:[exact,exact]))
        XCTAssertNil(ControlBadgeScope.match(pid:43,bounds:bounds,windows:[exact]))
        XCTAssertNil(ControlBadgeScope.match(pid:42,bounds:bounds.offsetBy(dx:3,dy:0),windows:[exact]))
        XCTAssertEqual(ControlBadgeScope.match(pid:42,bounds:bounds.offsetBy(dx:2,dy:2),windows:[exact]),7)
        for candidate in [ControlBadgeWindow(id:7,pid:42,layer:1,visible:true,alpha:1,bounds:bounds),ControlBadgeWindow(id:7,pid:42,layer:0,visible:false,alpha:1,bounds:bounds),ControlBadgeWindow(id:7,pid:42,layer:0,visible:true,alpha:0,bounds:bounds)] {XCTAssertNil(ControlBadgeScope.match(pid:42,bounds:bounds,windows:[candidate]))}
    }
    func testBoundedOpaqueOwnerAndDuration() {
        XCTAssertTrue(ControlBadgeScope.validToken(String(repeating:"a",count:64)))
        for token in ["",String(repeating:"a",count:63),String(repeating:"A",count:64),String(repeating:"g",count:64)] {XCTAssertFalse(ControlBadgeScope.validToken(token))}
        XCTAssertTrue(ControlBadgeScope.validDuration(100));XCTAssertTrue(ControlBadgeScope.validDuration(5000))
        XCTAssertFalse(ControlBadgeScope.validDuration(99));XCTAssertFalse(ControlBadgeScope.validDuration(5001))
    }
}

final class FramedInputReaderTests: XCTestCase {
    func testSerialFramesPreserveOrderAndEOF() async throws {
        let pipe=Pipe(),reader=FramedInputReader(pipe.fileHandleForReading)
        try FrameCodec.write(["order":1],to:pipe.fileHandleForWriting)
        try FrameCodec.write(["order":2],to:pipe.fileHandleForWriting)
        try pipe.fileHandleForWriting.close()
        let first=try await reader.read(),second=try await reader.read(),end=try await reader.read()
        XCTAssertEqual((try JSONSerialization.jsonObject(with:first!) as? [String:Int])?["order"],1)
        XCTAssertEqual((try JSONSerialization.jsonObject(with:second!) as? [String:Int])?["order"],2)
        XCTAssertNil(end)
    }
}

extension ControlBadgeScopeTests {
    func testInputPresentationWaitsUntilPostingAndNativeModalScopeIsExact() {
        for method in ["elements.pressKey","elements.pressSessionKey","input.key","input.text","input.pointer","windows.pressSessionKey","windows.typeText","elements.setValue","app.activate","app.launch"] {XCTAssertTrue(NativeControlBadgeRoutes.delayUntilDispatch(method))}
        for method in ["elements.press","elements.submit","elements.showMenu","elements.focus","elements.replaceText","windows.setPosition","app.quit"] {XCTAssertFalse(NativeControlBadgeRoutes.delayUntilDispatch(method))}
        let bounds=CGRect(x:0,y:20,width:200,height:100)
        let modal=ControlBadgeWindow(id:7,pid:42,layer:8,visible:true,alpha:1,bounds:bounds)
        XCTAssertNil(ControlBadgeScope.match(pid:42,bounds:bounds,windows:[modal]))
        XCTAssertEqual(ControlBadgeScope.match(pid:42,bounds:bounds,windows:[modal],allowedLayers:[0,3,8]),7)
    }
}
