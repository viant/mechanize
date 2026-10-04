import XCTest
@testable import MechanizeNativeCore
final class ProtocolTests: XCTestCase {
    func testFrameRoundTrip() throws {
        let pipe = Pipe()
        try FrameCodec.write(["requestId": "test", "value": "quotes\"\n$"], to: pipe.fileHandleForWriting)
        let data = try XCTUnwrap(FrameCodec.read(pipe.fileHandleForReading))
        let decoded = try JSONSerialization.jsonObject(with: data) as! [String: String]
        XCTAssertEqual(decoded["value"], "quotes\"\n$")
    }
    func testTruncationAndOversize() throws {
        for bytes in [Data([0, 0]), Data([0, 0, 0, 4, 1]), Data([0, 32, 0, 1])] {
            let pipe = Pipe(); try pipe.fileHandleForWriting.write(contentsOf: bytes); try pipe.fileHandleForWriting.close()
            XCTAssertThrowsError(try FrameCodec.read(pipe.fileHandleForReading))
        }
    }
    func testOnlyAuthenticatedSuccessfulCaptureReplyGetsLargerBudget() throws {
        let url=FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        FileManager.default.createFile(atPath:url.path,contents:nil)
        defer { try? FileManager.default.removeItem(at:url) }
        let handle=try FileHandle(forUpdating:url);defer { try? handle.close() }
        // A sizeable base64-shaped response; slash escaping cannot inflate it.
        let large:[String:Any] = ["result":["pngBase64":String(repeating:"/",count:3*1024*1024)]]
        XCTAssertEqual(FrameCodec.maximumWindowFrameResponseBytes,44_804_780)
        XCTAssertEqual(FrameCodec.maximumWindowFramePNGBytes,33_554_432)
        XCTAssertThrowsError(try FrameCodec.write(large,to:handle))
        XCTAssertThrowsError(try FrameCodec.writeResponse(large,to:handle,requestMethod:"doctor",brokerAuthenticated:true))
        XCTAssertThrowsError(try FrameCodec.writeResponse(large,to:handle,requestMethod:"windows.captureFrame",brokerAuthenticated:false))
        var failed=large;failed["error"]=["code":"denied"]
        XCTAssertThrowsError(try FrameCodec.writeResponse(failed,to:handle,requestMethod:"windows.captureFrame",brokerAuthenticated:true))
        try FrameCodec.writeResponse(large,to:handle,requestMethod:"windows.captureFrame",brokerAuthenticated:true)
        try handle.seek(toOffset:0)
        let header=try XCTUnwrap(handle.read(upToCount:4))
        let count=header.reduce(0){($0<<8)|Int($1)}
        XCTAssertGreaterThan(count,FrameCodec.maximumBytes)
        XCTAssertLessThan(count,4*1024*1024)
        try handle.seek(toOffset:0)
        // Generic decoder is the inbound request route, and stays at 2 MiB.
        XCTAssertThrowsError(try FrameCodec.read(handle))
    }
    func testInvalidDeadlineAndDedupe() throws {
        XCTAssertThrowsError(try Budget(milliseconds: 0))
        XCTAssertThrowsError(try Budget(milliseconds: 30_001))
        let ledger = MutationLedger(limit: 1)
        try ledger.reserve("a")
        XCTAssertEqual(ledger.reply(for: "a")?["dispatchState"] as? String, "unknown")
        XCTAssertThrowsError(try ledger.reserve("a"))
        XCTAssertThrowsError(try ledger.reserve("b"))
        ledger.finish("a", reply: ["dispatchState": "dispatched"])
        XCTAssertEqual(ledger.reply(for: "a")?["dispatchState"] as? String, "dispatched")
    }
}
