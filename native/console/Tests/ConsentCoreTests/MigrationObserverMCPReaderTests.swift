import XCTest
@testable import ConsentCore

final class MigrationObserverMCPReaderTests:XCTestCase {
    func packet(id:String="fixture",error:Bool=false)throws->Data {
        try JSONSerialization.data(withJSONObject:["jsonrpc":"2.0","id":id,"result":["isError":error,"structuredContent":["id":"observation","truncated":false]]])
    }
    func http(_ data:Data,type:String="application/json",status:String="200 OK",extra:String="")->Data {
        var raw=Data("HTTP/1.1 \(status)\r\nContent-Type: \(type)\r\nContent-Length: \(data.count)\r\n\(extra)\r\n".utf8);raw.append(data);return raw
    }
    func testBoundedClosedJSONAndSSEProjection()throws {
        let packet=try packet()
        let json=try MigrationObserverMCPReader.response(http(packet),id:"fixture")
        let sse=Data(("data: "+String(data:packet,encoding:.utf8)!+"\n\n").utf8)
        XCTAssertEqual(try MigrationObserverMCPReader.response(http(sse,type:"text/event-stream"),id:"fixture"),json)
        var chunks=Data("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n\(String(packet.count,radix:16))\r\n".utf8)
        chunks.append(packet);chunks.append(Data("\r\n0\r\n\r\n".utf8))
        XCTAssertEqual(try MigrationObserverMCPReader.response(chunks,id:"fixture"),json)
    }
    func testRejectsRedirectErrorsWrongIDsDuplicateHeadersAndMultipleEvents()throws {
        let packet=try packet()
        for raw in [http(packet,status:"302 Found"),http(try self.packet(id:"other")),http(try self.packet(error:true)),http(packet,extra:"Content-Length: 0\r\n"),http(packet,type:"text/html"),http(Data("data: {}\ndata: {}\n".utf8),type:"text/event-stream")] {
            XCTAssertThrowsError(try MigrationObserverMCPReader.response(raw,id:"fixture"))
        }
    }
    func testRejectsMalformedChunkedAndConflictingFraming()throws {
        let prefix="HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n"
        for text in [prefix+"Content-Length: 0\r\n\r\n0\r\n\r\n",prefix+"\r\nffffffffffffffff\r\n",prefix+"\r\n0\r\n\r\nextra",prefix+"\r\n1\r\naX\n0\r\n\r\n"] {
            XCTAssertThrowsError(try MigrationObserverMCPReader.response(Data(text.utf8),id:"fixture"))
        }
    }
    func testClosedConsentBindingCarriesExactOrdinaryAuthorization() throws {
        let binding = try MigrationObserverConsentBinding(["sessionID":"owned-session", "purpose":"inspect management", "grantID":"approved-grant"])
        XCTAssertEqual(binding.arguments["sessionId"] as? String, "owned-session")
        XCTAssertEqual(binding.arguments["purpose"] as? String, "inspect management")
        XCTAssertEqual(binding.arguments["grantId"] as? String, "approved-grant")
        XCTAssertNil(binding.arguments["nativeHuman"])
        for value: [String: Any] in [[:], ["sessionID":"s", "purpose":""], ["sessionID":"s", "purpose":"p", "nativeHuman":true], ["sessionID":"s", "purpose":"p", "grantID":false]] {
            XCTAssertThrowsError(try MigrationObserverConsentBinding(value))
        }
    }
    func testEnrollmentRejectsRemoteResourcesAndUnpinnedBrokers()throws {
        let pin="identifier \"com.viant.mechanize.broker\" and cdhash H\""+String(repeating:"a",count:40)+"\""
        XCTAssertThrowsError(try MigrationObserverReaderEnrollment(port:4987,brokerPID:1,brokerStart:"1:2",brokerRequirement:pin,credentialURL:URL(string:"https://example.test/token")!,credentialSHA256:String(repeating:"b",count:64),consentBinding:try MigrationObserverConsentBinding(sessionID:"fixture-session",purpose:"inspect management")))
        XCTAssertThrowsError(try MigrationObserverReaderEnrollment(port:4987,brokerPID:1,brokerStart:"1:2",brokerRequirement:"untrusted",credentialURL:URL(fileURLWithPath:"/private/fixture/token"),credentialSHA256:String(repeating:"b",count:64),consentBinding:try MigrationObserverConsentBinding(sessionID:"fixture-session",purpose:"inspect management")))
    }
}
