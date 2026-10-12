import Foundation
import XCTest
@testable import ConsentCore

final class BrokerEndpointTests: XCTestCase {
    func testMissingSocketIsUnavailableButUnsafePathStillRejected() throws {
        let home = URL(fileURLWithPath: "/private/tmp").appendingPathComponent("mechanize-endpoint-" + UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: home) }
        let runtime = home.appendingPathComponent("Library/Application Support/Mechanize/runtime")
        try FileManager.default.createDirectory(at: runtime, withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700])
        XCTAssertThrowsError(try UnixBrokerTransport.validateEndpoint(home: home.path)) {
            guard case BrokerTransportError.unavailable = $0 else { return XCTFail("Missing socket misreported as unsafe") }
        }
        let endpoint = runtime.appendingPathComponent("consent.sock")
        try FileManager.default.createSymbolicLink(atPath: endpoint.path, withDestinationPath: "/private/tmp/missing-endpoint")
        XCTAssertThrowsError(try UnixBrokerTransport.validateEndpoint(home: home.path)) {
            guard case BrokerTransportError.unsafeEndpoint = $0 else { return XCTFail("Symlink was treated as unavailable") }
        }
        try FileManager.default.removeItem(at: endpoint)
        try FileManager.default.setAttributes([.posixPermissions: 0o777], ofItemAtPath: runtime.path)
        XCTAssertThrowsError(try UnixBrokerTransport.validateEndpoint(home: home.path)) {
            guard case BrokerTransportError.unsafeEndpoint = $0 else { return XCTFail("Unsafe parent was hidden by missing socket") }
        }
    }
}
