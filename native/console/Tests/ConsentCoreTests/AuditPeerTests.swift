import XCTest
import Darwin
import Security
@testable import ConsentCore

final class AuditPeerTests: XCTestCase {
    func testKernelAuditPeerSignatureAndUID() throws {
        // A disposable local socket between this signed test process and itself;
        // no desktop API, enrollment credential, Keychain item or user app.
        var ownCode: SecCode?
        XCTAssertEqual(SecCodeCopySelf([], &ownCode), errSecSuccess)
        let code = try XCTUnwrap(ownCode)
        var ownStaticCode: SecStaticCode?
        XCTAssertEqual(SecCodeCopyStaticCode(code, [], &ownStaticCode), errSecSuccess)
        let staticCode = try XCTUnwrap(ownStaticCode)
        var information: CFDictionary?
        XCTAssertEqual(SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &information), errSecSuccess)
        let details = try XCTUnwrap(information) as NSDictionary
        let digest = try XCTUnwrap(details[kSecCodeInfoUnique] as? Data)
        let hash = digest.map { String(format: "%02x", $0) }.joined()
        XCTAssertEqual(hash.count, 40)
        let requirement = "cdhash H\"\(hash)\""

        let folder = URL(fileURLWithPath: "/private/tmp").appendingPathComponent("mechanize-peer-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: folder) }
        let path = folder.appendingPathComponent("s").path
        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        let name = Array(path.utf8CString)
        XCTAssertLessThanOrEqual(name.count, MemoryLayout.size(ofValue: address.sun_path))
        withUnsafeMutableBytes(of: &address.sun_path) { bytes in
            for (index, value) in name.enumerated() { bytes[index] = UInt8(bitPattern: value) }
        }
        let listener = socket(AF_UNIX, SOCK_STREAM, 0)
        XCTAssertGreaterThanOrEqual(listener, 0)
        defer { Darwin.close(listener) }
        let bound = withUnsafePointer(to: &address) { ptr in ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.bind(listener, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) } }
        XCTAssertEqual(bound, 0)
        XCTAssertEqual(listen(listener, 1), 0)
        let client = socket(AF_UNIX, SOCK_STREAM, 0)
        XCTAssertGreaterThanOrEqual(client, 0)
        defer { Darwin.close(client) }
        let connected = withUnsafePointer(to: &address) { ptr in ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.connect(client, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) } }
        XCTAssertEqual(connected, 0)
        let accepted = accept(listener, nil, nil)
        XCTAssertGreaterThanOrEqual(accepted, 0)
        defer { Darwin.close(accepted) }

        let exact = try SignedBrokerPeer(designatedRequirement: requirement, expectedUID: getuid())
        XCTAssertNoThrow(try exact.authenticate(socket: client))
        XCTAssertNoThrow(try exact.authenticate(socket: accepted))
        let wrongUID = try SignedBrokerPeer(designatedRequirement: requirement, expectedUID: getuid() + 1)
        XCTAssertThrowsError(try wrongUID.authenticate(socket: client))
        let wrongCode = try SignedBrokerPeer(designatedRequirement: "cdhash H\"0000000000000000000000000000000000000000\"", expectedUID: getuid())
        XCTAssertThrowsError(try wrongCode.authenticate(socket: client))
    }
}
