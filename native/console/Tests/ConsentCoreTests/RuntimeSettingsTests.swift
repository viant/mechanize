import XCTest
@testable import ConsentCore

final class RuntimeSettingsTests: XCTestCase {
    private func state(address: String = "127.0.0.1:4987", saved: Int = 5100, restart: Bool = true) -> RuntimeSettingsSnapshot {
        RuntimeSettingsSnapshot(transport: "http", currentAddress: address, currentPort: 4987, savedPort: saved, revision: 1, restartRequired: restart)
    }
    func testLocalEndpointAndRestartConsistency() {
        XCTAssertTrue(state().isValid)
        XCTAssertTrue(state(address: "[::1]:4987").isValid)
        XCTAssertTrue(state(saved: 4987, restart: false).isValid)
        for address in ["0.0.0.0:4987", "example.test:4987", "user:password@127.0.0.1:4987", "127.0.0.1:4987/path", "127.0.0.1:5000"] { XCTAssertFalse(state(address: address).isValid) }
        XCTAssertFalse(state(saved: 0).isValid)
        XCTAssertFalse(state(restart: false).isValid)
        XCTAssertTrue(RuntimeSettingsSnapshot(transport: "stdio", currentAddress: "", currentPort: 0, savedPort: 0, revision: 0, restartRequired: false).isValid)
    }
}
