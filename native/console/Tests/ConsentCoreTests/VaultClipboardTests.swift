import XCTest
@testable import ConsentCore

private final class ClipboardFixture: VaultClipboardSource {
    var changeCount = 1, reads = 0, clears = 0
    var value = Data("fixture-only-secret".utf8)
    func readUTF8() -> Data? { reads += 1; return value }
    func clear(ifUnchanged revision: Int) {
        if revision == changeCount { clears += 1; value.removeAll() }
    }
}

final class VaultClipboardTests: XCTestCase {
    func testProtectionGateNeverReadsClipboard() {
        for gate in [(false,true,false),(true,false,false),(true,true,true)] {
            let source=ClipboardFixture()
            XCTAssertEqual(VaultClipboard.importLocally(source:source,secureCaptureSuppressionConfirmed:gate.0,requestValid:gate.1,submitting:gate.2,consume:{_ in XCTFail("must not consume")}),.protectionUnavailable)
            XCTAssertEqual(source.reads,0);XCTAssertEqual(source.clears,0)
        }
    }
    func testLocalConsumptionAndConditionalClearingReturnStatusOnly() {
        let source=ClipboardFixture();var consumed=false
        XCTAssertEqual(VaultClipboard.importLocally(source:source,secureCaptureSuppressionConfirmed:true,requestValid:true,submitting:false,consume:{data in
            consumed = data == source.value
        }),.imported)
        XCTAssertTrue(consumed);XCTAssertEqual(source.clears,1)
        let changed=ClipboardFixture()
        XCTAssertEqual(VaultClipboard.importLocally(source:changed,secureCaptureSuppressionConfirmed:true,requestValid:true,submitting:false,consume:{_ in changed.changeCount += 1}),.imported)
        XCTAssertEqual(changed.clears,0)
    }
    func testMalformedOversizedAndCallbackFailureExposeNoBytes() {
        for value in [Data(),Data([0]),Data([255]),Data(repeating:65,count:65_537)] {
            let source=ClipboardFixture();source.value=value
            XCTAssertEqual(VaultClipboard.importLocally(source:source,secureCaptureSuppressionConfirmed:true,requestValid:true,submitting:false,consume:{_ in XCTFail("invalid clipboard")}),.invalidInput)
            XCTAssertEqual(source.clears,0)
        }
        let source=ClipboardFixture()
        XCTAssertEqual(VaultClipboard.importLocally(source:source,secureCaptureSuppressionConfirmed:true,requestValid:true,submitting:false,consume:{_ in throw NSError(domain:"fixture secret payload",code:1)}),.unavailable)
        XCTAssertEqual(source.clears,0)
    }
}
