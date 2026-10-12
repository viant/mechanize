import XCTest
@testable import ConsentCore

final class VaultRecordFrameTests: XCTestCase {
    private func record(key: Data = Data("arbitrary/key".utf8), fields: [(name: Data, value: Data)] = [
        (Data("login".utf8), Data("fixture-user".utf8)), (Data("token".utf8), Data([0, 255, 66]))
    ]) throws -> VaultRecordFrame {
        var ownedKey = key, ownedFields = fields
        let value = try VaultRecordFrame(key: &ownedKey, fields: &ownedFields)
        XCTAssertTrue(ownedKey.isEmpty); XCTAssertTrue(ownedFields.isEmpty)
        return value
    }
    func testExactGoldenMatchesGoRecordFrameV2AndPreservesOrder() throws {
        let value = try record()
        // Same literal as vault/record_frame_test.go: 74 bytes, payload 62.
        let golden = "4d564c54000000020000003e0000000d6172626974726172792f6b657900000002000000056c6f67696e0000000c666978747572652d7573657200000005746f6b656e0000000300ff42"
        var calls = 0
        try value.writeOnce { bytes in
            calls += 1; XCTAssertEqual(bytes.count, 74)
            XCTAssertEqual(bytes.map { String(format: "%02x", $0) }.joined(), golden)
        }
        XCTAssertEqual(calls, 1)
        XCTAssertThrowsError(try value.writeOnce { _ in XCTFail("Replayed record") }) {
            guard case VaultRecordFrameError.alreadyConsumed = $0 else { return XCTFail("Replay classification changed") }
        }
    }
    func testArbitraryBinaryKeyNamesAndValuesAreNeverTextNormalized() throws {
        let value = try record(key: Data([0,255]), fields: [(Data([255,0]),Data([0,128,255])),(Data([255,1]),Data([1]))])
        try value.writeOnce { frame in
            XCTAssertEqual(Array(frame), [77,86,76,84,0,0,0,2,0,0,0,34,0,0,0,2,0,255,0,0,0,2,0,0,0,2,255,0,0,0,0,3,0,128,255,0,0,0,2,255,1,0,0,0,1,1])
        }
    }
    func testInvalidInputsAreConsumedWithoutProducingAFrame() {
        let fixtures: [(Data, [(name: Data, value: Data)])] = [
            (Data(), [(Data([1]),Data([2]))]),
            (Data(repeating:1,count:1025), [(Data([1]),Data([2]))]),
            (Data([1]), []),
            (Data([1]), (0..<33).map { (Data([UInt8($0)]),Data([1])) }),
            (Data([1]), [(Data(),Data([1]))]),
            (Data([1]), [(Data(repeating:1,count:257),Data([1]))]),
            (Data([1]), [(Data([1]),Data())]),
            (Data([1]), [(Data([0,255]),Data([1])),(Data([0,255]),Data([2]))]),
            (Data([1]), [(Data([1]),Data(repeating:1,count:65507))])
        ]
        for fixture in fixtures {
            var key = fixture.0, fields = fixture.1
            XCTAssertThrowsError(try VaultRecordFrame(key: &key, fields: &fields)) {
                guard case VaultRecordFrameError.invalidInput = $0 else { return XCTFail("Unsafe input error") }
            }
            XCTAssertTrue(key.isEmpty); XCTAssertTrue(fields.isEmpty)
        }
    }
    func testCompleteFrameLimitIncludesHeaderAndLengthWords() throws {
        // 12-byte header + 18 bytes of payload structure/key/name + value.
        let value = try record(key:Data([1]),fields:[(Data([2]),Data(repeating:3,count:65506))])
        try value.writeOnce { frame in
            XCTAssertEqual(frame.count,65536)
            XCTAssertEqual(Array(frame[8..<12]),[0,0,255,244])
        }
        let maximalFields = try record(key:Data(repeating:1,count:1024),fields:(0..<32).map { (Data(repeating:UInt8($0),count:256),Data([1])) })
        try maximalFields.writeOnce { XCTAssertLessThan($0.count,65536) }
    }
    func testCopiesShareConsumptionIncludingTransportFailureAndReentrancy() throws {
        let value = try record(), alias = value
        struct PrivateFailure: Error, CustomStringConvertible { var description:String { "private-transport-canary" } }
        XCTAssertThrowsError(try value.writeOnce { _ in
            XCTAssertThrowsError(try alias.writeOnce { _ in XCTFail("Reentrant replay") })
            throw PrivateFailure()
        }) {
            guard case VaultRecordFrameError.transportUnavailable = $0 else { return XCTFail("Transport details escaped") }
            XCTAssertFalse(String(reflecting:$0).contains("canary")); XCTAssertFalse($0.localizedDescription.contains("canary"))
        }
        XCTAssertThrowsError(try alias.writeOnce { _ in XCTFail("Failure replay") })
        let cancelled = try record(), cancelledAlias = cancelled
        cancelled.destroy()
        XCTAssertThrowsError(try cancelledAlias.writeOnce { _ in XCTFail("Destroyed input replay") })
    }
    func testDescriptionsReflectionAndJSONExposeNoSecrets() throws {
        let value = try record(key:Data("private-key-canary".utf8),fields:[(Data("private-name-canary".utf8),Data("private-value-canary".utf8))])
        let opaque: Any = value
        XCTAssertFalse(opaque is any Encodable); XCTAssertFalse(JSONSerialization.isValidJSONObject(["record":opaque]))
        XCTAssertTrue(Mirror(reflecting:value).children.isEmpty)
        var dumpText = ""; dump(value,to:&dumpText)
        for text in [String(describing:value),String(reflecting:value),"\(value)",dumpText] {
            XCTAssertFalse(text.contains("private-"))
        }
        value.destroy()
    }
    func testOwnedInputAllocationsAreWipedOnEveryLifetimeExit() throws {
        for mode in ["success", "transportFailure", "destroy", "deinit", "invalid"] {
            let tracker = RecordFrameWipeTracker()
            var key = tracker.data(count: 512, byte: 91)
            var fields = [(name: tracker.data(count: 64, byte: 92), value: tracker.data(count: 1024, byte: 93))]
            if mode == "invalid" {
                fields.append((tracker.data(count: 64, byte: 92), tracker.data(count: 512, byte: 94)))
                XCTAssertThrowsError(try VaultRecordFrame(key: &key, fields: &fields))
            } else {
                var value: VaultRecordFrame? = try VaultRecordFrame(key: &key, fields: &fields)
                if mode == "destroy" { value?.destroy() }
                else if mode == "success" { try value?.writeOnce { _ in XCTAssertEqual(tracker.releases, 3) } }
                else if mode == "transportFailure" {
                    XCTAssertThrowsError(try value?.writeOnce { _ in
                        XCTAssertEqual(tracker.releases, 3)
                        throw VaultRecordFrameError.invalidInput
                    })
                }
                value = nil
            }
            XCTAssertTrue(key.isEmpty); XCTAssertTrue(fields.isEmpty)
            XCTAssertEqual(tracker.releases, mode == "invalid" ? 5 : 3)
            XCTAssertTrue(tracker.everyReleaseWasZero)
        }
    }
    func testConcurrentCopiesPermitExactlyOneWrite() throws {
        let value = try record()
        let count = RecordFrameCounter()
        DispatchQueue.concurrentPerform(iterations:16) { _ in
            do { try value.writeOnce { _ in count.increment() } }
            catch { guard case VaultRecordFrameError.alreadyConsumed = error else { return XCTFail("Unexpected concurrent error") } }
        }
        XCTAssertEqual(count.value,1)
    }
}
private final class RecordFrameCounter: @unchecked Sendable {
    private let lock = NSLock()
    private var count = 0
    func increment() { lock.lock(); count += 1; lock.unlock() }
    var value:Int { lock.lock(); defer { lock.unlock() }; return count }
}

/// Observes memory only from Data's deallocator while it is still valid, never
/// by retaining a borrowed callback pointer or reading freed memory.
private final class RecordFrameWipeTracker {
    var releases = 0
    var everyReleaseWasZero = true
    func data(count: Int, byte: UInt8) -> Data {
        let pointer = UnsafeMutableRawPointer.allocate(byteCount: count, alignment: 1)
        pointer.initializeMemory(as: UInt8.self, repeating: byte, count: count)
        return Data(bytesNoCopy: pointer, count: count, deallocator: .custom { pointer, length in
            self.releases += 1
            self.everyReleaseWasZero = self.everyReleaseWasZero && UnsafeRawBufferPointer(start: pointer, count: length).allSatisfy { $0 == 0 }
            pointer.deallocate()
        })
    }
}
