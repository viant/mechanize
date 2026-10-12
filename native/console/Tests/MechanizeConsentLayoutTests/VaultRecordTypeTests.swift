import XCTest
import ConsentCore
@testable import MechanizeConsent

@MainActor final class VaultRecordTypeTests:XCTestCase {
    func testTypesMirrorScyCLIAndTypeChangeClearsEveryControl() throws {
        XCTAssertEqual(VaultRecordSecretType.allCases.map(\.rawValue),["raw","basic","sha1","aws","ssh","generic","jwt","oauth2","key","certificate","x509"])
        let input=VaultRecordInput();XCTAssertEqual(input.type,.raw)
        input.key="synthetic";input.secret="synthetic";input.username="synthetic";input.password="synthetic";input.endpoint="synthetic";input.email="synthetic";input.keyName="synthetic";input.keySecret="synthetic";input.payload="synthetic"
        input.selectType(.basic)
        XCTAssertTrue([input.key,input.secret,input.username,input.password,input.endpoint,input.email,input.keyName,input.keySecret,input.payload].allSatisfy(\.isEmpty))
    }
    func testTypedFramesPreserveDeployedBasicFieldsAndAvoidDuplicatedPayload() throws {
        for type in VaultRecordSecretType.allCases {
            let input=VaultRecordInput();input.selectType(type);input.key="fixture-record"
            switch type {case .raw:input.secret="fixture-secret";case .basic:input.username="fixture-user";input.password="fixture-password";input.email="fixture@example.invalid";case .key:input.keyName="FIXTURE";input.keySecret="fixture-secret";default:input.payload="{\"fixture\":\"value\"}"}
            let frame=try input.takeFrame();defer{frame.destroy()}
            var data=Data();try frame.writeOnce{data.append(contentsOf:$0)};defer{data.resetBytes(in:0..<data.count)}
            let parsed=try decodeSynthetic(data)
            XCTAssertEqual(parsed["$scy.type"],type.rawValue)
            switch type {
            case .raw:XCTAssertEqual(Set(parsed.keys),["$scy.type","secret"])
            case .basic:XCTAssertEqual(Set(parsed.keys),["$scy.type","username","password","email"]);XCTAssertNil(parsed["$scy.payload"])
            case .key:XCTAssertEqual(Set(parsed.keys),["$scy.type","Key","Secret"])
            default:XCTAssertEqual(Set(parsed.keys),["$scy.type","$scy.payload"])
            }
            XCTAssertTrue(input.key.isEmpty);XCTAssertFalse(input.complete)
        }
    }
    func testInvalidStructuredPayloadClearsInputWithoutRawError() {
        let input=VaultRecordInput();input.selectType(.jwt);input.key="fixture";input.payload="not-json-fixture"
        XCTAssertThrowsError(try input.takeFrame()){XCTAssertEqual($0.localizedDescription,VaultRecordFrameError.invalidInput.localizedDescription)}
        XCTAssertTrue(input.key.isEmpty);XCTAssertTrue(input.payload.isEmpty)
    }
    private func decodeSynthetic(_ data:Data)throws->[String:String] {
        // Test-only parsing of inert synthetic inputs; production has no getter.
        var offset=12
        func number()throws->Int {guard offset+4<=data.count else{throw VaultRecordFrameError.invalidInput};defer{offset+=4};return data[offset..<offset+4].reduce(0){($0<<8)|Int($1)}}
        func bytes()throws->String {let n=try number();guard offset+n<=data.count else{throw VaultRecordFrameError.invalidInput};defer{offset+=n};return String(decoding:data[offset..<offset+n],as:UTF8.self)}
        _=try bytes();let count=try number();var result:[String:String]=[:]
        for _ in 0..<count{let name=try bytes(),value=try bytes();result[name]=value};return result
    }
}
