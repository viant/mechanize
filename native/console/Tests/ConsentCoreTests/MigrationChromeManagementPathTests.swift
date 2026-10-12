import XCTest
@testable import ConsentCore

final class MigrationChromeManagementPathTests: XCTestCase {
    let id = String(repeating: "a", count: 32)
    let shape: [(String, Int?)] = [("AXWindow",nil),("AXWebArea",0),("AXGroup",1),
        ("AXHeading",2),("AXGroup",2),("AXHeading",2),("AXGroup",2),("AXHeading",2),("AXGroup",2),("AXGroup",2),
        ("AXStaticText",3),("AXStaticText",4),("AXStaticText",5),("AXStaticText",6),("AXStaticText",7),
        ("AXStaticText",8),("AXStaticText",9),("AXLink",9),("AXStaticText",17)]
    func object() -> [String: Any] {
        let at = ISO8601DateFormatter().string(from: Date().addingTimeInterval(-1))
        return ["truncated":false,"started":at,"ended":at,"surface":["kind":"native","bundleId":"com.google.Chrome","processId":42,"processStartToken":"1:2"],"windowScope":["title":"Extensions","role":"AXWindow"],"nodes":shape.enumerated().map { index,pair -> [String:Any] in
            var row:[String:Any] = ["ref":["id":"n\(index)"],"nativeRole":pair.0,"nativeOwnerMatchesRoot":true,"nativeOwnerProcessId":42,"nativeOwnerStartToken":"1:2","nativeOwnerBundleId":"com.google.Chrome","nativeOwnerUid":getuid()]
            if let parent=pair.1 {row["parentId"]="n\(parent)"}; return row
        }]
    }
    func receipt(_ object:[String:Any]? = nil) throws -> MigrationManagementReceipt {
        try MigrationManagementReceipt(JSONSerialization.data(withJSONObject: object ?? self.object()),pid:42,birth:"1:2",title:"Extensions")
    }
    func testIdentifierlessCompleteManagementTreeReadsOnlySectionLabelsAndSelectedValues() throws {
        let r = try receipt(); var reads:[Int]=[]
        let values = [10:"Description",11:"Loaded from /description-lookalike",12:"ID",13:id,14:"Source",15:"Unpacked extension",16:"Loaded from",18:"/private/fixture/extension"]
        let path = try r.path(local:r.nodes,address:"chrome://extensions/?id=\(id)",extensionID:id) { i in reads.append(i); return values[i] ?? "unavailable" }
        XCTAssertEqual(path,"/private/fixture/extension")
        XCTAssertEqual(Set(reads),Set([10,12,13,14,16,18]))
        XCTAssertFalse(reads.contains(11)); XCTAssertFalse(reads.contains(15))
        XCTAssertTrue(r.nodes.allSatisfy{$0.identifier.isEmpty})
    }
    func testWrongPageOrMismatchedGraphCannotInvokeValueReader() throws {
        let r = try receipt()
        for address in ["https://lookalike.invalid/?id=\(id)","chrome://extensions/","chrome://extensions/?id=\(String(repeating:"b",count:32))"] {
            XCTAssertThrowsError(try r.path(local:r.nodes,address:address,extensionID:id){_ in XCTFail("read before provenance");return ""})
        }
        var changed=r.nodes;changed[9] = .init(role:"AXGroup",identifier:"",parent:4)
        XCTAssertThrowsError(try r.path(local:changed,address:"chrome://extensions/?id=\(id)",extensionID:id){_ in XCTFail("read before graph match");return ""})
    }
    func testRejectsIncompleteNestedForeignAndStaleReceipts() throws {
        for mode in ["truncated","nested","foreign","stale","missing owner","unavailable"] {
            var o=object(), rows=o["nodes"] as! [[String:Any]]
            switch mode {
            case "truncated":o["truncated"]=true
            case "nested":rows[4]["nativeRole"]="AXWebArea"
            case "foreign":rows[18]["nativeOwnerProcessId"]=43
            case "stale":o["started"]=ISO8601DateFormatter().string(from:Date().addingTimeInterval(-31))
            case "missing owner":rows[18].removeValue(forKey:"nativeOwnerMatchesRoot")
            default:rows[18]["unavailable"]=["children"]
            }
            o["nodes"]=rows;XCTAssertThrowsError(try receipt(o),mode)
        }
    }
    func testRejectsDescriptionSpoofWrongIDAndIncompletePath() throws {
        let r=try receipt()
        for mode in ["wrong ID","relative","truncated path","wrong heading","wrong label","ambiguous headings"] {
            var values=[10:"Description",12:"ID",13:id,14:"Source",16:"Loaded from",18:"/private/fixture/extension"]
            switch mode {
            case "wrong ID":values[13]=String(repeating:"b",count:32)
            case "relative":values[18]="../extension"
            case "truncated path":values[18]="/private/…/extension"
            case "wrong heading":values[12]="Description"
            case "ambiguous headings":values[10]="ID"
            default:values[16]="Other"
            }
            XCTAssertThrowsError(try r.path(local:r.nodes,address:"chrome://extensions/?id=\(id)",extensionID:id){values[$0] ?? "Loaded from"},mode)
        }
    }
    func testHomeDisplayNormalizationIsExactAndRejectsTraversalAndTruncation() throws {
        XCTAssertEqual(try MigrationLoadedPath.normalize("~/go/src/extension",home:{"/Users/fixture"}),"/Users/fixture/go/src/extension")
        XCTAssertEqual(try MigrationLoadedPath.normalize("/private/fixture/extension",home:{XCTFail("absolute path need not resolve home");return ""}),"/private/fixture/extension")
        for value in ["~","~/","~other/path","~/../extension","~/./extension","~//extension","~/a/../../extension","~/a/…/extension","~/a/.../extension","~/a\nextension","file:///Users/fixture/extension","/a/../b","/a//b","relative"] {
            XCTAssertThrowsError(try MigrationLoadedPath.normalize(value,home:{"/Users/fixture"}),value)
        }
        XCTAssertThrowsError(try MigrationLoadedPath.normalize("~/extension",home:{"/Users/fixture/../other"}))
        XCTAssertTrue(try MigrationRuntimeConsoleManifest.path(MigrationLoadedPath.userHome()))
    }
}
