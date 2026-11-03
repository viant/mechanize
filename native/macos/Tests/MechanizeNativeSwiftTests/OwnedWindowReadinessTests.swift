import AppKit
import ApplicationServices
import Testing
@testable import MechanizeNative
import MechanizeNativeCore

struct OwnedWindowReadinessTests {
    @Test func unavailableOwnerCannotQualifyOrHideAContradiction() throws {
        let app=AXUIElementCreateApplication(42),window=AXUIElementCreateApplication(43)
        let cases:[(AXElementOwner,String?)]=[
            (AXElementOwner(pid:42,uid:501,birth:"100:1",bundle:"com.fixture.Editor",status:AXError.success.rawValue),nil),
            (AXElementOwner(pid:nil,uid:nil,birth:nil,bundle:nil,status:AXError.cannotComplete.rawValue),"incompleteObservation"),
            (AXElementOwner(pid:nil,uid:nil,birth:nil,bundle:nil,status:AXError.apiDisabled.rawValue),"permissionDenied"),
            (AXElementOwner(pid:42,uid:nil,birth:"100:1",bundle:"com.fixture.Editor",status:AXError.success.rawValue),"incompleteObservation"),
            (AXElementOwner(pid:99,uid:nil,birth:nil,bundle:nil,status:AXError.cannotComplete.rawValue),"rootOwnerMismatch"),
            (AXElementOwner(pid:42,uid:502,birth:"100:1",bundle:"com.fixture.Editor",status:AXError.success.rawValue),"rootOwnerMismatch"),
            (AXElementOwner(pid:42,uid:501,birth:"100:2",bundle:"com.fixture.Editor",status:AXError.success.rawValue),"rootOwnerMismatch"),
            (AXElementOwner(pid:42,uid:501,birth:"100:1",bundle:"com.fixture.Other",status:AXError.success.rawValue),"rootOwnerMismatch")
        ]
        for (facts,expected) in cases {
            var contentReads=0
            let runtime=ScopedNativeRootRuntime(attribute:{element,name in
                if CFEqual(element,app)&&name==kAXWindowsAttribute{return(.success,[window] as CFArray)}
                contentReads+=1
                return(.success,kAXWindowRole as CFString)
            },owner:{_ in facts})
            do {
                let windows=try OwnedAXWindows.enumerate(application:app,pid:42,uid:501,birth:"100:1",bundle:"com.fixture.Editor",check:{},runtime:runtime)
                #expect(expected==nil && windows.count==1 && contentReads==1)
            } catch let failure as NativeFailure {
                #expect(failure.code==expected)
                #expect(contentReads==0)
                #expect(!failure.message.contains("com.fixture"))
            }
        }
    }
}
