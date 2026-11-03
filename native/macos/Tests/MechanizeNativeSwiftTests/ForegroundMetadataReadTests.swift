import AppKit
import ApplicationServices
import Testing
@testable import MechanizeNative
import MechanizeNativeCore

struct ForegroundMetadataReadTests {
    @Test func scopedProofDoesNotInheritSnapshotTimeout() throws {
        let element=AXUIElementCreateApplication(42_000)
        var timeout:Float=0,reads=0
        let result=try readForegroundMetadata(element,attribute:kAXRoleAttribute,budget:Budget(milliseconds:1000),read:{candidate,name in
            #expect(CFEqual(candidate,element) && name==kAXRoleAttribute)
            reads+=1
            return timeout>=0.12 ? (.success,kAXMenuItemRole as CFString):(.cannotComplete,nil)
        },setTimeout:{_,value in timeout=value;return .success})
        #expect(timeout==0.25 && reads==1 && result.0 == .success)
    }
    @Test func originalDeadlineAndNativeFailureRemainAuthoritative() throws {
        var timeout:Float=0,reads=0
        let result=try readForegroundMetadata(AXUIElementCreateApplication(42_000),attribute:kAXWindowAttribute,budget:Budget(milliseconds:20),read:{_,_ in reads+=1;return (.cannotComplete,nil)},setTimeout:{_,value in timeout=value;return .success})
        #expect(timeout>0 && timeout<=0.02 && reads==1 && result.0 == .cannotComplete && result.1==nil)
        #expect(throws:(any Error).self){
            try readForegroundMetadata(AXUIElementCreateApplication(42_000),attribute:kAXRoleAttribute,budget:Budget(milliseconds:1),read:{_,_ in Thread.sleep(forTimeInterval:0.005);return (.success,kAXWindowRole as CFString)},setTimeout:{_,_ in .success})
        }
    }
    @Test func unavailableTimeoutNeverReadsOrSynthesizesEvidence() {
        var reads=0
        do {
            _=try readForegroundMetadata(AXUIElementCreateApplication(42_000),attribute:kAXRoleAttribute,budget:Budget(milliseconds:1000),read:{_,_ in reads+=1;return (.success,kAXWindowRole as CFString)},setTimeout:{_,_ in .cannotComplete})
            Issue.record("Unavailable timeout accepted")
        } catch let failure as NativeFailure {#expect(failure.code=="foregroundMetadataTimeoutUnavailable")}
        catch {Issue.record("Unexpected error")}
        #expect(reads==0)
    }
}
