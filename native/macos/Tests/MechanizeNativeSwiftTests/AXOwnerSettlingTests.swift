import AppKit
import ApplicationServices
import Testing
@testable import MechanizeNative
import MechanizeNativeCore

struct AXOwnerSettlingTests {
    let element=AXUIElementCreateApplication(42_000)
    func valid(pid:pid_t=42,uid:uid_t=502,birth:String="100:1",bundle:String="com.example.Editor")->AXElementOwner {
        AXElementOwner(pid:pid,uid:uid,birth:birth,bundle:bundle,status:AXError.success.rawValue)
    }
    func missing(_ status:AXError = .cannotComplete)->AXElementOwner {
        AXElementOwner(pid:nil,uid:nil,birth:nil,bundle:nil,status:status.rawValue)
    }
    func check(_ budget:Budget?=nil,read:(AXUIElement)->AXElementOwner,pause:(TimeInterval)->Void={_ in})throws {
        let activeBudget = try budget ?? Budget(milliseconds:500)
        try requireAXElementOwner(element,pid:42,uid:502,birth:"100:1",bundle:"com.example.Editor",budget:activeBudget,owner:read,pause:pause)
    }
    @Test func temporaryMissingMetadataRequiresCompleteFreshProof() throws {
        for first in [missing(),AXElementOwner(pid:42,uid:nil,birth:"100:1",bundle:"com.example.Editor",status:AXError.success.rawValue)] {
            var reads=0,pauses=0
            try check(read:{candidate in
                #expect(CFEqual(candidate,element));reads+=1
                return reads==1 ? first:valid()
            },pause:{duration in #expect(duration>0 && duration<=0.015);pauses+=1})
            #expect(reads==2 && pauses==1)
        }
        var reads=0
        try check(read:{_ in reads+=1;return valid()})
        #expect(reads==1)
    }
    @Test func knownForeignOwnerAndChangedBirthNeverRetry() {
        for foreign in [valid(pid:43),valid(uid:503),valid(birth:"100:2"),valid(bundle:"com.example.Other")] {
            var reads=0
            do {try check(read:{_ in reads+=1;return foreign});Issue.record("Foreign owner accepted")}
            catch let failure as NativeFailure {#expect(failure.code=="foregroundAXOwnerMismatch")}
            catch {Issue.record("Unexpected error")}
            #expect(reads==1)
        }
        var reads=0
        do {try check(read:{_ in reads+=1;return reads==1 ? missing():valid(pid:43)});Issue.record("Owner change accepted")}
        catch let failure as NativeFailure {#expect(failure.code=="foregroundAXOwnerMismatch")}
        catch {Issue.record("Unexpected error")}
        #expect(reads==2)
    }
    @Test func unavailableAndInvalidReferenceStayBounded() {
        for status in [AXError.cannotComplete,AXError.invalidUIElement] {
            var reads=0
            do {try check(read:{_ in reads+=1;return missing(status)});Issue.record("Unavailable owner accepted")}
            catch let failure as NativeFailure {#expect(failure.code=="foregroundAXOwnerUnavailable")}
            catch {Issue.record("Unexpected error")}
            #expect(reads==(status == .cannotComplete ? 3:1))
        }
        var reads=0
        #expect(throws:(any Error).self){
            try check(Budget(milliseconds:1),read:{_ in reads+=1;return missing()},pause:{_ in Thread.sleep(forTimeInterval:0.005)})
        }
        #expect(reads<=1)
    }
}
