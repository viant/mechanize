import Foundation
import Darwin
import Testing
@testable import MechanizeNative
import MechanizeNativeCore

struct ApplicationLookupTests {
    let params: [String: Any] = ["expectedApp":"com.fixture.editor","pid":42,"startToken":"1790000000:1","launchTime":"kernel:1790000000:1"]
    func entry(pid: pid_t = 42, bundle: String? = "com.fixture.editor", owner: uid_t? = getuid(), token: String? = "1790000000:1", terminated: Bool = false) -> ApplicationInventoryEntry {
        ApplicationInventoryEntry(pid:pid,bundleID:bundle,name:"Fixture",owner:owner,launchTime:nil,startToken:token,active:true,terminated:terminated)
    }
    @Test func exactLiveProcessDoesNotDependOnAnApplicationList() throws {
        var reads = 0
        let result = try exactApplicationInventory(params, runtime: ApplicationLookupRuntime(exited:{_ in false},entry:{pid in reads += 1; #expect(pid == 42); return entry()}))
        #expect(reads == 1 && result["complete"] as? Bool == true)
        #expect((result["apps"] as? [[String:Any]])?.first?["startToken"] as? String == "1790000000:1")
    }
    @Test func missingMetadataIsNotEvidenceOfExit() {
        for app in [nil, entry(bundle:nil), entry(bundle:""), entry(owner:nil), entry(token:nil), entry(terminated:true)] {
            do {
                _ = try exactApplicationInventory(params,runtime:ApplicationLookupRuntime(exited:{_ in false},entry:{_ in app}))
                Issue.record("Missing metadata accepted")
            } catch let failure as NativeFailure { #expect(failure.code == "incompleteObservation") }
            catch { Issue.record("Unexpected failure") }
        }
    }
    @Test func knownContradictionIsNotHiddenByOtherMissingMetadata() {
        for app in [entry(pid:43),entry(bundle:"com.other.editor"),entry(bundle:nil,owner:getuid()+1),entry(owner:nil,token:"1790000000:2")] {
            do {
                _ = try exactApplicationInventory(params,runtime:ApplicationLookupRuntime(exited:{_ in false},entry:{_ in app}))
                Issue.record("Changed identity accepted")
            } catch let failure as NativeFailure { #expect(failure.code == "staleReference") }
            catch { Issue.record("Unexpected failure") }
        }
    }
    @Test func onlyIndependentExitProofReturnsAnEmptyCompleteInventory() throws {
        let result = try exactApplicationInventory(params,runtime:ApplicationLookupRuntime(exited:{_ in true},entry:{_ in Issue.record("Exited PID looked up");return nil}))
        #expect(result["complete"] as? Bool == true)
        #expect((result["apps"] as? [Any])?.isEmpty == true)
        do {
            _ = try exactApplicationInventory(params,runtime:ApplicationLookupRuntime(exited:{_ in nil},entry:{_ in Issue.record("Unknown process looked up");return entry()}))
            Issue.record("Unavailable liveness accepted")
        } catch let failure as NativeFailure { #expect(failure.code == "incompleteObservation") }
    }
}
