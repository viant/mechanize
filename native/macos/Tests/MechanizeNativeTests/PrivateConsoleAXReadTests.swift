import XCTest
import ApplicationServices
import MechanizeNativeCore
@testable import MechanizeNative

final class PrivateConsoleAXReadTests:XCTestCase {
    func testBusyReadRetriesOnceWithBoundedTimeoutAndFreshOwnerChecks()throws {
        let element=AXUIElementCreateApplication(42000);var reads=0,owners=0,timeouts:[Float]=[]
        let runtime=PrivateConsoleAXRuntime(owner:{_ in owners+=1;return(.success,42000)},timeout:{_,value in timeouts.append(value);return .success},read:{_,name in
            XCTAssertEqual(name,kAXWindowsAttribute);reads+=1
            return reads==1 ? (.cannotComplete,nil):(.success,NSArray())
        })
        _=try privateConsoleAXValue(element,kAXWindowsAttribute,pid:42000,budget:Budget(milliseconds:1000),runtime:runtime)
        XCTAssertEqual(reads,2);XCTAssertEqual(owners,4);XCTAssertEqual(timeouts.count,2);XCTAssertTrue(timeouts.allSatisfy{$0>0 && $0<=0.25})
    }
    func testRetryIsBoundedAndNeverWidensShapeOwnershipOrPermission()throws {
        for mode in ["busy","absent","unsupported","illegal","permission","mixed","owner","ownerAfterRead","timeout"] {
            let element=AXUIElementCreateApplication(42000);var reads=0,owners=0
            let runtime=PrivateConsoleAXRuntime(owner:{_ in owners+=1;return(.success,mode=="owner" || mode=="ownerAfterRead" && owners>1 ? 42001:42000)},timeout:{_,_ in mode=="timeout" ? .failure:.success},read:{_,_ in
                reads+=1
                switch mode {
                case "absent":return(.noValue,nil)
                case "unsupported":return(.attributeUnsupported,nil)
                case "illegal":return(.illegalArgument,nil)
                case "permission":return(.apiDisabled,nil)
                case "mixed":return(.cannotComplete,"unexpected" as CFString)
                case "ownerAfterRead":return(.success,NSArray())
                default:return(.cannotComplete,nil)
                }
            })
            XCTAssertThrowsError(try privateConsoleAXValue(element,kAXWindowsAttribute,pid:42000,budget:Budget(milliseconds:1000),runtime:runtime),mode)
            XCTAssertEqual(reads,mode=="busy" ? 2:(mode=="owner" || mode=="timeout" ? 0:1),mode)
        }
    }
    func testExistingBudgetCapsTimeoutAndExpiredBudgetCannotRead()throws {
        let element=AXUIElementCreateApplication(42000);var timeouts:[Float]=[],reads=0
        let runtime=PrivateConsoleAXRuntime(owner:{_ in (.success,42000)},timeout:{_,value in timeouts.append(value);return .success},read:{_,_ in reads+=1;return(.success,NSArray())})
        _=try privateConsoleAXValue(element,kAXWindowsAttribute,pid:42000,budget:Budget(milliseconds:20),runtime:runtime)
        XCTAssertEqual(reads,1);XCTAssertTrue(timeouts.allSatisfy{$0>0 && $0<=0.020})
        let slowOwner=PrivateConsoleAXRuntime(owner:{_ in Thread.sleep(forTimeInterval:0.005);return(.success,42000)},timeout:{_,_ in XCTFail("Expired budget must never set a zero AX timeout");return .success},read:{_,_ in XCTFail("Expired owner check must never read");return(.success,NSArray())})
        XCTAssertThrowsError(try privateConsoleAXValue(element,kAXWindowsAttribute,pid:42000,budget:Budget(milliseconds:1),runtime:slowOwner))
        let expired=try Budget(milliseconds:1);Thread.sleep(forTimeInterval:0.005)
        XCTAssertThrowsError(try privateConsoleAXValue(element,kAXWindowsAttribute,pid:42000,budget:expired,runtime:runtime));XCTAssertEqual(reads,1)
    }
}
