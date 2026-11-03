import Foundation
import Testing
@testable import MechanizeNative
import MechanizeNativeCore

struct ForegroundRefreshTests {
    @Test func queueSchedulingAllowsBusyTurnWithoutExtendingRequestDeadline() throws {
        let normal = try foregroundRefreshWaitNanoseconds(Budget(milliseconds: 1000))
        #expect(normal == 250_000_000)
        let short = try foregroundRefreshWaitNanoseconds(Budget(milliseconds: 20))
        #expect(short > 0 && short <= 20_000_000)
        let expired = try Budget(milliseconds: 1)
        Thread.sleep(forTimeInterval: 0.005)
        #expect(throws: (any Error).self) { try foregroundRefreshWaitNanoseconds(expired) }
    }

    @Test func failedOrLateRefreshNeverReadsCachedForeground() throws {
        for late in [false, true] {
            var reads = 0
            let runtime = ForegroundProofRuntime(refresh: { _ in
                if late { Thread.sleep(forTimeInterval: 0.01) }
                else { throw NativeFailure("foregroundRefreshUnavailable", "synthetic refresh failure") }
            }, current: { reads += 1; return nil }, corroborate: { nil })
            do {
                _ = try qualifiedForeground(nil, Budget(milliseconds: 5), runtime: runtime)
                Issue.record("Failed or expired refresh accepted")
            } catch let failure as NativeFailure {
                #expect(failure.code == (late ? "deadlineExceeded" : "foregroundRefreshUnavailable"))
            }
            #expect(reads == 0)
        }
    }
}
