import Foundation

/// Observes the already requested focus effect; never performs/repeats a setter.
public enum FocusProof {
    public static func nonfocusedReason(_ code:String)->Bool { ["focusNotObserved","focusedIdentityMismatch","foregroundChanged"].contains(code) }
    public static func read(validate: () throws -> Void) throws -> Bool {
        do {try validate();return true} catch let failure as NativeFailure {
            if nonfocusedReason(failure.code) {return false}
            throw failure
        }
    }
    public static func settle(maximumNanoseconds: UInt64 = 750_000_000,
        clock: () -> UInt64 = {DispatchTime.now().uptimeNanoseconds},
        validate: () throws -> Void, refresh: () -> Void, pause: () -> Void) throws {
        let start = clock()
        var last = NativeFailure("focusUnconfirmed", "Exact focus has not been observed")
        for _ in 0..<40 {
            do {try validate(); return} catch let failure as NativeFailure {
                last = failure
                guard ["focusNotObserved","focusedIdentityMismatch","focusedIdentityUnavailable","foregroundChanged","foregroundUnavailable"].contains(failure.code) else {throw failure}
            } catch {throw error}
            if clock() &- start >= maximumNanoseconds {throw last}
            refresh();pause()
        }
        throw last
    }
}
