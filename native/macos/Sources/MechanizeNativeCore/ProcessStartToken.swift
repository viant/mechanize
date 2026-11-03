import Foundation

// Canonical, bounded public libproc fingerprint (seconds:microseconds).
public func validApplicationProcessStartToken(_ token: String) -> Bool {
    token.utf8.count <= 27 && token.range(of: #"\A[1-9][0-9]{0,19}:(0|[1-9][0-9]{0,5})\z"#, options: .regularExpression) != nil && UInt64(token.split(separator: ":")[0]) != nil
}
