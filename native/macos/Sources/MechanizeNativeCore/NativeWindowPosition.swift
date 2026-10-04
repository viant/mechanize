import Foundation
import CoreFoundation

/// Exact logical integer points. No resize, physical pointer or display fallback.
public struct NativeWindowPosition: Equatable {
    public let x: Int
    public let y: Int
    public init(_ value: Any?) throws {
        guard let value = value as? [String: Any], Set(value.keys) == Set(["x", "y"]) else {
            throw NativeFailure("invalidPosition", "Exact window position x/y object required")
        }
        func coordinate(_ raw: Any?) throws -> Int {
            guard let number = raw as? NSNumber, CFGetTypeID(number) == CFNumberGetTypeID(), number.doubleValue.isFinite,
                  number.doubleValue >= -32768, number.doubleValue <= 32767, number.doubleValue.rounded(.towardZero) == number.doubleValue else {
                throw NativeFailure("invalidPosition", "Window coordinates must be integer logical points within -32768...32767")
            }
            return Int(number.doubleValue)
        }
        x = try coordinate(value["x"]); y = try coordinate(value["y"])
    }
    public func matches(x actualX: Double, y actualY: Double) -> Bool {
        actualX.isFinite && actualY.isFinite && actualX == Double(x) && actualY == Double(y)
    }
}
