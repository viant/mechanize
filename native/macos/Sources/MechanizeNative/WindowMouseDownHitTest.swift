import AppKit
import MechanizeNativeCore

func appKitMouseDownPoint(_ point: CGPoint, primaryCG: CGRect, primaryAppKit: CGRect) throws -> CGPoint {
    guard [point.x, point.y, primaryCG.width, primaryCG.height, primaryAppKit.width, primaryAppKit.height].allSatisfy({ $0.isFinite }),
          primaryCG.origin == .zero, primaryAppKit.origin == .zero,
          primaryCG.size == primaryAppKit.size, primaryCG.width > 0, primaryCG.height > 0 else {
        throw NativeFailure("windowHitTestUnavailable", "Primary display coordinate transform is unqualified")
    }
    // Both global spaces use the primary display as origin. Flip around its
    // upper edge, preserving negative coordinates on adjacent displays.
    let converted = CGPoint(x: point.x, y: primaryAppKit.maxY - point.y)
    guard converted.x.isFinite, converted.y.isFinite else {
        throw NativeFailure("windowHitTestUnavailable", "Converted mouse-down point is unqualified")
    }
    return converted
}

/// Public WindowServer mouse-down hit testing, not an AX or alpha inference.
/// Zero, timeout and uncertain display mapping never authorize a click.
func mouseDownWindowAtPoint(_ point: CGPoint) throws -> UInt32? {
    func query() throws -> UInt32? {
        guard let screen = NSScreen.screens.first else {
            throw NativeFailure("windowHitTestUnavailable", "Primary AppKit screen unavailable")
        }
        let converted = try appKitMouseDownPoint(point, primaryCG: CGDisplayBounds(CGMainDisplayID()), primaryAppKit: screen.frame)
        let number = NSWindow.windowNumber(at: converted, belowWindowWithWindowNumber: 0)
        guard number > 0, number <= Int(UInt32.max) else { return nil }
        return UInt32(number)
    }
    if Thread.isMainThread { return try query() }
    let semaphore = DispatchSemaphore(value: 0), lock = NSLock()
    var expired = false
    var result: Result<UInt32?, Error>?
    DispatchQueue.main.async {
        lock.lock(); let shouldQuery = !expired; lock.unlock()
        if shouldQuery {
            let value = Result { try query() }
            lock.lock(); if !expired { result = value }; lock.unlock()
        }
        semaphore.signal()
    }
    let completed = semaphore.wait(timeout: .now() + .milliseconds(50))
    lock.lock(); expired = true; let value = result; lock.unlock()
    guard completed == .success, let value else {
        throw NativeFailure("windowHitTestUnavailable", "Bounded main-thread mouse-down hit test unavailable")
    }
    return try value.get()
}
