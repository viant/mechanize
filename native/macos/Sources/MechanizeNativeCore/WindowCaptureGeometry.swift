import Foundation
import CoreGraphics


/// An exact window crop in a display's logical coordinate system. Independent
/// window filters can render the parent composition for child sheets while
/// reporting the child's contentRect, so those dimensions are not a crop proof.
public struct WindowCaptureGeometry {
    public let bounds: CGRect
    public let sourceRect: CGRect
    public let widthPixels: Int
    public let heightPixels: Int

    public init(window: CGRect, display: CGRect, scale: Double, maximumPixels: Int = 32_000_000) throws {
        func valid(_ rect: CGRect) -> Bool {
            [rect.minX, rect.minY, rect.width, rect.height, rect.maxX, rect.maxY].allSatisfy { $0.isFinite }
                && rect.width > 0 && rect.height > 0
        }
        guard valid(window), valid(display), scale.isFinite, scale > 0, scale <= 8, maximumPixels > 0 else {
            throw NativeFailure("captureUnqualified", "Exact window capture geometry is unavailable")
        }
        guard display.contains(window) else {
            throw NativeFailure("captureUnqualified", "Exact window must fit wholly inside one display")
        }
        let width = Double(window.width) * scale
        let height = Double(window.height) * scale
        // Do not round a crop outward or distort fractional pixels into metadata
        // claiming an exact logical-point rectangle.
        guard width >= 1, height >= 1, width <= Double(maximumPixels), height <= Double(maximumPixels),
              width.rounded() == width, height.rounded() == height, width * height <= Double(maximumPixels) else {
            throw NativeFailure("captureTooLarge", "Exact capture pixel geometry exceeds its budget or is fractional")
        }
        bounds = window
        sourceRect = CGRect(x: window.minX - display.minX, y: window.minY - display.minY, width: window.width, height: window.height)
        widthPixels = Int(width)
        heightPixels = Int(height)
    }

    public func validateImage(width: Int, height: Int) throws {
        guard width == widthPixels, height == heightPixels else {
            throw NativeFailure("captureUnqualified", "Screenshot dimensions do not match the exact requested window crop")
        }
    }
}
