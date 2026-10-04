import XCTest
import CoreGraphics

@testable import MechanizeNativeCore

final class WindowCaptureGeometryTests: XCTestCase {
    func testChildSheetCropDoesNotScaleParentComposition() throws {
        let child = CGRect(x: 392, y: 430, width: 460, height: 215)
        let geometry = try WindowCaptureGeometry(window: child, display: CGRect(x: 0, y: 0, width: 1512, height: 982), scale: 2)
        XCTAssertEqual(geometry.bounds, child)
        XCTAssertEqual(geometry.sourceRect, child)
        XCTAssertEqual(geometry.widthPixels, 920)
        XCTAssertEqual(geometry.heightPixels, 430)
        try geometry.validateImage(width: 920, height: 430)
        XCTAssertThrowsError(try geometry.validateImage(width: 1070, height: 860))
    }

    func testDisplayOriginTranslationIncludingNegativeCoordinates() throws {
        for display in [CGRect(x: -1920, y: -200, width: 1920, height: 1080), CGRect(x: 1512, y: 100, width: 1920, height: 1080)] {
            let window = CGRect(x: display.minX + 392, y: display.minY + 430, width: 460, height: 215)
            let geometry = try WindowCaptureGeometry(window: window, display: display, scale: 1)
            XCTAssertEqual(geometry.sourceRect, CGRect(x: 392, y: 430, width: 460, height: 215))
            XCTAssertEqual(geometry.bounds, window)
        }
    }

    func testOffscreenSpanningAndInvalidGeometryFailClosed() {
        let display = CGRect(x: 0, y: 0, width: 1000, height: 800)
        for window in [CGRect(x: -1, y: 0, width: 460, height: 215), CGRect(x: 900, y: 0, width: 460, height: 215), CGRect(x: 0, y: 700, width: 460, height: 215), CGRect(x: 0, y: 0, width: 0, height: 215), CGRect(x: Double.infinity, y: 0, width: 460, height: 215)] {
            XCTAssertThrowsError(try WindowCaptureGeometry(window: window, display: display, scale: 2)) { XCTAssertEqual(($0 as? NativeFailure)?.code, "captureUnqualified") }
        }
        for scale in [Double.nan, Double.infinity, 0, -1, 9] {
            XCTAssertThrowsError(try WindowCaptureGeometry(window: CGRect(x: 0, y: 0, width: 460, height: 215), display: display, scale: scale))
        }
    }

    func testPixelBudgetAndFractionalOutputFailBeforeIntegerConversion() {
        for window in [CGRect(x: 0, y: 0, width: 10_000, height: 10_000), CGRect(x: 0, y: 0, width: 460.25, height: 215)] {
            XCTAssertThrowsError(try WindowCaptureGeometry(window: window, display: CGRect(x: 0, y: 0, width: 20_000, height: 20_000), scale: 2)) { XCTAssertEqual(($0 as? NativeFailure)?.code, "captureTooLarge") }
        }
    }
}
