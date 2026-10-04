import AppKit
import ScreenCaptureKit
import MechanizeNativeCore

struct ExactWindowCapture {
    let filter: SCContentFilter
    let configuration: SCStreamConfiguration
    let geometry: WindowCaptureGeometry
    let scale: Double
    let displayID: CGDirectDisplayID

    init(window: SCWindow, displays: [SCDisplay]) throws {
        guard #available(macOS 14.2, *) else {
            throw NativeFailure("captureUnqualified", "Exact capture requires explicit exclusion of child windows (macOS 14.2 or later)")
        }
        let bounds = window.frame
        let matches = displays.filter { $0.frame.contains(bounds) }
        guard !matches.isEmpty else { throw NativeFailure("captureOffDisplay", "Exact window must fit wholly inside one display before capture") }
        guard matches.count == 1, let display = matches.first else {
            throw NativeFailure("captureAmbiguousDisplay", "Exact window capture has more than one containing display")
        }
        // Capture a filtered display crop, never an unfiltered display or app.
        // SCK independent-window captures may compose a sheet's parent while
        // still reporting the sheet's contentRect; output sizing is not cropping.
        displayID = display.displayID
        filter = SCContentFilter(display: display, including: [window])
        scale = Double(filter.pointPixelScale)
        geometry = try WindowCaptureGeometry(window: bounds, display: display.frame, scale: scale)
        configuration = SCStreamConfiguration()
        configuration.sourceRect = geometry.sourceRect
        configuration.width = geometry.widthPixels
        configuration.height = geometry.heightPixels
        configuration.destinationRect = CGRect(x: 0, y: 0, width: geometry.widthPixels, height: geometry.heightPixels)
        configuration.showsCursor = false
        configuration.ignoreShadowsDisplay = true
        configuration.includeChildWindows = false
    }
}
