import AppKit
import ScreenCaptureKit
import ImageIO
import UniformTypeIdentifiers
import CryptoKit
import CoreVideo
import MechanizeNativeCore

// SCStreamConfiguration.backgroundColor is assign/unowned: retain its owner.
private let frameCaptureClearBackground = CGColor(gray:0,alpha:0)

// Ephemeral pixels are retained only in the qualified control helper. No file,
// artifact identifier or caller geometry can mint a click permit.
final class WindowFrameImageStore {
    private let lock = NSLock()
    private var held: (String, CGImage)?
    func install(_ id: String, _ image: CGImage) { lock.lock(); held = (id, image); lock.unlock() }
    func take(_ id: String) throws -> CGImage {
        lock.lock(); defer { lock.unlock() }
        guard let value = held, value.0 == id else { throw NativeFailure("stalePermit", "Captured pixels unavailable") }
        held = nil; return value.1
    }
    func clear() { lock.lock(); held = nil; lock.unlock() }
}

// At most 64x64 pixels, clipped at frame edges. Exact equality intentionally
// rejects animations/clock updates rather than inventing a confidence score.
func windowFramePatch(x: Int, y: Int, width: Int, height: Int) throws -> CGRect {
    guard width > 0, height > 0, x >= 0, y >= 0, x < width, y < height else { throw NativeFailure("invalidPoint", "Bounded frame point required") }
    let left = max(0, x - 32), top = max(0, y - 32)
    return CGRect(x: left, y: top, width: min(width, x + 32) - left, height: min(height, y + 32) - top)
}
func windowFrameRGBA(_ image: CGImage) throws -> [UInt8] {
    guard image.width > 0, image.height > 0, image.width <= 64, image.height <= 64 else { throw NativeFailure("staleCapture", "Bounded current pixel patch required") }
    var pixels = [UInt8](repeating: 0, count: image.width * image.height * 4)
    let ok = pixels.withUnsafeMutableBytes { bytes -> Bool in
        guard let ctx = CGContext(data: bytes.baseAddress, width: image.width, height: image.height, bitsPerComponent: 8, bytesPerRow: image.width * 4,
                                  space: CGColorSpace(name: CGColorSpace.sRGB)!, bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue | CGBitmapInfo.byteOrder32Big.rawValue) else { return false }
        ctx.setBlendMode(.copy); ctx.interpolationQuality = .none
        ctx.draw(image, in: CGRect(x: 0, y: 0, width: image.width, height: image.height)); return true
    }
    guard ok else { throw NativeFailure("staleCapture", "Current pixel patch comparison unavailable") }
    return pixels
}
private func windowFrameOpaquePixel(_ image: CGImage) throws -> Bool {
    var bytes = try windowFrameRGBA(image)
    defer { _ = bytes.withUnsafeMutableBytes { $0.initializeMemory(as: UInt8.self, repeating: 0) } }
    return bytes[3] == 255
}
func requireWindowFramePatch(_ original: CGImage, current: CGImage, rect: CGRect, x: Int, y: Int) throws {
    let alphaFormats: [CGImageAlphaInfo] = [.first, .last, .premultipliedFirst, .premultipliedLast]
    guard original.bitsPerComponent == 8, current.bitsPerComponent == 8,
          alphaFormats.contains(original.alphaInfo), alphaFormats.contains(current.alphaInfo),
          rect.contains(CGPoint(x:Double(x)+0.5,y:Double(y)+0.5)),
          let oldPixel = original.cropping(to:CGRect(x:x,y:y,width:1,height:1)),
          let newPixel = current.cropping(to:CGRect(x:Double(x)-rect.minX,y:Double(y)-rect.minY,width:1,height:1)),
          try windowFrameOpaquePixel(oldPixel), try windowFrameOpaquePixel(newPixel) else {
        throw NativeFailure("windowClickTransparent", "Clicked pixel opacity is unqualified; recapture")
    }
    guard current.width == Int(rect.width), current.height == Int(rect.height), let cropped = original.cropping(to: rect) else { throw NativeFailure("staleCapture", "Captured patch geometry changed; recapture") }
    var before = try windowFrameRGBA(cropped), after = try windowFrameRGBA(current)
    defer { _ = before.withUnsafeMutableBytes { $0.initializeMemory(as: UInt8.self, repeating: 0) }; _ = after.withUnsafeMutableBytes { $0.initializeMemory(as: UInt8.self, repeating: 0) } }
    guard before == after else { throw NativeFailure("staleCapture", "Captured point pixels changed; recapture") }
}

func requireWindowFrameCurrentImage(_ original: CGImage, current: CGImage, x: Int, y: Int) throws {
    guard current.width == original.width, current.height == original.height else {
        throw NativeFailure("staleCapture", "Current window image geometry changed; recapture")
    }
    let rect = try windowFramePatch(x: x, y: y, width: original.width, height: original.height)
    guard let patch = current.cropping(to: rect) else {
        throw NativeFailure("staleCapture", "Current window patch unavailable; recapture")
    }
    try requireWindowFramePatch(original, current: patch, rect: rect, x: x, y: y)
}

func requireWindowFramePNGSize(_ count: Int) throws {
    guard count > 0, count <= FrameCodec.maximumWindowFramePNGBytes else {
        throw NativeFailure("captureTooLarge", "Exact window PNG exceeds 32 MiB limit; no scaling performed")
    }
}
func encodeWindowFramePNG(_ image: CGImage) throws -> Data {
    let encoded = NSMutableData()
    guard let destination = CGImageDestinationCreateWithData(encoded, UTType.png.identifier as CFString, 1, nil) else {
        throw NativeFailure("captureUnqualified", "Frame PNG encoder unavailable")
    }
    CGImageDestinationAddImage(destination, image, nil)
    guard CGImageDestinationFinalize(destination) else { throw NativeFailure("captureUnqualified", "Frame PNG encoding failed") }
    try requireWindowFramePNGSize(encoded.length)
    return encoded as Data
}

extension Helper {
    func clearWindowFrame() { framePermits.clear(); frameImages.clear() }
    func checkWindowFrameAuthority(_ request: [String: Any], owner: WindowFrameOwner, bundle: String, budget: Budget) throws -> Int {
        try budget.check()
        guard !Task.isCancelled, windowFrameClickEnabled, let held = lease, let persisted = fenceLease(),
              let offered = request["lease"] as? [String: Any], offered["id"] as? String == held.0, offered["generation"] as? Int == held.1,
              persisted["id"] as? String == held.0, persisted["generation"] as? Int == held.1, persisted["owner"] as? String == owner.namespace,
              let scope = persisted["scope"] as? [String: Any], fenceScopeAllows(scope, bundle) else { throw NativeFailure("staleLease", "Captured frame control authority changed") }
        return held.1
    }
    func exactFrameCapture(_ permit: WindowFramePermit, _ budget: Budget) async throws -> ExactWindowCapture {
        let content = try await SCShareableContent.excludingDesktopWindows(false, onScreenWindowsOnly: true)
        try budget.check()
        let matches = content.windows.filter { $0.windowID == permit.windowId && $0.owningApplication?.processID == permit.pid && $0.owningApplication?.bundleIdentifier == permit.bundleId }
        guard matches.count == 1, let window = matches.first, window.frame == permit.bounds else { throw NativeFailure("staleCapture", "Captured window geometry changed; recapture") }
        let exact = try ExactWindowCapture(window: window, displays: content.displays)
        guard exact.displayID == permit.displayId, exact.scale == permit.scale, exact.geometry.widthPixels == permit.widthPixels,
              exact.geometry.heightPixels == permit.heightPixels else { throw NativeFailure("staleCapture", "Captured display mapping changed; recapture") }
        return exact
    }
    func captureWindowFrame(_ request: [String: Any], _ params: [String: Any], _ budget: Budget) async throws -> [String: Any] {
        clearWindowFrame()
        guard Set(params.keys) == Set(["expectedApp", "pid", "processStartToken", "windowId", "owner"]),
              let bundle = params["expectedApp"] as? String, concreteApplicationBundle(bundle),
              let birth = params["processStartToken"] as? String, validApplicationProcessStartToken(birth) else { throw NativeFailure("invalidScope", "Exact owned frame scope required") }
        let owner = try WindowFrameOwner(params["owner"])
        let pid = Int32(try RecordingConsentLease.integer(params["pid"], maximum: UInt64(Int32.max)))
        let windowID = UInt32(try RecordingConsentLease.integer(params["windowId"], maximum: UInt64(UInt32.max)))
        let heldGeneration = try checkWindowFrameAuthority(request, owner: owner, bundle: bundle, budget: budget)
        try qualifyWindowFrameTarget(pid: pid, uid: getuid(), birth: birth, bundle: bundle, windowID: windowID, check: { try budget.check() })
        let content = try await SCShareableContent.excludingDesktopWindows(false, onScreenWindowsOnly: true)
        try budget.check()
        let matches = content.windows.filter { $0.windowID == windowID && $0.owningApplication?.processID == pid && $0.owningApplication?.bundleIdentifier == bundle }
        guard matches.count == 1, let window = matches.first else { throw NativeFailure("captureUnqualified", "Exact capture window unavailable") }
        let exact = try ExactWindowCapture(window: window, displays: content.displays)
        exact.configuration.pixelFormat = kCVPixelFormatType_32BGRA
        exact.configuration.backgroundColor = frameCaptureClearBackground
        let image = try await SCScreenshotManager.captureImage(contentFilter: exact.filter, configuration: exact.configuration)
        try budget.check(); try exact.geometry.validateImage(width: image.width, height: image.height)
        let capturedAt = Date(), capturedUptime = DispatchTime.now().uptimeNanoseconds
        let png = try encodeWindowFramePNG(image)
        let permit = try WindowFramePermit(id: UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased(), owner: owner, helperEpoch: epoch,
                                          fenceGeneration: heldGeneration, bundleId: bundle, pid: pid, processStartToken: birth, windowId: windowID,
                                          displayId: exact.displayID, bounds: exact.geometry.bounds, widthPixels: image.width, heightPixels: image.height, scale: exact.scale,
                                          contentHash: SHA256.hash(data: png).map { String(format: "%02x", $0) }.joined(), capturedAt: capturedAt, uptime: capturedUptime)
        _ = try await exactFrameCapture(permit, budget)
        guard try checkWindowFrameAuthority(request, owner: owner, bundle: bundle, budget: budget) == heldGeneration else { throw NativeFailure("staleLease", "Frame lease generation changed") }
        try qualifyWindowFrameCapture(permit, uid: getuid(), check: { try budget.check() })
        frameImages.install(permit.id, image); framePermits.install(permit)
        // Watchdog may revoke between publication and return; never export a
        // usable proof after its authority disappeared.
        do { _ = try checkWindowFrameAuthority(request, owner: owner, bundle: bundle, budget: budget) }
        catch { clearWindowFrame(); throw error }
        return ["permit": permit.metadata(format: preciseISO.string), "pngBase64": png.base64EncodedString()]
    }
    func prepareWindowFrameClick(_ request: [String: Any], _ params: [String: Any], _ budget: Budget, acquire:(NativeForegroundTarget)throws->Void = {_ in}) async throws -> (WindowFramePermit, CGPoint) {
        defer { clearWindowFrame() }
        guard Set(params.keys) == Set(["expectedApp", "pid", "processStartToken", "owner", "permitId", "x", "y"]),
              let bundle = params["expectedApp"] as? String, let birth = params["processStartToken"] as? String,
              let id = params["permitId"] as? String else { throw NativeFailure("invalidPermit", "Exact capture-bound click required") }
        let owner = try WindowFrameOwner(params["owner"])
        let generation = try checkWindowFrameAuthority(request, owner: owner, bundle: bundle, budget: budget)
        // Burn before any await/guard/dispatch; rejected clicks cannot revive it.
        let permit = try framePermits.consume(id: id, owner: owner, epoch: epoch, generation: generation, now: DispatchTime.now().uptimeNanoseconds)
        let image = try frameImages.take(id)
        let pid = try RecordingConsentLease.integer(params["pid"], maximum: UInt64(Int32.max))
        guard permit.bundleId == bundle, permit.processStartToken == birth, UInt64(permit.pid) == pid else { throw NativeFailure("stalePermit", "Captured frame identity differs") }
        let (x, y, mappedPoint) = try permit.point(x: params["x"], y: params["y"])
        // RobotGo's public pointer API uses integer screen points. Qualify the
        // actual posted point, including at Retina edges, rather than a proxy.
        let point = CGPoint(x: mappedPoint.x.rounded(), y: mappedPoint.y.rounded())
        let foreground=try NativeForegroundTarget.physical(pid:permit.pid,birth:permit.processStartToken,bundle:permit.bundleId,windowID:permit.windowId,budget:budget,pointerDelivery:true)
        try acquire(foreground)
        try qualifyWindowFramePoint(permit, point: point, uid: getuid(), check: { try budget.check() })
        let exact = try await exactFrameCapture(permit, budget)
        // Match the producer's full-window rendering geometry. A separately
        // rendered subregion can change compositor sampling around UI edges.
        // Crop locally only after the same bounded exact-window capture.
        exact.configuration.pixelFormat = kCVPixelFormatType_32BGRA
        exact.configuration.backgroundColor = frameCaptureClearBackground
        let current = try await SCScreenshotManager.captureImage(contentFilter: exact.filter, configuration: exact.configuration)
        try requireWindowFrameCurrentImage(image, current: current, x:x, y:y)
        try validateWindowFrameClick(request, permit, point, budget)
        return (permit, point)
    }
    func validateWindowFrameClick(_ request: [String: Any], _ permit: WindowFramePermit, _ point: CGPoint, _ budget: Budget) throws {
        guard DispatchTime.now().uptimeNanoseconds < permit.deadline,
              try checkWindowFrameAuthority(request, owner: permit.owner, bundle: permit.bundleId, budget: budget) == permit.fenceGeneration else { throw NativeFailure("stalePermit", "Captured click interval expired") }
        try qualifyWindowFramePoint(permit, point: point, uid: getuid(), check: { try budget.check() })
    }
}
