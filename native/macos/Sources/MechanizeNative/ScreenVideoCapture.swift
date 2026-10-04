import Foundation
import ScreenCaptureKit
import CoreMedia
import CoreImage
import AppKit
import MechanizeNativeCore

/// Opt-in ScreenCaptureKit producer, intentionally not registered in the helper RPC yet.
/// Frames are encoded in memory and handed to a synchronous encrypted artifact sink.
/// A trusted local redactor must affirm each frame; nil pauses before any persistence.
/// The sink must never queue unbounded bytes or write plaintext temporary movies.
@available(macOS 14.0, *)
final class ScreenVideoCapture: NSObject, SCStreamOutput, SCStreamDelegate {
    typealias Redactor = (CVPixelBuffer, VideoRecordingScope) throws -> Data?
    typealias Sink = (VideoFrameStamp, Data) throws -> Void
    private let budget: VideoRecordingBudget
    private let redact: Redactor
    private let sink: Sink
    private let queue = DispatchQueue(label: "mechanize.video.frames")
    @MainActor private var streams: [SCStream] = []
    @MainActor private var stopTask: Task<Bool, Never>?
    private var displayIDs: [ObjectIdentifier: UInt32] = [:]
    @MainActor private var expiry: DispatchWorkItem?
    init(budget: VideoRecordingBudget, redactor: @escaping Redactor, sink: @escaping Sink) {
        self.budget = budget; self.redact = redactor; self.sink = sink
    }
    /// Invoke only from a visible, user-authorized privacy setup flow.
    static func requestScreenPermission() -> Bool { CGRequestScreenCaptureAccess() }
    @MainActor func start() async throws {
        guard CGPreflightScreenCaptureAccess(), budget.snapshot.state == "recording", streams.isEmpty else { throw NativeFailure("screenCapturePermission", "Live record authority and Screen Recording permission required") }
        let content = try await SCShareableContent.excludingDesktopWindows(false, onScreenWindowsOnly: false)
        var filters: [(SCContentFilter, UInt32, Int, Int)] = []
        switch budget.scope {
        case .desktop:
            for display in content.displays { filters.append((SCContentFilter(display: display, excludingApplications: [], exceptingWindows: []), display.displayID, display.width, display.height)) }
        case .application(let bundle):
            let apps = content.applications.filter { $0.bundleIdentifier == bundle }
            guard !apps.isEmpty else { throw NativeFailure("videoScopeUnavailable", "Authorized application is not capturable") }
            for display in content.displays { filters.append((SCContentFilter(display: display, including: apps, exceptingWindows: []), display.displayID, display.width, display.height)) }
        case .window(let bundle, let id):
            guard let window = content.windows.first(where: { $0.windowID == id && $0.owningApplication?.bundleIdentifier == bundle }) else { throw NativeFailure("videoScopeUnavailable", "Exact authorized window unavailable") }
            filters.append((SCContentFilter(desktopIndependentWindow: window), 0, Int(window.frame.width), Int(window.frame.height)))
        }
        guard !filters.isEmpty, filters.count <= 8 else { throw NativeFailure("videoScopeUnavailable", "Bounded display inventory required") }
        do {
            for (filter, display, width, height) in filters {
                guard stopTask == nil, budget.snapshot.state == "recording" else { throw NativeFailure("videoAuthorityEnded", "Video authority ended during capture startup") }
                let config = SCStreamConfiguration()
                let scale = min(1.0, 1920.0 / Double(max(width, height, 1)))
                config.width = max(1, Int(Double(width) * scale)); config.height = max(1, Int(Double(height) * scale))
                config.minimumFrameInterval = CMTime(value: 1, timescale: 2)
                config.queueDepth = 3; config.showsCursor = false; config.capturesAudio = false
                let stream = SCStream(filter: filter, configuration: config, delegate: self)
                try stream.addStreamOutput(self, type: .screen, sampleHandlerQueue: queue)
                queue.sync { displayIDs[ObjectIdentifier(stream)] = display }
                streams.append(stream)
                try await stream.startCapture()
                guard stopTask == nil, budget.snapshot.state == "recording" else { try? await stream.stopCapture(); throw NativeFailure("videoAuthorityEnded", "Video authority ended during capture startup") }
            }
            let work = DispatchWorkItem { [weak self] in self?.pause(reason: "durationExpired") }
            expiry = work; queue.asyncAfter(deadline: .now() + .milliseconds(budget.durationMs), execute: work)
        } catch {
            budget.pause(reason: "producerUnavailable"); _ = await stop(); throw error
        }
    }
    func stream(_ stream: SCStream, didOutputSampleBuffer sampleBuffer: CMSampleBuffer, of type: SCStreamOutputType) {
        guard type == .screen, budget.snapshot.state == "recording", sampleBuffer.isValid, let pixel = CMSampleBufferGetImageBuffer(sampleBuffer) else { return }
        guard CGPreflightScreenCaptureAccess() else { pause(reason: "permissionLost"); return }
        guard let attachments = CMSampleBufferGetSampleAttachmentsArray(sampleBuffer, createIfNecessary: false) as? [[SCStreamFrameInfo: Any]], let rawStatus = attachments.first?[.status] as? Int, SCFrameStatus(rawValue: rawStatus) == .complete else { return }
        do {
            guard let safe = try redact(pixel, budget.scope) else { pause(reason: "redactionUnavailable"); return }
            // Reject opaque/incorrect sink formats; reviewed redaction must emit JPEG.
            guard safe.count <= 4 * 1024 * 1024, safe.starts(with: [0xff, 0xd8]), safe.suffix(2).elementsEqual([0xff, 0xd9]) else { pause(reason: "redactionUnavailable"); return }
            guard let stamp = budget.accept(sizeBytes: safe.count, displayID: displayIDs[ObjectIdentifier(stream)] ?? 0) else { pause(reason: budget.snapshot.reason ?? "producerUnavailable"); return }
            try sink(stamp, safe)
        } catch { pause(reason: "sinkFailure") }
    }
    func stream(_ stream: SCStream, didStopWithError error: Error) { pause(reason: "producerUnavailable") }
    func pause(reason: String = "manualPause") {
        budget.pause(reason: reason)
        Task { @MainActor in _ = await stop() }
    }
    func revoke() { pause(reason: "consentWithdrawn") }
    @MainActor @discardableResult func stop() async -> Bool {
        if let stopTask { return await stopTask.value }
        budget.pause(reason: "manualPause")
        expiry?.cancel()
        let owned = streams
        streams.removeAll()
        let task = Task { @MainActor in
            var confirmed = true
            for stream in owned { do { try await stream.stopCapture() } catch { confirmed = false } }
            // Drain the serialized sink before advertising cleanup.
            queue.sync { displayIDs.removeAll() }
            budget.stop(confirmed: confirmed)
            return confirmed
        }
        stopTask = task
        return await task.value
    }
}
