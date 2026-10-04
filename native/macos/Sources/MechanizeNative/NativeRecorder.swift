import AppKit
import ApplicationServices
import Carbon
import CoreGraphics
import CryptoKit
import Darwin
import Foundation
import MechanizeNativeCore

struct NativeRecordingOptions {
    let recordingID: String
    let expectedUID: UInt32
    let maxEvents: Int
    let durationMs: Int
}
struct NativeRecordingPermissions {
    let accessibility: Bool
    let listening: Bool
    let secureInput: Bool
}
struct NativeRecordingSignal {
    enum Kind { case primaryClick, textEdit, activation, health, unavailable, unsupported }
    let kind: Kind
    let timestamp: Date
    let pid: Int32?
    let point: CGPoint?
    let windowID: UInt32?
    // Public CGEvent fields cannot prove physical human provenance. The live
    // provider always leaves this false; only enrolled fixture sources attest.
    let trusted: Bool
    init(_ kind: Kind, timestamp: Date = Date(), pid: Int32? = nil, point: CGPoint? = nil, windowID: UInt32? = nil, trusted: Bool = false) {
        self.kind = kind; self.timestamp = timestamp; self.pid = pid; self.point = point; self.windowID = windowID; self.trusted = trusted
    }
}
struct NativeRecordingResolution {
    let identity: NativeRecordingIdentity
    let target: NativeRecordingTarget?
    let secure: Bool
}
struct NativeRecordingRuntime {
    let currentUID: () -> UInt32
    let permissions: () -> NativeRecordingPermissions
    let authorizedLive: () -> Bool
    let watchdogLive: () -> Bool
    let now: () -> Date
    var monotonicNow: () -> UInt64 = { DispatchTime.now().uptimeNanoseconds }
    let resolve: (NativeRecordingSignal, Data) -> NativeRecordingResolution?
    let install: (@escaping (NativeRecordingSignal) -> Void) throws -> (() -> Bool)

    /// Construction is dormant. Neither the tap nor workspace observer is
    /// installed until NativeRecorder.start succeeds under explicit authority.
    static func live(authorizedLive: @escaping () -> Bool, watchdogLive: @escaping () -> Bool, identifierIsSafe: @escaping (NativeRecordingIdentity, String) -> Bool = { _, _ in false }) -> NativeRecordingRuntime {
        NativeRecordingRuntime(currentUID: { getuid() }, permissions: {
            NativeRecordingPermissions(accessibility: AXIsProcessTrusted(), listening: CGPreflightListenEventAccess(), secureInput: IsSecureEventInputEnabled())
        }, authorizedLive: authorizedLive, watchdogLive: watchdogLive, now: Date.init, resolve: { signal, salt in
            resolveNativeRecordingTarget(signal, salt: salt, identifierIsSafe: identifierIsSafe)
        }, install: { receive in
            let producer = PassiveNativeRecordingProducer(receive: receive)
            try producer.start()
            return { producer.stop() }
        })
    }
}

/// One bounded recording per instance. No input dispatch, implicit permission
/// request, app allowlist, storage writer, workflow scheduler, or startup hook.
final class NativeRecorder {
    private let runtime: NativeRecordingRuntime
    private let lock = NSLock()
    private let work = OperationQueue()
    private var journal: RecordingJournal?
    private var expectedUID: UInt32 = 0
    private var end = Date.distantPast
    private var beganUptime: UInt64 = 0
    private var endUptime: UInt64 = 0
    private var cleanup: (() -> Bool)?
    private var accepting = false
    private var pending = 0
    private let salt: Data
    init(runtime: NativeRecordingRuntime) {
        self.runtime = runtime
        work.maxConcurrentOperationCount = 1
        work.name = "mechanize.native.recording"
        var random = SystemRandomNumberGenerator()
        salt = Data((0..<32).map { _ in UInt8.random(in: .min ... .max, using: &random) })
    }
    deinit { work.cancelAllOperations(); _ = cleanup?() }
    func start(_ options: NativeRecordingOptions) throws -> NativeRecordingBatch {
        lock.lock(); let used = journal != nil; lock.unlock()
        guard !used, runtime.currentUID() == options.expectedUID, runtime.authorizedLive(), runtime.watchdogLive() else { throw NativeFailure("recordingDenied", "Fresh current-user desktop recording authority required") }
        let permissions = runtime.permissions()
        guard permissions.accessibility, permissions.listening, !permissions.secureInput else { throw NativeFailure("recordingPermissionDenied", "Accessibility/listening must be granted and secure input absent") }
        let now = runtime.now()
        let created = try RecordingJournal(recordingID: options.recordingID, expectedUID: options.expectedUID, capacity: options.maxEvents, durationMs: options.durationMs, now: now, monotonicNow: runtime.monotonicNow)
        let uptime = runtime.monotonicNow(), duration = UInt64(options.durationMs) * 1_000_000
        guard uptime <= UInt64.max-duration else { throw NativeFailure("invalidRecording", "Recording monotonic deadline overflow") }
        lock.lock()
        guard journal == nil else { lock.unlock(); throw NativeFailure("recordingConflict", "Recorder instance already assigned") }
        journal = created; expectedUID = options.expectedUID; beganUptime = uptime; endUptime = uptime + duration; end = now.addingTimeInterval(Double(options.durationMs)/1000); accepting = true
        lock.unlock()
        do {
            let close = try runtime.install { [weak self] signal in self?.receive(signal) }
            lock.lock(); if accepting { cleanup = close; lock.unlock() } else { lock.unlock(); if !close() { lock.lock(); cleanup = close; lock.unlock() } }
        } catch {
            pause(reason: "producerUnavailable")
            throw NativeFailure("recordingUnavailable", "Passive recording producer unavailable")
        }
        return try created.poll(after: 0)
    }
    func pause(reason: String = "manualPause") {
        lock.lock(); accepting = false; let current = journal; let close = cleanup; cleanup = nil; lock.unlock()
        current?.pause(reason: reason, now: runtime.now())
        work.cancelAllOperations()
        if let close, !close() { lock.lock(); cleanup = close; lock.unlock() }
    }
    func watchdogStopped() { pause(reason: "watchdogStopped") }
    func stop() throws -> NativeRecordingBatch {
        lock.lock(); accepting = false; let current = journal; let close = cleanup; cleanup = nil; lock.unlock()
        guard let current else { throw NativeFailure("recordingUnavailable", "Recorder not started") }
        work.cancelAllOperations()
        let confirmed = close?() ?? true
        if !confirmed { current.pause(reason: "producerUnavailable", now: runtime.now()); lock.lock(); cleanup = close; lock.unlock() }
        current.stop(confirmed: confirmed, now: runtime.now())
        return try current.poll(after: 0)
    }
    func poll(after: UInt64, limit: Int = 64) throws -> NativeRecordingBatch {
        _ = healthy()
        lock.lock(); let current = journal; lock.unlock()
        guard let current else { throw NativeFailure("recordingUnavailable", "Recorder not started") }
        return try current.poll(after: after, limit: limit)
    }
    private func healthy() -> Bool {
        lock.lock(); let live = accepting; let uid = expectedUID; let deadline = end; let beganUptime = self.beganUptime; let endUptime = self.endUptime; lock.unlock()
        guard live else { return false }
        if runtime.currentUID() != uid || !runtime.authorizedLive() { pause(reason: "consentWithdrawn"); return false }
        if !runtime.watchdogLive() { pause(reason: "watchdogStopped"); return false }
        if runtime.monotonicNow() < beganUptime || runtime.monotonicNow() >= endUptime || runtime.now() >= deadline { pause(reason: "durationExpired"); return false }
        let permissions = runtime.permissions()
        if permissions.secureInput { pause(reason: "secureInput"); return false }
        if !permissions.accessibility || !permissions.listening { pause(reason: "permissionLost"); return false }
        return true
    }
    private func coverageGap(_ reason: String) {
        lock.lock(); let current = journal; lock.unlock()
        current?.gap(reason: reason, now: runtime.now())
        if (try? current?.poll(after: 0).state) == "paused" { pause(reason: "journalCapacity") }
    }
    private func receive(_ signal: NativeRecordingSignal) {
        lock.lock()
        guard accepting else { lock.unlock(); return }
        guard pending < 64 else { lock.unlock(); pause(reason: "producerOverflow"); return }
        pending += 1; lock.unlock()
        work.addOperation { [weak self] in
            guard let self else { return }
            defer { self.lock.lock(); self.pending -= 1; self.lock.unlock() }
            self.process(signal)
        }
    }
    private func process(_ signal: NativeRecordingSignal) {
        guard healthy() else { return }
        if signal.kind == .health { return }
        if signal.kind == .unavailable { pause(reason: "tapDisabled"); return }
        if signal.kind == .unsupported { coverageGap("unsupportedInput"); return }
        let age = runtime.now().timeIntervalSince(signal.timestamp)
        guard age >= 0, age <= 0.5, let resolved = runtime.resolve(signal, salt), resolved.identity.valid(for: expectedUID) else { coverageGap("targetUnresolved"); return }
        guard !resolved.secure else { pause(reason: "secureTarget"); return }
        guard healthy(), runtime.now().timeIntervalSince(signal.timestamp) <= 1 else { pause(reason: "targetUnresolved"); return }
        let kind = signal.kind == .activation ? "app.activate" : (signal.kind == .textEdit ? "fill" : "press")
        lock.lock(); let current = journal; lock.unlock()
        do {
            if try current?.append(kind: kind, identity: resolved.identity, target: resolved.target, trusted: signal.trusted, now: signal.timestamp) == false { pause(reason: "journalCapacity") }
        } catch { coverageGap("targetUnresolved") }
    }
}

// AX values/titles/descriptions and CGEvent unicode/keycode data are never read.
private func resolveNativeRecordingTarget(_ signal: NativeRecordingSignal, salt: Data, identifierIsSafe: (NativeRecordingIdentity, String) -> Bool) -> NativeRecordingResolution? {
    var element: AXUIElement?
    let system = AXUIElementCreateSystemWide()
    guard AXUIElementSetMessagingTimeout(system, 0.05) == .success else { return nil }
    var pid: pid_t = signal.pid ?? 0
    if signal.kind == .primaryClick {
        guard let point = signal.point, point.x.isFinite, point.y.isFinite,
              AXUIElementCopyElementAtPosition(system, Float(point.x), Float(point.y), &element) == .success, let found = element,
              AXUIElementGetPid(found, &pid) == .success else { return nil }
    } else if signal.kind == .textEdit {
        var focused: CFTypeRef?
        guard AXUIElementCopyAttributeValue(system, kAXFocusedUIElementAttribute as CFString, &focused) == .success,
              let focused, CFGetTypeID(focused) == AXUIElementGetTypeID() else { return nil }
        element = unsafeBitCast(focused, to: AXUIElement.self)
        guard AXUIElementGetPid(element!, &pid) == .success else { return nil }
    }
    guard pid > 0, signal.pid == nil || signal.pid == pid, let app = NSRunningApplication(processIdentifier: pid), let bundle = app.bundleIdentifier else { return nil }
    var before = proc_bsdinfo()
    guard proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &before, Int32(MemoryLayout<proc_bsdinfo>.size)) == MemoryLayout<proc_bsdinfo>.size,
          before.pbi_uid == getuid(), before.pbi_status != 5 else { return nil }
    let token = "\(before.pbi_start_tvsec):\(before.pbi_start_tvusec)"
    var window = signal.windowID
    if let candidate = window, !recordingWindow(candidate, belongsTo: pid) { return nil }
    var target: NativeRecordingTarget?
    var secure = false
    if let element {
        guard AXUIElementSetMessagingTimeout(element, 0.05) == .success else { return nil }
        let role = recordingAttribute(element, kAXRoleAttribute) as? String ?? "AXUnknown"
        secure = recordingAttribute(element, kAXSubroleAttribute) as? String == kAXSecureTextFieldSubrole
        if signal.kind == .textEdit && ![kAXTextFieldRole, kAXTextAreaRole].contains(role) { return nil }
        if window == nil { window = recordingWindowForElement(element, pid: pid) }
        let identity = NativeRecordingIdentity(uid: before.pbi_uid, bundleID: bundle, pid: pid, startToken: token, windowID: window.map(String.init))
        if !secure, let identifier = recordingAttribute(element, kAXIdentifierAttribute) as? String, !identifier.isEmpty, identifier.utf8.count <= 256 {
            if identifierIsSafe(identity, identifier) {
                target = NativeRecordingTarget(role: role, identifier: identifier, identifierQualified: true)
            } else {
                let digest = HMAC<SHA256>.authenticationCode(for: Data((bundle + "\u{0}" + identifier).utf8), using: SymmetricKey(data: salt)).map { String(format: "%02x", $0) }.joined()
                target = NativeRecordingTarget(role: role, identifierDigest: digest)
            }
        } else { target = NativeRecordingTarget(role: role) }
        if target?.valid != true { target = NativeRecordingTarget(role: "AXUnknown") }
    }
    var after = proc_bsdinfo()
    guard proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &after, Int32(MemoryLayout<proc_bsdinfo>.size)) == MemoryLayout<proc_bsdinfo>.size,
          before.pbi_uid == after.pbi_uid, before.pbi_start_tvsec == after.pbi_start_tvsec, before.pbi_start_tvusec == after.pbi_start_tvusec,
          after.pbi_status != 5, NSRunningApplication(processIdentifier: pid)?.bundleIdentifier == bundle else { return nil }
    return NativeRecordingResolution(identity: NativeRecordingIdentity(uid: before.pbi_uid, bundleID: bundle, pid: pid, startToken: token, windowID: window.map(String.init)), target: target, secure: secure)
}
private func recordingAttribute(_ element: AXUIElement, _ name: String) -> CFTypeRef? {
    var value: CFTypeRef?
    return AXUIElementCopyAttributeValue(element, name as CFString, &value) == .success ? value : nil
}
private func recordingWindow(_ id: UInt32, belongsTo pid: Int32) -> Bool {
    guard let windows = CGWindowListCopyWindowInfo(.optionIncludingWindow, CGWindowID(id)) as? [[String: Any]], windows.count == 1 else { return false }
    return (windows[0][kCGWindowOwnerPID as String] as? NSNumber)?.int32Value == pid && (windows[0][kCGWindowNumber as String] as? NSNumber)?.uint32Value == id
}
private func recordingWindowForElement(_ element: AXUIElement, pid: Int32) -> UInt32? {
    guard let value = recordingAttribute(element, kAXWindowAttribute), CFGetTypeID(value) == AXUIElementGetTypeID() else { return nil }
    let window = unsafeBitCast(value, to: AXUIElement.self)
    _ = AXUIElementSetMessagingTimeout(window, 0.05)
    guard let position = recordingAttribute(window, kAXPositionAttribute), CFGetTypeID(position) == AXValueGetTypeID(),
          let size = recordingAttribute(window, kAXSizeAttribute), CFGetTypeID(size) == AXValueGetTypeID() else { return nil }
    var point = CGPoint.zero; var dimensions = CGSize.zero
    guard AXValueGetValue(unsafeBitCast(position, to: AXValue.self), .cgPoint, &point), AXValueGetValue(unsafeBitCast(size, to: AXValue.self), .cgSize, &dimensions),
          let windows = CGWindowListCopyWindowInfo([.optionOnScreenOnly, .excludeDesktopElements], kCGNullWindowID) as? [[String: Any]], windows.count <= 4096 else { return nil }
    let matching = windows.filter { item in
        guard (item[kCGWindowOwnerPID as String] as? NSNumber)?.int32Value == pid,
              let raw = item[kCGWindowBounds as String] as? [String: Any], let bounds = CGRect(dictionaryRepresentation: raw as CFDictionary) else { return false }
        return abs(bounds.minX-point.x) < 1 && abs(bounds.minY-point.y) < 1 && abs(bounds.width-dimensions.width) < 1 && abs(bounds.height-dimensions.height) < 1
    }
    return matching.count == 1 ? (matching[0][kCGWindowNumber as String] as? NSNumber)?.uint32Value : nil
}

/// Dedicated passive run loop. Its callback carries only bounded metadata into
/// the resolver queue; Accessibility never runs in the event-tap callback.
private final class PassiveNativeRecordingProducer {
    private let receive: (NativeRecordingSignal) -> Void
    private let lock = NSLock()
    private let ready = DispatchSemaphore(value: 0)
    private var cancelled = false
    private var installed = false
    private var tap: CFMachPort?
    private var loop: CFRunLoop?
    private var observer: NSObjectProtocol?
    private var timer: CFRunLoopTimer?
    init(receive: @escaping (NativeRecordingSignal) -> Void) { self.receive = receive }
    func start() throws {
        Thread.detachNewThread { self.run() }
        guard ready.wait(timeout: .now()+2) == .success else { _ = stop(); throw NativeFailure("recordingUnavailable", "Passive producer startup timed out") }
        lock.lock(); let success = installed; lock.unlock()
        guard success else { _ = stop(); throw NativeFailure("recordingUnavailable", "Passive tap installation failed") }
    }
    private func run() {
        lock.lock(); let stopped = cancelled; lock.unlock(); if stopped { ready.signal(); return }
        let mask = [CGEventType.leftMouseUp, .keyDown, .rightMouseUp, .otherMouseUp, .scrollWheel].reduce(CGEventMask(0)) { $0 | (CGEventMask(1) << $1.rawValue) }
        guard let port = CGEvent.tapCreate(tap: .cgSessionEventTap, place: .tailAppendEventTap, options: .listenOnly, eventsOfInterest: mask, callback: { _, type, event, context in
            guard let context else { return Unmanaged.passUnretained(event) }
            let producer = Unmanaged<PassiveNativeRecordingProducer>.fromOpaque(context).takeUnretainedValue()
            producer.event(type, event)
            return Unmanaged.passUnretained(event)
        }, userInfo: Unmanaged.passUnretained(self).toOpaque()) else { ready.signal(); return }
        guard let source = CFMachPortCreateRunLoopSource(kCFAllocatorDefault, port, 0) else { CFMachPortInvalidate(port); ready.signal(); return }
        let runLoop = CFRunLoopGetCurrent()!
        let notification = NSWorkspace.shared.notificationCenter.addObserver(forName: NSWorkspace.didActivateApplicationNotification, object: nil, queue: nil) { [weak self] value in
            guard let app = value.userInfo?[NSWorkspace.applicationUserInfoKey] as? NSRunningApplication else { return }
            self?.receive(NativeRecordingSignal(.activation, pid: app.processIdentifier))
        }
        let monitor = CFRunLoopTimerCreateWithHandler(kCFAllocatorDefault, CFAbsoluteTimeGetCurrent()+0.25, 0.25, 0, 0) { [weak self] _ in self?.receive(NativeRecordingSignal(.health)) }
        lock.lock()
        if cancelled { lock.unlock(); NSWorkspace.shared.notificationCenter.removeObserver(notification); CFMachPortInvalidate(port); ready.signal(); return }
        tap = port; loop = runLoop; observer = notification; timer = monitor; installed = true; lock.unlock()
        CFRunLoopAddSource(runLoop, source, .commonModes)
        if let monitor { CFRunLoopAddTimer(runLoop, monitor, .commonModes) }
        CGEvent.tapEnable(tap: port, enable: true)
        ready.signal(); CFRunLoopRun()
        _ = stop(); CFRunLoopRemoveSource(runLoop, source, .commonModes)
    }
    private func event(_ type: CGEventType, _ event: CGEvent) {
        if type == .tapDisabledByTimeout || type == .tapDisabledByUserInput { receive(NativeRecordingSignal(.unavailable)); return }
        let rawPID = event.getIntegerValueField(.eventTargetUnixProcessID)
        let pid = rawPID > 0 && rawPID <= Int64(Int32.max) ? Int32(rawPID) : nil
        if type == .leftMouseUp {
            let rawWindow = event.getIntegerValueField(.mouseEventWindowUnderMousePointer)
            let window = rawWindow > 0 && rawWindow <= Int64(UInt32.max) ? UInt32(rawWindow) : nil
            receive(NativeRecordingSignal(.primaryClick, pid: pid, point: event.location, windowID: window))
        } else if type == .keyDown && !event.flags.contains(.maskCommand) && !event.flags.contains(.maskControl) {
            receive(NativeRecordingSignal(.textEdit, pid: pid))
        } else { receive(NativeRecordingSignal(.unsupported)) }
    }
    @discardableResult func stop() -> Bool {
        lock.lock(); cancelled = true; installed = false
        let port = tap; tap = nil; let runLoop = loop; loop = nil; let notification = observer; observer = nil; let monitor = timer; timer = nil
        lock.unlock()
        if let monitor { CFRunLoopTimerInvalidate(monitor) }
        if let notification { NSWorkspace.shared.notificationCenter.removeObserver(notification) }
        if let port { CGEvent.tapEnable(tap: port, enable: false); CFMachPortInvalidate(port) }
        if let runLoop { CFRunLoopStop(runLoop) }
        return true
    }
}
