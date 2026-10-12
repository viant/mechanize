import Foundation
import ApplicationServices
import MechanizeNativeCore

/// Callbacks carry invalidation only. They never read, retain or export UI data.
final class HierarchySignal {
    private let lock = NSLock()
    private var active = true
    private var counter: UInt64 = 0
    private var structuralCounter: UInt64 = 0
    var revision: UInt64 { lock.lock(); defer { lock.unlock() }; return counter }
    var structuralRevision:UInt64 {lock.lock();defer{lock.unlock()};return structuralCounter}
    func changed() { lock.lock(); defer { lock.unlock() }; if active { counter &+= 1;structuralCounter &+= 1 } }
    func focusChanged(){lock.lock();defer{lock.unlock()};if active {counter &+= 1}}
    func retire() { lock.lock(); active = false; lock.unlock() }
}

private let hierarchyCallback: AXObserverCallback = { _, _, notification, context in
    guard let context else { return }
    let signal=Unmanaged<HierarchySignal>.fromOpaque(context).takeUnretainedValue()
    if [kAXFocusedWindowChangedNotification,kAXFocusedUIElementChangedNotification].contains(notification as String){signal.focusChanged()}else{signal.changed()}
}

/// A new observer owns a new thread/run loop. Stopped observers are never reused.
/// The signal remains retained until the callback source is removed on its thread.
final class HierarchyObserver {
    let pid: pid_t
    let birth: String
    let signal = HierarchySignal()
    private let condition = NSCondition()
    private var stopping = false
    private var started = false
    private var ready = false
    private var finished = false
    private var supported = false
    init(pid: pid_t, birth: String) { self.pid = pid; self.birth = birth }
    func start() -> Bool {
        condition.lock()
        guard !stopping else { condition.unlock(); return false }
        guard !started else { let value = supported && !stopping; condition.unlock(); return value }
        started = true
        let thread = Thread { self.run() }
        thread.name = "Mechanize AX invalidation"
        thread.start()
        let deadline = Date().addingTimeInterval(1)
        while !ready && !finished { if !condition.wait(until: deadline) { break } }
        let value = ready && supported && !stopping
        condition.unlock()
        if !value { stop() }
        return value
    }
    func stop() {
        signal.retire()
        condition.lock(); stopping = true; condition.broadcast(); condition.unlock()
    }
    private func shouldStop() -> Bool {
        condition.lock(); defer { condition.unlock() }; return stopping
    }
    private func run() {
        let root = AXUIElementCreateApplication(pid)
        // Registration and cleanup must not inherit the default long AX timeout.
        AXUIElementSetMessagingTimeout(root, 0.1)
        var observer: AXObserver?
        let code = AXObserverCreate(pid, hierarchyCallback, &observer)
        var registrations: [String] = []
        if code == .success, let observer, !shouldStop(), applicationProcessStartToken(pid) == birth {
            let context = Unmanaged.passUnretained(signal).toOpaque()
            for name in [kAXFocusedWindowChangedNotification, kAXFocusedUIElementChangedNotification, kAXWindowCreatedNotification] {
                if shouldStop() { break }
                if AXObserverAddNotification(observer, root, name as CFString, context) == .success { registrations.append(name) }
            }
        }
        let loop = CFRunLoopGetCurrent()!
        let source = observer.map { AXObserverGetRunLoopSource($0) }
        if let source, !registrations.isEmpty { CFRunLoopAddSource(loop, source, .defaultMode) }
        condition.lock(); supported = !registrations.isEmpty; ready = true; condition.broadcast(); condition.unlock()
        if !registrations.isEmpty {
            while !shouldStop() {
                if applicationProcessStartToken(pid) != birth { signal.changed(); break }
                CFRunLoopRunInMode(.defaultMode, 0.1, false)
            }
        }
        signal.retire()
        if let observer {
            for name in registrations { AXObserverRemoveNotification(observer, root, name as CFString) }
        }
        if let source { CFRunLoopRemoveSource(loop, source, .defaultMode) }
        condition.lock(); finished = true; condition.broadcast(); condition.unlock()
        // observer and signal release only after source removal on this thread.
    }
}

// An activation may produce focus notifications. They can be acknowledged only
// after the original target is independently revalidated and no structural
// invalidation arrived before or during that proof.
func confirmNativeFocusTransition(_ signal:HierarchySignal,structural:UInt64,revalidate:()throws->Void)throws->UInt64 {
 guard signal.structuralRevision==structural else{throw NativeFailure("staleReference","Application structure changed before foreground proof")}
 try revalidate()
 guard signal.structuralRevision==structural else{throw NativeFailure("staleReference","Application structure changed during foreground proof")}
 return signal.revision
}
