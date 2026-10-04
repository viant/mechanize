import AppKit
import Darwin
import MechanizeNativeCore

struct ForegroundIdentity {
    let pid:pid_t
    let uid:uid_t?
    let birth:String?
    let bundle:String?
    let active:Bool
}
struct ForegroundProofRuntime {
    let refresh:(Budget)throws->Void
    let current:()->ForegroundIdentity?
    let corroborate:()->pid_t?
    static let system=ForegroundProofRuntime(refresh:{budget in
        try refreshForegroundNotifications(budget)
    },current:{
        guard let current=NSWorkspace.shared.frontmostApplication else {return nil}
        return ForegroundIdentity(pid:current.processIdentifier,uid:applicationLoginUID(current.processIdentifier),birth:applicationProcessStartToken(current.processIdentifier),bundle:current.bundleIdentifier,active:current.isActive)
    },corroborate:{try? freshFocusedApplicationPID()})
}

/// Cocoa documents running-application properties as run-loop updated. Drain at
/// most two already queued main-loop sources before reading frontmost/isActive;
/// neither this refresh nor its callbacks accept caller code or dispatch input.
func refreshForegroundNotifications(_ budget:Budget)throws {
    try budget.check()
    func drain() throws {
        try budget.check()
        for _ in 0..<2 {
            _ = CFRunLoopRunInMode(.defaultMode,min(0.005,Double(budget.remainingSeconds)),true)
            try budget.check()
        }
    }
    if Thread.isMainThread {try drain();return}
    let complete=DispatchSemaphore(value:0)
    let lock=NSLock()
    var finished=false
    var failure:Error?
    let waitNanoseconds=Int(min(0.05,Double(budget.remainingSeconds))*1_000_000_000)
    let deadline=DispatchTime.now() + .nanoseconds(waitNanoseconds)
    DispatchQueue.main.async {
        lock.lock();let expired=finished;lock.unlock()
        if !expired {do {try drain()}catch{lock.lock();failure=error;lock.unlock()}}
        complete.signal()
    }
    let result=complete.wait(timeout:deadline)
    lock.lock();finished=true;let error=failure;lock.unlock()
    guard result == .success else {throw NativeFailure("foregroundRefreshUnavailable","Bounded main-runloop foreground refresh unavailable")}
    if let error {throw error}
    try budget.check()
}
func qualifiedForeground(_ expected:ForegroundIdentity?,_ budget:Budget,runtime:ForegroundProofRuntime = .system)throws->ForegroundIdentity {
    try runtime.refresh(budget);try budget.check()
    guard let current=runtime.current() else {throw NativeFailure("foregroundUnavailable","Public NSWorkspace foreground unavailable")}
    guard current.active else {throw NativeFailure("foregroundNotActive","NSWorkspace frontmost application is not active")}
    guard current.uid == getuid(),let birth=current.birth,!birth.isEmpty,let bundle=current.bundle,bundle != "com.apple.loginwindow" else {throw NativeFailure("foregroundOwnerUnqualified","Active foreground UID/kernel identity unavailable or outside current user")}
    if let systemPID=runtime.corroborate(),systemPID != current.pid {throw NativeFailure("foregroundCorroborationConflict","Available system AX foreground disagrees with independent public application source")}
    if let expected {
        guard current.pid == expected.pid else {throw NativeFailure("foregroundChanged","Refreshed public foreground differs from exact target PID")}
        guard current.uid == expected.uid,current.birth == expected.birth,current.bundle == expected.bundle else {throw NativeFailure("staleReference","Foreground UID/kernel birth/bundle changed")}
    }
    try budget.check()
    return current
}
