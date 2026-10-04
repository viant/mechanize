import Foundation
import Darwin
import MechanizeNativeCore

final class Watchdog {
    let inputs: InputSafety
    let beforeExit: (() -> Void)?
    private let lock = NSLock()
    private var lastBeat = DispatchTime.now().uptimeNanoseconds
    private var stopped = false
    private let timer: DispatchSourceTimer
    init?(inputs: InputSafety, beforeExit: (() -> Void)? = nil) {
        var descriptor = stat()
        guard fstat(4, &descriptor) == 0, descriptor.st_mode & S_IFMT == S_IFIFO else { return nil }
        self.inputs = inputs
        self.beforeExit = beforeExit
        timer = DispatchSource.makeTimerSource(queue: .global(qos: .userInitiated))
        timer.schedule(deadline: .now() + .milliseconds(100), repeating: .milliseconds(100))
        timer.setEventHandler { [weak self] in self?.check() }; timer.resume()
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            while let self {
                var byte: UInt8 = 0
                let count = read(4, &byte, 1)
                if count <= 0 { self.stop(); return }
                self.lock.lock(); self.lastBeat = DispatchTime.now().uptimeNanoseconds; self.lock.unlock()
            }
        }
    }
    func live() -> Bool { lock.lock(); defer { lock.unlock() }; return !stopped && DispatchTime.now().uptimeNanoseconds - lastBeat < 2_000_000_000 }
    private func check() { if !live() { stop() } }
    private func stop() {
        lock.lock(); if stopped { lock.unlock(); return }; stopped = true; lock.unlock()
        _ = inputs.inhibitAndRelease()
        // Passive source cleanup gets a small bounded opportunity. A blocked
        // callback cannot stall independent watchdog exit or claim cleanup.
        if let beforeExit {
            let finished = DispatchSemaphore(value: 0)
            DispatchQueue.global(qos: .userInitiated).async { beforeExit(); finished.signal() }
            _ = finished.wait(timeout: .now()+0.1)
        }
        // Independent of a blocked AX/SCK request and the stdin action lane.
        _exit(70)
    }
}
