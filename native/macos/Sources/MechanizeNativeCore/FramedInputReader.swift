import Foundation

// One framed read at a time on a dedicated queue. Awaiting stdin must not block
// AppKit's main run loop; the caller still processes requests strictly in order.
public final class FramedInputReader: @unchecked Sendable {
    private let handle: FileHandle
    private let queue=DispatchQueue(label:"com.viant.mechanize.framed-input")
    public init(_ handle: FileHandle) {self.handle=handle}
    public func read() async throws -> Data? {
        try await withCheckedThrowingContinuation { continuation in
            queue.async {
                do {continuation.resume(returning:try FrameCodec.read(self.handle))}
                catch {continuation.resume(throwing:error)}
            }
        }
    }
}
