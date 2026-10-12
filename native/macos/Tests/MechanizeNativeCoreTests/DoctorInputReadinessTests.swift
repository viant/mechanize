import XCTest
@testable import MechanizeNativeCore

final class DoctorInputReadinessTests: XCTestCase {
    func testEveryFlagCombinationPreservesOutputsWithAtMostOneProbe() {
        let routes = ControlReadinessRoute.allCases
        for mask in 0..<8 {
            let requested = Set(routes.enumerated().filter { mask & (1 << $0.offset) != 0 }.map { $0.element })
            for semantic in [false, true] {
                for eventPost in [false, true] {
                    for result in [ControlReadinessProbeResult.ready, .sessionUnqualified, .foregroundUnavailable] {
                        var calls = 0
                        let reply = DoctorInputReadiness.evaluate(semantic: semantic, eventPost: eventPost, requested: requested) { calls += 1; return result }
                        let eligible = semantic && eventPost && mask != 0
                        XCTAssertEqual(calls, eligible ? 1 : 0)
                        for route in routes {
                            XCTAssertEqual(reply.enabled[route], semantic && eventPost && requested.contains(route) && result == .ready)
                            XCTAssertEqual(reply.probes[route], eligible && requested.contains(route) ? result : nil)
                        }
                    }
                }
            }
        }
    }
    func testErrorFailsAllRequestedRoutesAndNextReplyReprobes() {
        var calls = 0
        let reply = DoctorInputReadiness.evaluate(semantic: true, eventPost: true, requested: Set(ControlReadinessRoute.allCases)) {
            calls += 1
            throw NativeFailure("PRIVATE_ERROR_CANARY", "PRIVATE_MESSAGE_CANARY")
        }
        XCTAssertEqual(calls, 1)
        for route in ControlReadinessRoute.allCases {
            XCTAssertEqual(reply.enabled[route], false)
            XCTAssertEqual(reply.probes[route], .probeUnavailable)
        }
        let next = DoctorInputReadiness.evaluate(semantic: true, eventPost: true, requested: [.sessionText]) { calls += 1; return .ready }
        XCTAssertEqual(calls, 2)
        XCTAssertEqual(next.enabled[.sessionText], true)
    }
}
