import Foundation
import MechanizeRobotGoC
import MechanizeNativeCore

// RobotGo runs inside this helper's existing signed process and InputSafety
// lane. Geometry/owner/consent preflight remains independent of the driver.
enum RobotGoPointer {
    static func move(to point: CGPoint) throws {
        guard MechanizeRobotGoMove(point.x, point.y) == 0 else {
            throw NativeFailure("robotGoMoveUnconfirmed", "RobotGo cursor movement was not confirmed")
        }
    }
    static func down(at point: CGPoint) -> Bool { MechanizeRobotGoDown(point.x, point.y) == 0 }
    static func up() -> Bool { MechanizeRobotGoUp() == 0 }
}
