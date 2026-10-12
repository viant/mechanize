// swift-tools-version: 6.0
import PackageDescription
import Foundation
let robotGoArchive = URL(fileURLWithPath: #filePath).deletingLastPathComponent().appendingPathComponent(".build/robotgo/libmechanize_robotgo.a").path
let package = Package(name: "MechanizeNative", platforms: [.macOS(.v14)], products: [.executable(name: "mechanize-native", targets: ["MechanizeNative"])], targets: [.target(name: "MechanizeNativeCore"), .target(name: "MechanizeRobotGoC", linkerSettings: [.unsafeFlags([robotGoArchive])]), .executableTarget(name: "MechanizeNative", dependencies: ["MechanizeNativeCore", "MechanizeRobotGoC"], linkerSettings: [.linkedLibrary("bsm")]), .testTarget(name: "MechanizeNativeCoreTests", dependencies: ["MechanizeNativeCore"]), .testTarget(name: "MechanizeNativeTests", dependencies: ["MechanizeNative", "MechanizeNativeCore"])], swiftLanguageModes: [.v5])
