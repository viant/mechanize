// swift-tools-version: 6.0
import PackageDescription
import Foundation
let robotGoArchive = URL(fileURLWithPath: #filePath).deletingLastPathComponent().appendingPathComponent(".build/robotgo/libmechanize_robotgo.a").path
let nativeSwiftTests = Target.testTarget(name: "MechanizeNativeSwiftTests", dependencies: ["MechanizeNative", "MechanizeNativeCore"], exclude: ["README.md"])
// Explicit focused subset for command-line-tools installations without XCTest.
let nativeTestTargets: [Target] = ProcessInfo.processInfo.environment["MECHANIZE_NATIVE_SWIFT_TESTS_ONLY"] == "1" ? [nativeSwiftTests] : [.testTarget(name: "MechanizeNativeCoreTests", dependencies: ["MechanizeNativeCore"]), .testTarget(name: "MechanizeNativeTests", dependencies: ["MechanizeNative", "MechanizeNativeCore"]), nativeSwiftTests]
let package = Package(name: "MechanizeNative", platforms: [.macOS(.v14)], products: [.executable(name: "mechanize-native", targets: ["MechanizeNative"])], targets: [.target(name: "MechanizeNativeCore"), .target(name: "MechanizeRobotGoC", linkerSettings: [.unsafeFlags([robotGoArchive])]), .executableTarget(name: "MechanizeNative", dependencies: ["MechanizeNativeCore", "MechanizeRobotGoC"], swiftSettings: [.unsafeFlags(["-parse-as-library"])], linkerSettings: [.linkedLibrary("bsm")])] + nativeTestTargets, swiftLanguageModes: [.v5])
