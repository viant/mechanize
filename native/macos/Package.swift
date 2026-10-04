// swift-tools-version: 6.0
import PackageDescription
let package = Package(name: "MechanizeNative", platforms: [.macOS(.v14)], products: [.executable(name: "mechanize-native", targets: ["MechanizeNative"])], targets: [.target(name: "MechanizeNativeCore"), .executableTarget(name: "MechanizeNative", dependencies: ["MechanizeNativeCore"], linkerSettings: [.linkedLibrary("bsm")]), .testTarget(name: "MechanizeNativeCoreTests", dependencies: ["MechanizeNativeCore"]), .testTarget(name: "MechanizeNativeTests", dependencies: ["MechanizeNative", "MechanizeNativeCore"])], swiftLanguageModes: [.v5])
