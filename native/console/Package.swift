// swift-tools-version: 6.0
import PackageDescription
let package = Package(name: "MechanizeConsent", platforms: [.macOS(.v14)], products: [.executable(name: "MechanizeConsent", targets: ["MechanizeConsent"])], targets: [.target(name: "ConsentCore"), .executableTarget(name: "MechanizeConsent", dependencies: ["ConsentCore"]), .testTarget(name: "ConsentCoreTests", dependencies: ["ConsentCore"])], swiftLanguageModes: [.v5])
