// swift-tools-version: 6.0
import PackageDescription
import Foundation
let focusedTests = Target.testTarget(name: "ConsentCoreSwiftTests", dependencies: ["ConsentCore"])
let testTargets: [Target] = ProcessInfo.processInfo.environment["MECHANIZE_CONSOLE_SWIFT_TESTS_ONLY"] == "1" ? [focusedTests] : [.testTarget(name: "ConsentCoreTests", dependencies: ["ConsentCore"]), .testTarget(name: "MechanizeConsentLayoutTests", dependencies: ["MechanizeConsent"]), focusedTests]
let package = Package(name: "MechanizeConsent", platforms: [.macOS(.v14)], products: [.executable(name: "MechanizeConsent", targets: ["MechanizeConsent"])], targets: [.target(name: "ConsentCore"), .executableTarget(name: "MechanizeConsent", dependencies: ["ConsentCore"])] + testTargets, swiftLanguageModes: [.v5])
