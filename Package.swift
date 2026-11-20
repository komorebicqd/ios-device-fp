// swift-tools-version:5.7
import PackageDescription

let package = Package(
    name: "DeviceFingerprintSDK",
    // iOS 为真实使用目标；macOS 仅用于在 CI / 本机直接执行 `swift test`（UIKit 相关代码已做条件编译）。
    platforms: [
        .iOS(.v13),
        .macOS(.v12)
    ],
    products: [
        .library(name: "DeviceFingerprintSDK", targets: ["DeviceFingerprintSDK"])
    ],
    targets: [
        .target(
            name: "DeviceFingerprintSDK",
            path: "Sources/DeviceFingerprintSDK"
        ),
        .testTarget(
            name: "DeviceFingerprintSDKTests",
            dependencies: ["DeviceFingerprintSDK"],
            path: "Tests/DeviceFingerprintSDKTests"
        )
    ],
    // 固定 Swift 5 语言模式：Swift 6 工具链下也能以 Swift 5 语义稳定编译。
    swiftLanguageVersions: [.v5]
)
