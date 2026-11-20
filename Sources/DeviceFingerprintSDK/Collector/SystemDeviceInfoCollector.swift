import Foundation

#if canImport(UIKit)
import UIKit
#endif

/// 基于 Apple 公开 API 的真实采集实现。
///
/// 所有取值均来自 `UIKit` / `Foundation` / POSIX `uname`，不包含任何私有 API、
/// 越狱探测或 App Store 审核敏感行为。
public struct SystemDeviceInfoCollector: DeviceInfoCollecting {

    public init() {}

    public func collect(clientAnchorId: String) -> RawDeviceInfo {
        let screen = Self.screenMetrics()
        return RawDeviceInfo(
            clientAnchorId: clientAnchorId,
            idfv: Self.identifierForVendor,
            deviceModel: Self.machineIdentifier,
            osVersion: Self.osVersion,
            screenWidth: screen.width,
            screenHeight: screen.height,
            screenScale: screen.scale,
            physicalMemory: ProcessInfo.processInfo.physicalMemory,
            totalDiskSpace: Self.totalDiskSpace,
            cpuCount: ProcessInfo.processInfo.processorCount,
            systemLanguages: Locale.preferredLanguages,
            regionCode: Self.regionCode,
            timeZone: TimeZone.current.identifier,
            isSimulator: Self.isSimulator
        )
    }

    // MARK: - 硬件

    /// `uname().machine`，例如 `iPhone16,1`。模拟器上返回宿主架构（如 `arm64`）。
    private static var machineIdentifier: String {
        var systemInfo = utsname()
        uname(&systemInfo)
        let mirror = Mirror(reflecting: systemInfo.machine)
        var identifier = ""
        for child in mirror.children {
            guard let value = child.value as? Int8, value != 0 else { break }
            identifier.append(Character(UnicodeScalar(UInt8(bitPattern: value))))
        }
        return identifier
    }

    private static var totalDiskSpace: UInt64 {
        let attributes = try? FileManager.default.attributesOfFileSystem(forPath: NSHomeDirectory())
        return (attributes?[.systemSize] as? NSNumber)?.uint64Value ?? 0
    }

    // MARK: - 系统 / 环境

    private static var osVersion: String {
        #if canImport(UIKit)
        return UIDevice.current.systemVersion
        #else
        let version = ProcessInfo.processInfo.operatingSystemVersion
        return "\(version.majorVersion).\(version.minorVersion).\(version.patchVersion)"
        #endif
    }

    private static var identifierForVendor: String {
        #if canImport(UIKit)
        return UIDevice.current.identifierForVendor?.uuidString ?? ""
        #else
        return ""
        #endif
    }

    private static var regionCode: String {
        if #available(iOS 16.0, macOS 13.0, *) {
            return Locale.current.region?.identifier ?? Locale.current.identifier
        } else {
            return Locale.current.regionCode ?? Locale.current.identifier
        }
    }

    private static var isSimulator: Bool {
        #if targetEnvironment(simulator)
        return true
        #else
        return false
        #endif
    }

    private static var screenMetrics: (width: Int, height: Int, scale: Double) {
        #if canImport(UIKit)
        let bounds = UIScreen.main.bounds
        return (
            Int(bounds.width.rounded()),
            Int(bounds.height.rounded()),
            Double(UIScreen.main.scale)
        )
        #else
        return (0, 0, 1)
        #endif
    }
}
