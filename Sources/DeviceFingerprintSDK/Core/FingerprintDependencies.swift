import Foundation

/// SDK 依赖集合。
///
/// 所有依赖均为协议类型，默认可由 `standard()` 装配真实实现；
/// 单元测试可替换为 Mock，无需真机与网络。
public struct FingerprintDependencies {

    public let httpClient: HTTPClienting
    public let keychain: KeychainStoring
    public let collector: DeviceInfoCollecting
    public let crypto: FingerprintCryptoProviding
    /// 上报给服务端的 bundleId。
    public let bundleIdentifier: String
    /// 当前时间来源，便于测试时间校准逻辑。
    public let now: () -> Date

    public init(
        httpClient: HTTPClienting,
        keychain: KeychainStoring,
        collector: DeviceInfoCollecting,
        crypto: FingerprintCryptoProviding,
        bundleIdentifier: String,
        now: @escaping () -> Date
    ) {
        self.httpClient = httpClient
        self.keychain = keychain
        self.collector = collector
        self.crypto = crypto
        self.bundleIdentifier = bundleIdentifier
        self.now = now
    }

    /// 生产环境默认装配。
    public static func standard(
        bundleIdentifier: String = Bundle.main.bundleIdentifier ?? "unknown",
        now: @escaping () -> Date = { Date() }
    ) -> FingerprintDependencies {
        FingerprintDependencies(
            httpClient: URLSessionHTTPClient(),
            keychain: KeychainStore(),
            collector: SystemDeviceInfoCollector(),
            crypto: DefaultCryptoEngine(),
            bundleIdentifier: bundleIdentifier,
            now: now
        )
    }
}
