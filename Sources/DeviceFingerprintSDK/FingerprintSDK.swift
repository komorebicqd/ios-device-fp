import Foundation

/// 设备指纹 SDK 对外门面。
///
/// 使用方式：
/// ```swift
/// FingerprintSDK.configure(appId: "your-app-id", baseURL: "https://api.example.com")
/// FingerprintSDK.getDeviceId { result in
///     switch result {
///     case .success(let deviceId): print(deviceId)
///     case .failure(let error): print(error)
///     }
/// }
/// ```
///
/// 注：`getDeviceId` 的回调不保证在主线程执行；如需更新 UI，请自行切回主线程。
public final class FingerprintSDK {

    public static let shared = FingerprintSDK()

    private let lock = NSLock()
    private var service: FingerprintService?
    private var configurationError: FingerprintError?

    private init() {}

    // MARK: - 配置

    /// 生产环境配置，内部装配 `URLSession` / Keychain / 系统采集 / CryptoKit。
    public static func configure(appId: String, baseURL: String) {
        shared.apply(appId: appId, baseURL: baseURL, dependencies: .standard())
    }

    /// 可注入依赖的配置入口（单元测试 / 自定义网络栈）。
    public static func configure(appId: String, baseURL: String, dependencies: FingerprintDependencies) {
        shared.apply(appId: appId, baseURL: baseURL, dependencies: dependencies)
    }

    /// 清空内部状态（内存缓存、时间偏移、进行中的服务实例）。
    ///
    /// 不会删除 Keychain 中的 `deviceId` / `clientAnchorId`；
    /// 典型用途是测试隔离或切换账号后重新配置。
    public static func reset() {
        shared.lock.lock()
        shared.service = nil
        shared.configurationError = nil
        shared.lock.unlock()
    }

    // MARK: - 获取 deviceId

    /// 异步获取设备指纹 ID（回调可能同步完成，也可能在任意队列回调）。
    public static func getDeviceId(completion: @escaping (Result<String, Error>) -> Void) {
        do {
            try shared.currentService().getDeviceId(completion: completion)
        } catch {
            completion(.failure(error))
        }
    }

    /// `getDeviceId` 的 async/await 封装。
    public static func getDeviceId() async throws -> String {
        try await withCheckedThrowingContinuation { continuation in
            getDeviceId { result in
                continuation.resume(with: result)
            }
        }
    }

    // MARK: - Private

    private func apply(appId: String, baseURL: String, dependencies: FingerprintDependencies) {
        let newService: FingerprintService?
        let error: FingerprintError?

        if let url = Self.makeBaseURL(from: baseURL) {
            newService = FingerprintService(appId: appId, baseURL: url, dependencies: dependencies)
            error = nil
        } else {
            newService = nil
            error = .invalidBaseURL(baseURL)
        }

        lock.lock()
        service = newService
        configurationError = error
        lock.unlock()
    }

    private func currentService() throws -> FingerprintService {
        lock.lock()
        defer { lock.unlock() }

        if let service = service {
            return service
        }
        throw configurationError ?? FingerprintError.notConfigured
    }

    private static func makeBaseURL(from string: String) -> URL? {
        guard let url = URL(string: string),
              let scheme = url.scheme?.lowercased(),
              scheme == "http" || scheme == "https",
              url.host != nil else {
            return nil
        }
        return url
    }
}
