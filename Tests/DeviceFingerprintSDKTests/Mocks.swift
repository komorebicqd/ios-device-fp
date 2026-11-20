import Foundation
import CryptoKit
@testable import DeviceFingerprintSDK

// MARK: - Mock 网络层

/// 可控网络层：按 URL path 返回预置响应，并记录全部请求。
final class MockHTTPClient: HTTPClienting {

    struct Request {
        let url: URL
        let body: Data
        let headers: [String: String]

        var json: [String: Any] {
            (try? JSONSerialization.jsonObject(with: body)) as? [String: Any] ?? [:]
        }
    }

    private let lock = NSLock()
    private var stubs: [String: Result<Data, Error>] = [:]
    private var recorded: [Request] = []

    /// 响应延迟，用于制造并发重叠窗口（单飞测试必需）。
    var responseDelay: TimeInterval = 0

    /// 未命中 stub 时返回的错误。
    var missingStubError: Error = FingerprintError.network("Mock 未配置该 path 的响应")

    // MARK: 配置

    func stubJSON(path: String, json: String) {
        stub(path: path, result: .success(Data(json.utf8)))
    }

    func stub(path: String, result: Result<Data, Error>) {
        lock.lock()
        stubs[path] = result
        lock.unlock()
    }

    // MARK: 观察

    var requests: [Request] {
        lock.lock()
        defer { lock.unlock() }
        return recorded
    }

    func requests(forPath path: String) -> [Request] {
        requests.filter { $0.url.path == path }
    }

    // MARK: HTTPClienting

    func post(
        url: URL,
        jsonBody: Data,
        headers: [String: String],
        completion: @escaping (Result<Data, Error>) -> Void
    ) {
        lock.lock()
        recorded.append(Request(url: url, body: jsonBody, headers: headers))
        let result = stubs[url.path] ?? .failure(missingStubError)
        let delay = responseDelay
        lock.unlock()

        guard delay > 0 else {
            completion(result)
            return
        }
        DispatchQueue.global().asyncAfter(deadline: .now() + delay) {
            completion(result)
        }
    }
}

// MARK: - Mock Keychain

/// 纯内存 Keychain，线程安全。
final class MockKeychain: KeychainStoring {

    private let lock = NSLock()
    private var storage: [String: String] = [:]

    /// 每次 `string(forKey:)` 都会计数，便于断言读取行为。
    private(set) var readCount = 0
    /// 写入失败注入点（模拟 Keychain 异常）。
    var writeError: Error?

    func setString(_ value: String, forKey key: String) throws {
        if let writeError = writeError {
            throw writeError
        }
        lock.lock()
        storage[key] = value
        lock.unlock()
    }

    func string(forKey key: String) throws -> String? {
        lock.lock()
        defer { lock.unlock() }
        readCount += 1
        return storage[key]
    }

    func removeString(forKey key: String) throws {
        lock.lock()
        storage[key] = nil
        lock.unlock()
    }

    // MARK: 测试辅助

    func seed(_ value: String, forKey key: String) {
        lock.lock()
        storage[key] = value
        lock.unlock()
    }

    func value(forKey key: String) -> String? {
        lock.lock()
        defer { lock.unlock() }
        return storage[key]
    }
}

// MARK: - Mock 采集器

/// 固定特征数据采集器，同时记录 SDK 传入的锚点。
final class MockCollector: DeviceInfoCollecting {

    private let lock = NSLock()
    private(set) var lastClientAnchorId: String?
    private(set) var callCount = 0

    var info = RawDeviceInfo(
        clientAnchorId: "",
        idfv: "TEST-IDFV-0001",
        deviceModel: "iPhone16,1",
        osVersion: "17.2",
        screenWidth: 393,
        screenHeight: 852,
        screenScale: 3,
        physicalMemory: 8_589_934_592,
        totalDiskSpace: 127_000_000_000,
        cpuCount: 6,
        systemLanguages: ["zh-Hans-CN", "en-CN"],
        regionCode: "CN",
        timeZone: "Asia/Shanghai",
        isSimulator: false
    )

    func collect(clientAnchorId: String) -> RawDeviceInfo {
        lock.lock()
        lastClientAnchorId = clientAnchorId
        callCount += 1
        lock.unlock()

        var copy = info
        copy.clientAnchorId = clientAnchorId
        return copy
    }
}

// MARK: - Mock 加密

/// 可预测输出的加密实现。
///
/// 对称加密只做 Base64 包装（便于断言明文内容），HMAC 仍使用真实的 `CryptoKit`，
/// 这样测试可以独立复算签名并与服务端协议做交叉校验。
final class MockCrypto: FingerprintCryptoProviding {

    private let lock = NSLock()

    var aesKey = Data(repeating: 0x5A, count: 32)
    private var plaintexts: [Data] = []
    private var publicKeyPEMs: [String] = []
    private var signedMessages: [(message: String, key: String)] = []

    func generateAESKey() -> Data {
        aesKey
    }

    func encryptAESGCM(plaintext: Data, key: Data) throws -> String {
        lock.lock()
        plaintexts.append(plaintext)
        lock.unlock()
        return "AES[" + plaintext.base64EncodedString() + "]"
    }

    func encryptAESKey(_ aesKey: Data, rsaPublicKeyPEM: String) throws -> String {
        lock.lock()
        publicKeyPEMs.append(rsaPublicKeyPEM)
        lock.unlock()
        return "RSA[" + aesKey.base64EncodedString() + "]"
    }

    func hmacSHA256Hex(message: String, key: String) throws -> String {
        lock.lock()
        signedMessages.append((message, key))
        lock.unlock()

        let mac = HMAC<SHA256>.authenticationCode(
            for: Data(message.utf8),
            using: SymmetricKey(data: Data(key.utf8))
        )
        return mac.withUnsafeBytes { buffer in
            buffer.map { String(format: "%02x", $0) }.joined()
        }
    }

    // MARK: 观察

    var lastPlaintext: Data? {
        lock.lock()
        defer { lock.unlock() }
        return plaintexts.last
    }

    var lastPlaintextString: String? {
        lastPlaintext.flatMap { String(data: $0, encoding: .utf8) }
    }

    var lastPublicKeyPEM: String? {
        lock.lock()
        defer { lock.unlock() }
        return publicKeyPEMs.last
    }

    var lastSignedMessage: String? {
        lock.lock()
        defer { lock.unlock() }
        return signedMessages.last?.message
    }
}
