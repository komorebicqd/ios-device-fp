import XCTest
import CryptoKit
@testable import DeviceFingerprintSDK

final class FingerprintServiceTests: XCTestCase {

    // MARK: - Fixtures

    private enum Fixture {
        static let sessionToken = "session-token-123"
        static let nonce = "nonce-abc"
        static let deviceId = "device-xyz"
        static let localNow = Date(timeIntervalSince1970: 1_700_000_000)

        static let initResponse = """
        {"nonce":"\(nonce)","sessionToken":"\(sessionToken)","rsaPublicKey":"-----BEGIN PUBLIC KEY-----\\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtestkey\\n-----END PUBLIC KEY-----","serverTimestamp":1700000000000}
        """

        static let generateResponse = """
        {"deviceId":"\(deviceId)","success":true}
        """
    }

    private var service: FingerprintService!
    private var http: MockHTTPClient!
    private var keychain: MockKeychain!
    private var collector: MockCollector!
    private var crypto: MockCrypto!

    override func setUp() {
        super.setUp()

        http = MockHTTPClient()
        http.stubJSON(path: "/fingerprint/init", json: Fixture.initResponse)
        http.stubJSON(path: "/fingerprint/generate", json: Fixture.generateResponse)

        keychain = MockKeychain()
        collector = MockCollector()
        crypto = MockCrypto()

        let dependencies = FingerprintDependencies(
            httpClient: http,
            keychain: keychain,
            collector: collector,
            crypto: crypto,
            bundleIdentifier: "com.example.app",
            now: { Fixture.localNow }
        )
        service = FingerprintService(
            appId: "app-1",
            baseURL: URL(string: "https://api.example.com")!,
            dependencies: dependencies
        )
    }

    override func tearDown() {
        service = nil
        http = nil
        keychain = nil
        collector = nil
        crypto = nil
        super.tearDown()
    }

    // MARK: - ① 缓存命中不发请求

    func testCachedDeviceIdInKeychainSkipsNetwork() {
        keychain.seed("cached-device-123", forKey: StorageKey.deviceId)

        var captured: Result<String, Error>?
        service.getDeviceId { captured = $0 }

        guard case .success(let deviceId)? = captured else {
            return XCTFail("缓存命中应同步返回成功，实际：\(String(describing: captured))")
        }
        XCTAssertEqual(deviceId, "cached-device-123")
        XCTAssertTrue(http.requests.isEmpty, "缓存命中时不得发起任何网络请求")
        XCTAssertEqual(keychain.readCount, 1)
    }

    func testSecondCallUsesInMemoryCacheWithoutKeychainOrNetwork() {
        let first = expectation(description: "first")
        service.getDeviceId { result in
            XCTAssertEqual(try? result.get(), Fixture.deviceId)
            first.fulfill()
        }
        wait(for: [first], timeout: 5)

        // 第二次应命中内存缓存：Keychain 不再读取，网络不再请求。
        let readsAfterFirst = keychain.readCount
        let requestsAfterFirst = http.requests.count

        var captured: Result<String, Error>?
        service.getDeviceId { captured = $0 }

        XCTAssertEqual(try? captured?.get(), Fixture.deviceId)
        XCTAssertEqual(keychain.readCount, readsAfterFirst)
        XCTAssertEqual(http.requests.count, requestsAfterFirst)
    }

    // MARK: - ② 并发 10 次只触发一次完整链路

    func testConcurrentCallsTriggerSingleInitAndGenerate() {
        http.responseDelay = 0.05

        let expectation = self.expectation(description: "10 次调用全部回调")
        expectation.expectedFulfillmentCount = 10

        let resultLock = NSLock()
        var results: [Result<String, Error>] = []

        let queue = DispatchQueue(label: "test.concurrent", attributes: .concurrent)
        let service = self.service!
        for _ in 0..<10 {
            queue.async {
                service.getDeviceId { result in
                    resultLock.lock()
                    results.append(result)
                    resultLock.unlock()
                    expectation.fulfill()
                }
            }
        }
        wait(for: [expectation], timeout: 10)

        XCTAssertEqual(http.requests(forPath: "/fingerprint/init").count, 1, "/init 只能被调用一次")
        XCTAssertEqual(http.requests(forPath: "/fingerprint/generate").count, 1, "/generate 只能被调用一次")
        XCTAssertEqual(collector.callCount, 1, "特征只应采集一次")
        XCTAssertEqual(results.count, 10)

        for result in results {
            XCTAssertEqual(try? result.get(), Fixture.deviceId)
        }
        XCTAssertEqual(keychain.value(forKey: StorageKey.deviceId), Fixture.deviceId)
    }

    // MARK: - ③ 完整链路与协议字段

    func testFullFlowStoresDeviceIdAndAnchor() {
        let expectation = self.expectation(description: "generate")
        service.getDeviceId { result in
            XCTAssertEqual(try? result.get(), Fixture.deviceId)
            expectation.fulfill()
        }
        wait(for: [expectation], timeout: 5)

        // deviceId 与锚点均已落库
        XCTAssertEqual(keychain.value(forKey: StorageKey.deviceId), Fixture.deviceId)
        let anchorId = keychain.value(forKey: StorageKey.clientAnchorId)
        XCTAssertNotNil(anchorId)
        XCTAssertEqual(collector.lastClientAnchorId, anchorId)

        // 采集到的 rawData 确实按声明顺序序列化，并包含锚点
        let rawData = try? XCTUnwrap(crypto.lastPlaintextString)
        XCTAssertNotNil(rawData)
        XCTAssertTrue(rawData?.contains("\"clientAnchorId\":\"\(anchorId ?? "")\"") ?? false)
        XCTAssertTrue(rawData?.hasPrefix("{\"clientAnchorId\":") ?? false)

        // init 请求字段
        let initBody = http.requests(forPath: "/fingerprint/init").first?.json ?? [:]
        XCTAssertEqual(initBody["appId"] as? String, "app-1")
        XCTAssertEqual(initBody["bundleId"] as? String, "com.example.app")
        XCTAssertEqual((initBody["timestamp"] as? NSNumber)?.int64Value, 1_700_000_000_000)

        // 两次请求共用同一个 tempId
        let generateBody = http.requests(forPath: "/fingerprint/generate").first?.json ?? [:]
        XCTAssertEqual(generateBody["tempId"] as? String, initBody["tempId"] as? String)
        XCTAssertEqual(generateBody["nonce"] as? String, Fixture.nonce)
    }

    func testGenerateSignatureMatchesProtocol() throws {
        let expectation = self.expectation(description: "generate")
        service.getDeviceId { _ in expectation.fulfill() }
        wait(for: [expectation], timeout: 5)

        let body = try XCTUnwrap(http.requests(forPath: "/fingerprint/generate").first?.json)
        let tempId = try XCTUnwrap(body["tempId"] as? String)
        let nonce = try XCTUnwrap(body["nonce"] as? String)
        let encryptedAesKey = try XCTUnwrap(body["encryptedAesKey"] as? String)
        let encryptedData = try XCTUnwrap(body["encryptedData"] as? String)
        let timestamp = try XCTUnwrap((body["timestamp"] as? NSNumber)?.int64Value)
        let signature = try XCTUnwrap(body["signature"] as? String)

        let expectedMessage = "\(timestamp)|\(tempId)|\(nonce)|\(encryptedAesKey)|\(encryptedData)"
        XCTAssertEqual(crypto.lastSignedMessage, expectedMessage)

        let mac = HMAC<SHA256>.authenticationCode(
            for: Data(expectedMessage.utf8),
            using: SymmetricKey(data: Data(Fixture.sessionToken.utf8))
        )
        let expectedSignature = mac.withUnsafeBytes { buffer in
            buffer.map { String(format: "%02x", $0) }.joined()
        }

        XCTAssertEqual(signature, expectedSignature)
        XCTAssertEqual(signature, signature.lowercased())
        XCTAssertEqual(signature.count, 64)
        // AES 密钥使用服务端下发的公钥加密
        XCTAssertEqual(crypto.lastPublicKeyPEM?.contains("BEGIN PUBLIC KEY"), true)
        XCTAssertTrue(encryptedAesKey.hasPrefix("RSA["))
        XCTAssertTrue(encryptedData.hasPrefix("AES["))
    }

    // MARK: - 时间校准

    func testServerTimestampCalibratesGenerateTimestamp() {
        http.stubJSON(
            path: "/fingerprint/init",
            json: """
            {"nonce":"nonce-abc","sessionToken":"session-token-123","rsaPublicKey":"PEM","serverTimestamp":1700000060000}
            """
        )

        let expectation = self.expectation(description: "generate")
        service.getDeviceId { _ in expectation.fulfill() }
        wait(for: [expectation], timeout: 5)

        let generateBody = http.requests(forPath: "/fingerprint/generate").first?.json ?? [:]
        // 本地 1_700_000_000_000 + 服务端偏移 +60_000
        XCTAssertEqual((generateBody["timestamp"] as? NSNumber)?.int64Value, 1_700_000_060_000)
    }

    // MARK: - 错误处理

    func testFailureIsSharedByWaitersAndRetryIsAllowed() {
        http.stub(path: "/fingerprint/init", result: .failure(FingerprintError.network("boom")))
        http.responseDelay = 0.05

        let failureExpectation = expectation(description: "3 个等待者都失败")
        failureExpectation.expectedFulfillmentCount = 3

        let resultLock = NSLock()
        var failures = 0

        let queue = DispatchQueue(label: "test.failure", attributes: .concurrent)
        let service = self.service!
        for _ in 0..<3 {
            queue.async {
                service.getDeviceId { result in
                    if case .failure = result {
                        resultLock.lock()
                        failures += 1
                        resultLock.unlock()
                    }
                    failureExpectation.fulfill()
                }
            }
        }
        wait(for: [failureExpectation], timeout: 10)

        XCTAssertEqual(failures, 3)
        XCTAssertEqual(http.requests(forPath: "/fingerprint/init").count, 1, "失败态同样只触发一次 /init")
        XCTAssertNil(keychain.value(forKey: StorageKey.deviceId))

        // 失败不应污染状态：下一次调用可以重新走链路
        http.stubJSON(path: "/fingerprint/init", json: Fixture.initResponse)
        http.responseDelay = 0

        let retryExpectation = expectation(description: "retry")
        service.getDeviceId { result in
            XCTAssertEqual(try? result.get(), Fixture.deviceId)
            retryExpectation.fulfill()
        }
        wait(for: [retryExpectation], timeout: 5)

        XCTAssertEqual(http.requests(forPath: "/fingerprint/init").count, 2)
    }

    func testServerRejectionPropagatesAndDoesNotCache() {
        http.stubJSON(path: "/fingerprint/generate", json: #"{"deviceId":"","success":false}"#)

        let expectation = self.expectation(description: "rejected")
        service.getDeviceId { result in
            guard case .failure(let error) = result else {
                return XCTFail("success=false 时必须返回失败")
            }
            XCTAssertEqual(error as? FingerprintError, .serverRejected("服务端未返回有效 deviceId"))
            expectation.fulfill()
        }
        wait(for: [expectation], timeout: 5)

        XCTAssertNil(keychain.value(forKey: StorageKey.deviceId))
    }

    func testKeychainWriteFailureSurfacesAsError() {
        keychain.writeError = FingerprintError.keychain(-34018)

        let expectation = self.expectation(description: "write failure")
        service.getDeviceId { result in
            guard case .failure(let error) = result else {
                return XCTFail("Keychain 写入失败时不应返回成功")
            }
            XCTAssertEqual(error as? FingerprintError, .keychain(-34018))
            expectation.fulfill()
        }
        wait(for: [expectation], timeout: 5)
    }

    func testMalformedInitResponseFails() {
        http.stubJSON(path: "/fingerprint/init", json: #"{"nonce":"","sessionToken":"t","rsaPublicKey":"pem","serverTimestamp":1700000000000}"#)

        let expectation = self.expectation(description: "invalid response")
        service.getDeviceId { result in
            guard case .failure(let error) = result,
                  let fingerprintError = error as? FingerprintError,
                  case .invalidResponse(_) = fingerprintError else {
                return XCTFail("空 nonce 应被识别为非法响应，实际：\(result)")
            }
            expectation.fulfill()
        }
        wait(for: [expectation], timeout: 5)

        XCTAssertTrue(http.requests(forPath: "/fingerprint/generate").isEmpty)
    }
}

// MARK: - 门面层

final class FingerprintSDKFacadeTests: XCTestCase {

    override func tearDown() {
        FingerprintSDK.reset()
        super.tearDown()
    }

    func testUnconfiguredThrows() {
        FingerprintSDK.reset()

        let expectation = expectation(description: "not configured")
        FingerprintSDK.getDeviceId { result in
            guard case .failure(let error) = result else {
                return XCTFail("未配置时不应返回成功")
            }
            XCTAssertEqual(error as? FingerprintError, .notConfigured)
            expectation.fulfill()
        }
        wait(for: [expectation], timeout: 1)
    }

    func testFacadeReturnsCachedDeviceIdWithoutNetwork() {
        let keychain = MockKeychain()
        keychain.seed("facade-device-id", forKey: StorageKey.deviceId)

        let http = MockHTTPClient()
        let dependencies = FingerprintDependencies(
            httpClient: http,
            keychain: keychain,
            collector: MockCollector(),
            crypto: MockCrypto(),
            bundleIdentifier: "com.example.app",
            now: { Date() }
        )

        FingerprintSDK.configure(appId: "app-1", baseURL: "https://api.example.com", dependencies: dependencies)

        var captured: Result<String, Error>?
        FingerprintSDK.getDeviceId { captured = $0 }

        XCTAssertEqual(try? captured?.get(), "facade-device-id")
        XCTAssertTrue(http.requests.isEmpty)
    }

    func testInvalidBaseURLSurfacesConfigurationError() {
        FingerprintSDK.configure(
            appId: "app-1",
            baseURL: "ftp://api.example.com",
            dependencies: FingerprintDependencies(
                httpClient: MockHTTPClient(),
                keychain: MockKeychain(),
                collector: MockCollector(),
                crypto: MockCrypto(),
                bundleIdentifier: "com.example.app",
                now: { Date() }
            )
        )

        let expectation = expectation(description: "invalid base url")
        FingerprintSDK.getDeviceId { result in
            guard case .failure(let error) = result else {
                return XCTFail("非法 baseURL 不应返回成功")
            }
            XCTAssertEqual(error as? FingerprintError, .invalidBaseURL("ftp://api.example.com"))
            expectation.fulfill()
        }
        wait(for: [expectation], timeout: 1)
    }

    func testAsyncAwaitWrapperReturnsDeviceId() async throws {
        let keychain = MockKeychain()
        keychain.seed("async-device-id", forKey: StorageKey.deviceId)

        let dependencies = FingerprintDependencies(
            httpClient: MockHTTPClient(),
            keychain: keychain,
            collector: MockCollector(),
            crypto: MockCrypto(),
            bundleIdentifier: "com.example.app",
            now: { Date() }
        )
        FingerprintSDK.configure(appId: "app-1", baseURL: "https://api.example.com", dependencies: dependencies)

        let deviceId = try await FingerprintSDK.getDeviceId()
        XCTAssertEqual(deviceId, "async-device-id")
    }
}
