import Foundation

/// 指纹生成调度器：缓存、单飞、时间校准与完整 `/init` -> `/generate` 链路的唯一入口。
final class FingerprintService {

    private let appId: String
    private let baseURL: URL
    private let dependencies: FingerprintDependencies

    /// 保护 `cachedDeviceId` / `isInFlight` / `waiters` / `serverTimeOffsetMillis`。
    private let lock = NSLock()

    private var cachedDeviceId: String?
    private var isInFlight = false
    private var waiters: [(Result<String, Error>) -> Void] = []
    private var serverTimeOffsetMillis: Int64 = 0

    init(appId: String, baseURL: URL, dependencies: FingerprintDependencies) {
        self.appId = appId
        self.baseURL = baseURL
        self.dependencies = dependencies
    }

    // MARK: - 对外入口

    /// 获取 deviceId。
    ///
    /// 语义保证：
    /// 1. 内存缓存 / Keychain 命中时直接返回，不发起任何请求；
    /// 2. 缓存未命中时，同一时刻只有一次完整链路在飞行，其余调用挂起并共享同一结果；
    /// 3. 链路失败时所有等待者收到同一错误，并允许后续调用重新发起（不缓存失败）。
    func getDeviceId(completion: @escaping (Result<String, Error>) -> Void) {
        if let cached = currentCachedDeviceId() {
            completion(.success(cached))
            return
        }

        let storedDeviceId: String?
        do {
            storedDeviceId = try dependencies.keychain.string(forKey: StorageKey.deviceId)
        } catch {
            completion(.failure(error))
            return
        }

        if let storedDeviceId = storedDeviceId, !storedDeviceId.isEmpty {
            storeInMemory(deviceId: storedDeviceId)
            completion(.success(storedDeviceId))
            return
        }

        lock.lock()
        // 双重检查：并发调用可能已在等待 Keychain 读取期间完成过一次链路。
        if let cached = cachedDeviceId {
            lock.unlock()
            completion(.success(cached))
            return
        }
        if isInFlight {
            waiters.append(completion)
            lock.unlock()
            return
        }
        isInFlight = true
        waiters.append(completion)
        lock.unlock()

        runFullFlow { result in
            self.finish(result)
        }
    }

    // MARK: - 完整链路

    private func runFullFlow(completion: @escaping (Result<String, Error>) -> Void) {
        let tempId = UUID().uuidString
        let request = InitRequestBody(
            appId: appId,
            bundleId: dependencies.bundleIdentifier,
            tempId: tempId,
            timestamp: currentEpochMillis()
        )

        performPost(path: Endpoint.initialize, body: request) { [weak self] (result: Result<InitResponseBody, Error>) in
            guard let self = self else {
                completion(.failure(FingerprintError.notConfigured))
                return
            }
            switch result {
            case .failure(let error):
                completion(.failure(error))
            case .success(let response):
                do {
                    try self.generateDeviceId(initResponse: response, tempId: tempId, completion: completion)
                } catch {
                    completion(.failure(error))
                }
            }
        }
    }

    /// Step 2 ~ Step 4：采集、加密、签名、上报。
    private func generateDeviceId(
        initResponse: InitResponseBody,
        tempId: String,
        completion: @escaping (Result<String, Error>) -> Void
    ) throws {
        guard !initResponse.nonce.isEmpty,
              !initResponse.sessionToken.isEmpty,
              !initResponse.rsaPublicKey.isEmpty,
              initResponse.serverTimestamp > 0 else {
            throw FingerprintError.invalidResponse("/fingerprint/init 返回的 nonce / sessionToken / rsaPublicKey / serverTimestamp 不完整")
        }

        updateServerTimeOffset(serverTimestampMillis: initResponse.serverTimestamp)

        let anchorId = try loadOrCreateAnchorId()
        let rawInfo = dependencies.collector.collect(clientAnchorId: anchorId)
        let rawData = Data(rawInfo.orderedJSONString().utf8)

        let aesKey = dependencies.crypto.generateAESKey()
        let encryptedData = try dependencies.crypto.encryptAESGCM(plaintext: rawData, key: aesKey)
        let encryptedAesKey = try dependencies.crypto.encryptAESKey(aesKey, rsaPublicKeyPEM: initResponse.rsaPublicKey)

        let timestamp = calibratedEpochMillis()
        let stringToSign = SignatureComposer.stringToSign(
            timestamp: timestamp,
            tempId: tempId,
            nonce: initResponse.nonce,
            encryptedAesKey: encryptedAesKey,
            encryptedData: encryptedData
        )
        let signature = try dependencies.crypto.hmacSHA256Hex(message: stringToSign, key: initResponse.sessionToken)

        let body = GenerateRequestBody(
            tempId: tempId,
            nonce: initResponse.nonce,
            encryptedAesKey: encryptedAesKey,
            encryptedData: encryptedData,
            timestamp: timestamp,
            signature: signature
        )

        performPost(path: Endpoint.generate, body: body) { [weak self] (result: Result<GenerateResponseBody, Error>) in
            guard let self = self else {
                completion(.failure(FingerprintError.notConfigured))
                return
            }
            switch result {
            case .failure(let error):
                completion(.failure(error))
            case .success(let response):
                guard response.success, !response.deviceId.isEmpty else {
                    completion(.failure(FingerprintError.serverRejected("服务端未返回有效 deviceId")))
                    return
                }
                do {
                    try self.dependencies.keychain.setString(response.deviceId, forKey: StorageKey.deviceId)
                    self.storeInMemory(deviceId: response.deviceId)
                    completion(.success(response.deviceId))
                } catch {
                    completion(.failure(error))
                }
            }
        }
    }

    // MARK: - 单飞结果广播

    private func finish(_ result: Result<String, Error>) {
        lock.lock()
        isInFlight = false
        if case .success(let deviceId) = result {
            cachedDeviceId = deviceId
        }
        let waiting = waiters
        waiters.removeAll()
        lock.unlock()

        waiting.forEach { $0(result) }
    }

    // MARK: - 缓存

    private func currentCachedDeviceId() -> String? {
        lock.lock()
        defer { lock.unlock() }
        return cachedDeviceId
    }

    private func storeInMemory(deviceId: String) {
        lock.lock()
        cachedDeviceId = deviceId
        lock.unlock()
    }

    // MARK: - 锚点

    private func loadOrCreateAnchorId() throws -> String {
        if let existing = try dependencies.keychain.string(forKey: StorageKey.clientAnchorId), !existing.isEmpty {
            return existing
        }
        let newAnchorId = UUID().uuidString
        try dependencies.keychain.setString(newAnchorId, forKey: StorageKey.clientAnchorId)
        return newAnchorId
    }

    // MARK: - 时间校准

    private func currentEpochMillis() -> Int64 {
        Int64((dependencies.now().timeIntervalSince1970 * 1000).rounded())
    }

    /// 使用服务端时间偏移校准后的毫秒时间戳。
    private func calibratedEpochMillis() -> Int64 {
        lock.lock()
        let offset = serverTimeOffsetMillis
        lock.unlock()
        return currentEpochMillis() + offset
    }

    private func updateServerTimeOffset(serverTimestampMillis: Int64) {
        let offset = serverTimestampMillis - currentEpochMillis()
        lock.lock()
        serverTimeOffsetMillis = offset
        lock.unlock()
    }

    // MARK: - 请求

    private func performPost<RequestBody: Encodable, ResponseBody: Decodable>(
        path: String,
        body: RequestBody,
        completion: @escaping (Result<ResponseBody, Error>) -> Void
    ) {
        let url = baseURL.appendingPathComponent(path)

        let payload: Data
        do {
            payload = try JSONEncoder().encode(body)
        } catch {
            completion(.failure(FingerprintError.encoding("\(path) 请求体编码失败：\(error.localizedDescription)")))
            return
        }

        dependencies.httpClient.post(
            url: url,
            jsonBody: payload,
            headers: ["Content-Type": "application/json", "Accept": "application/json"]
        ) { result in
            switch result {
            case .failure(let error):
                completion(.failure(error))
            case .success(let data):
                do {
                    completion(.success(try JSONDecoder().decode(ResponseBody.self, from: data)))
                } catch {
                    let snippet = String(data: data, encoding: .utf8).map { String($0.prefix(256)) } ?? ""
                    completion(.failure(FingerprintError.invalidResponse(
                        "\(path) 响应解析失败：\(error.localizedDescription)，body=\(snippet)"
                    )))
                }
            }
        }
    }
}
