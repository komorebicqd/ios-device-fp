import Foundation

/// 基于 `URLSession` 的默认网络实现。
public final class URLSessionHTTPClient: HTTPClienting {

    private let session: URLSession
    private let timeout: TimeInterval

    public init(session: URLSession = .shared, timeout: TimeInterval = 15) {
        self.session = session
        self.timeout = timeout
    }

    public func post(
        url: URL,
        jsonBody: Data,
        headers: [String: String],
        completion: @escaping (Result<Data, Error>) -> Void
    ) {
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.httpBody = jsonBody
        request.timeoutInterval = timeout
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        headers.forEach { request.setValue($0.value, forHTTPHeaderField: $0.key) }

        session.dataTask(with: request) { data, response, error in
            if let error = error {
                completion(.failure(FingerprintError.network(error.localizedDescription)))
                return
            }
            guard let httpResponse = response as? HTTPURLResponse else {
                completion(.failure(FingerprintError.invalidResponse("响应不是 HTTPURLResponse")))
                return
            }
            let body = data ?? Data()
            guard (200..<300).contains(httpResponse.statusCode) else {
                completion(.failure(FingerprintError.httpStatus(
                    code: httpResponse.statusCode,
                    body: String(data: body, encoding: .utf8)
                )))
                return
            }
            completion(.success(body))
        }.resume()
    }
}
