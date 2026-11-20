import Foundation

/// 网络层抽象。测试时注入 Mock 即可完全控制响应与耗时。
public protocol HTTPClienting {
    /// 发送 JSON POST 请求。
    /// - Parameter completion: 成功返回响应 body；失败返回 `FingerprintError.network` /
    ///   `FingerprintError.httpStatus` 等错误。
    func post(
        url: URL,
        jsonBody: Data,
        headers: [String: String],
        completion: @escaping (Result<Data, Error>) -> Void
    )
}
