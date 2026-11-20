import Foundation

/// SDK 对外统一的错误类型。
///
/// 所有错误消息只包含用于排查的描述，不会携带任何密钥、`sessionToken` 或原始特征数据。
public enum FingerprintError: Error, LocalizedError, Equatable {

    /// 尚未调用 `FingerprintSDK.configure(appId:baseURL:)`。
    case notConfigured

    /// `baseURL` 不是合法的 http/https 地址。
    case invalidBaseURL(String)

    /// Keychain 操作失败，携带 `OSStatus`。
    case keychain(OSStatus)

    /// 请求体编码失败。
    case encoding(String)

    /// 网络层错误（DNS、超时、连接中断等）。
    case network(String)

    /// 服务端返回了非 2xx 状态码。
    case httpStatus(code: Int, body: String?)

    /// 响应结构不符合预期，或字段为空。
    case invalidResponse(String)

    /// 服务端明确拒绝生成指纹（如 `success == false`）。
    case serverRejected(String)

    /// 服务端下发的 RSA 公钥无法解析或不受支持。
    case invalidPublicKey(String)

    /// 加解密、签名过程中出现的错误。
    case crypto(String)

    public var errorDescription: String? {
        switch self {
        case .notConfigured:
            return "FingerprintSDK 尚未配置，请先调用 FingerprintSDK.configure(appId:baseURL:)。"
        case .invalidBaseURL(let url):
            return "非法的 baseURL：\(url)，仅支持 http / https 且必须包含 host。"
        case .keychain(let status):
            return "Keychain 操作失败，OSStatus = \(status)。"
        case .encoding(let message):
            return "请求体编码失败：\(message)"
        case .network(let message):
            return "网络请求失败：\(message)"
        case .httpStatus(let code, let body):
            let snippet = body.map { "，响应：\(String($0.prefix(256)))" } ?? ""
            return "服务端返回 HTTP \(code)\(snippet)"
        case .invalidResponse(let message):
            return "响应数据不合法：\(message)"
        case .serverRejected(let message):
            return "服务端拒绝生成指纹：\(message)"
        case .invalidPublicKey(let message):
            return "RSA 公钥不可用：\(message)"
        case .crypto(let message):
            return "加密/签名失败：\(message)"
        }
    }
}
