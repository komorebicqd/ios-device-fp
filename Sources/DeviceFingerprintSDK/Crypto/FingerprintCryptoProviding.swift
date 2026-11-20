import Foundation

/// 加密与签名能力抽象。
///
/// 测试时可注入固定 AES 密钥 / 固定输出的 Mock，从而验证上层协议拼装是否正确。
public protocol FingerprintCryptoProviding {

    /// 生成 32 字节（256 位）随机 AES 密钥。
    func generateAESKey() -> Data

    /// AES-GCM 加密。
    /// - Returns: Base64(`12 字节 IV || 密文 || 16 字节 Tag`)
    func encryptAESGCM(plaintext: Data, key: Data) throws -> String

    /// 使用服务端下发的 PEM 公钥，以 RSA-OAEP-SHA256 加密 AES 密钥。
    /// - Returns: Base64 密文
    func encryptAESKey(_ aesKey: Data, rsaPublicKeyPEM: String) throws -> String

    /// HMAC-SHA256，返回小写十六进制字符串。
    func hmacSHA256Hex(message: String, key: String) throws -> String
}
