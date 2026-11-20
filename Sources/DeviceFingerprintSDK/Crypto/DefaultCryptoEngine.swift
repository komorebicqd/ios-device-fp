import Foundation
import Security
import CryptoKit

/// 基于 `CryptoKit` + `Security` 的默认实现。
///
/// - 对称加密：`AES.GCM`（256 位密钥，12 字节随机 IV，16 字节认证 Tag）。
/// - 非对称加密：`SecKeyCreateEncryptedData(..., .rsaEncryptionOAEPSHA256, ...)`。
/// - 签名：`HMAC<SHA256>`，输出小写十六进制。
public struct DefaultCryptoEngine: FingerprintCryptoProviding {

    public init() {}

    // MARK: - AES

    public func generateAESKey() -> Data {
        SymmetricKey(size: .bits256).withUnsafeBytes { Data($0) }
    }

    public func encryptAESGCM(plaintext: Data, key: Data) throws -> String {
        guard key.count == 32 else {
            throw FingerprintError.crypto("AES 密钥必须为 32 字节，实际 \(key.count) 字节")
        }

        // 显式生成 12 字节 IV，保证输出布局可控：IV || ciphertext || tag。
        var nonceBytes = [UInt8](repeating: 0, count: 12)
        let randomStatus = SecRandomCopyBytes(kSecRandomDefault, nonceBytes.count, &nonceBytes)
        guard randomStatus == errSecSuccess else {
            throw FingerprintError.crypto("生成随机 IV 失败，OSStatus = \(randomStatus)")
        }

        do {
            let nonce = try AES.GCM.Nonce(data: Data(nonceBytes))
            let sealed = try AES.GCM.seal(plaintext, using: SymmetricKey(data: key), nonce: nonce)

            var combined = Data(nonceBytes)
            combined.append(sealed.ciphertext)
            combined.append(sealed.tag)
            return combined.base64EncodedString()
        } catch {
            throw FingerprintError.crypto("AES-GCM 加密失败：\(error.localizedDescription)")
        }
    }

    /// 解密，仅用于自检与单元测试，业务链路不调用。
    public func decryptAESGCM(_ base64: String, key: Data) throws -> Data {
        guard let combined = Data(base64Encoded: base64) else {
            throw FingerprintError.crypto("密文不是合法的 Base64")
        }
        guard key.count == 32 else {
            throw FingerprintError.crypto("AES 密钥必须为 32 字节，实际 \(key.count) 字节")
        }
        guard combined.count >= 12 + 16 else {
            throw FingerprintError.crypto("密文长度不足，无法拆分 IV 与 Tag")
        }

        do {
            let nonce = try AES.GCM.Nonce(data: combined.prefix(12))
            let ciphertext = combined.dropFirst(12).dropLast(16)
            let tag = combined.suffix(16)
            let box = try AES.GCM.SealedBox(nonce: nonce, ciphertext: ciphertext, tag: tag)
            return try AES.GCM.open(box, using: SymmetricKey(data: key))
        } catch {
            throw FingerprintError.crypto("AES-GCM 解密失败：\(error.localizedDescription)")
        }
    }

    // MARK: - RSA

    public func encryptAESKey(_ aesKey: Data, rsaPublicKeyPEM: String) throws -> String {
        let parsedKey: ParsedRSAPublicKey
        do {
            parsedKey = try PEMRSAKeyParser.parse(pem: rsaPublicKeyPEM)
        } catch {
            throw FingerprintError.invalidPublicKey("PEM 解析失败：\(error)")
        }

        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            kSecAttrKeySizeInBits as String: parsedKey.modulusBits
        ]

        var error: Unmanaged<CFError>?
        guard let publicKey = SecKeyCreateWithData(
            parsedKey.pkcs1DER as CFData,
            attributes as CFDictionary,
            &error
        ) else {
            throw FingerprintError.invalidPublicKey(Self.describe(error))
        }

        guard SecKeyIsAlgorithmSupported(publicKey, .encrypt, .rsaEncryptionOAEPSHA256) else {
            throw FingerprintError.invalidPublicKey("该 RSA 公钥不支持 OAEP-SHA256 加密")
        }

        guard let cipher = SecKeyCreateEncryptedData(
            publicKey,
            .rsaEncryptionOAEPSHA256,
            aesKey as CFData,
            &error
        ) else {
            throw FingerprintError.crypto("RSA-OAEP 加密失败：\(Self.describe(error))")
        }

        return (cipher as Data).base64EncodedString()
    }

    // MARK: - HMAC

    public func hmacSHA256Hex(message: String, key: String) throws -> String {
        let mac = HMAC<SHA256>.authenticationCode(
            for: Data(message.utf8),
            using: SymmetricKey(data: Data(key.utf8))
        )
        var hex = ""
        mac.withUnsafeBytes { buffer in
            hex = buffer.map { String(format: "%02x", $0) }.joined()
        }
        return hex
    }

    // MARK: - Helpers

    private static func describe(_ error: Unmanaged<CFError>?) -> String {
        guard let error = error?.takeRetainedValue() else { return "未知错误" }
        return (error as Error).localizedDescription
    }
}
