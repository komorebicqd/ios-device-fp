import XCTest
import CryptoKit
import Security
@testable import DeviceFingerprintSDK

/// 验证密码学实现与线上协议一致：AES-GCM 布局、HMAC-SHA256、RSA-OAEP-SHA256。
final class CryptoEngineTests: XCTestCase {

    private let engine = DefaultCryptoEngine()

    // MARK: - AES-GCM

    func testAESGCMOutputLayoutIsIVCiphertextTag() throws {
        let plaintext = Data("device-fingerprint-raw-data".utf8)
        let key = engine.generateAESKey()
        XCTAssertEqual(key.count, 32, "AES 密钥必须为 256 位")

        let base64 = try engine.encryptAESGCM(plaintext: plaintext, key: key)
        let combined = try XCTUnwrap(Data(base64Encoded: base64))

        // 12 字节 IV + 密文（与明文等长）+ 16 字节 Tag
        XCTAssertEqual(combined.count, 12 + plaintext.count + 16)

        let nonce = combined.prefix(12)
        let ciphertext = combined.dropFirst(12).dropLast(16)
        let tag = combined.suffix(16)
        XCTAssertEqual(ciphertext.count, plaintext.count)
        XCTAssertEqual(tag.count, 16)

        // 按协议拆分后可以独立还原明文
        let box = try AES.GCM.SealedBox(
            nonce: try AES.GCM.Nonce(data: nonce),
            ciphertext: ciphertext,
            tag: tag
        )
        let opened = try AES.GCM.open(box, using: SymmetricKey(data: key))
        XCTAssertEqual(opened, plaintext)

        // SDK 内置解密路径
        XCTAssertEqual(try engine.decryptAESGCM(base64, key: key), plaintext)
    }

    func testAESGCMUsesRandomIVPerCall() throws {
        let plaintext = Data("same-plaintext".utf8)
        let key = engine.generateAESKey()

        let first = try engine.encryptAESGCM(plaintext: plaintext, key: key)
        let second = try engine.encryptAESGCM(plaintext: plaintext, key: key)

        XCTAssertNotEqual(first, second, "每次加密必须使用新的随机 IV")

        let firstIV = try XCTUnwrap(Data(base64Encoded: first)?.prefix(12))
        let secondIV = try XCTUnwrap(Data(base64Encoded: second)?.prefix(12))
        XCTAssertNotEqual(Data(firstIV), Data(secondIV))
    }

    func testAESGCMRejectsInvalidKeyLength() {
        XCTAssertThrowsError(try engine.encryptAESGCM(plaintext: Data("x".utf8), key: Data(repeating: 1, count: 16))) { error in
            guard let fingerprintError = error as? FingerprintError,
                  case .crypto = fingerprintError else {
                return XCTFail("密钥长度非法时应抛出 .crypto，实际：\(error)")
            }
        }
    }

    func testDecryptRejectsTamperedCiphertext() throws {
        let plaintext = Data("tamper-check".utf8)
        let key = engine.generateAESKey()
        var combined = try XCTUnwrap(Data(base64Encoded: try engine.encryptAESGCM(plaintext: plaintext, key: key)))
        combined[13] ^= 0xFF

        XCTAssertThrowsError(try engine.decryptAESGCM(combined.base64EncodedString(), key: key))
    }

    // MARK: - HMAC-SHA256

    func testHMACSHA256MatchesKnownVector() throws {
        // 由独立实现（.NET HMACSHA256）计算出的参考值
        let key = "session-token-123"
        let message = "1700000000000|temp-1|nonce-1|RSA-ENC|AES-ENC"
        let expected = "93b89250252aa1cf4b43cb1e62af10322deb34fd4cba1bcb24e53315fe9ef96d"

        let signature = try engine.hmacSHA256Hex(message: message, key: key)
        XCTAssertEqual(signature, expected)
        XCTAssertEqual(signature, signature.lowercased())
    }

    func testStringToSignUsesPipeSeparatorInFixedOrder() {
        let value = SignatureComposer.stringToSign(
            timestamp: 1_700_000_000_000,
            tempId: "temp-1",
            nonce: "nonce-1",
            encryptedAesKey: "ENC-KEY",
            encryptedData: "ENC-DATA"
        )
        XCTAssertEqual(value, "1700000000000|temp-1|nonce-1|ENC-KEY|ENC-DATA")
        XCTAssertEqual(value.components(separatedBy: "|").count, 5)
    }

    // MARK: - RSA-OAEP-SHA256

    func testRSAOAEPEncryptsAESKeyWithSPKIAndPKCS1PEM() throws {
        let privateKey = try makeRSAKeyPair()
        let publicKey = try XCTUnwrap(SecKeyCopyPublicKey(privateKey))
        let external = try XCTUnwrap(SecKeyCopyExternalRepresentation(publicKey, nil), "导出公钥失败")
        let pkcs1 = external as Data

        let aesKey = engine.generateAESKey()

        // ① X.509 SubjectPublicKeyInfo（`BEGIN PUBLIC KEY`）—— 需要剥离 ASN.1 外壳
        let spkiPEM = Self.spkiPEM(fromPKCS1: pkcs1)
        let spkiCipher = try XCTUnwrap(Data(base64Encoded: try engine.encryptAESKey(aesKey, rsaPublicKeyPEM: spkiPEM)))
        XCTAssertEqual(try decrypt(spkiCipher, with: privateKey), aesKey)

        // ② PKCS#1（`BEGIN RSA PUBLIC KEY`）—— 直接使用
        let pkcs1PEM = Self.pem(body: pkcs1, header: "RSA PUBLIC KEY")
        let pkcs1Cipher = try XCTUnwrap(Data(base64Encoded: try engine.encryptAESKey(aesKey, rsaPublicKeyPEM: pkcs1PEM)))
        XCTAssertEqual(try decrypt(pkcs1Cipher, with: privateKey), aesKey)
    }

    func testInvalidPEMThrowsInvalidPublicKey() {
        XCTAssertThrowsError(try engine.encryptAESKey(Data(repeating: 0, count: 32), rsaPublicKeyPEM: "not-a-pem")) { error in
            guard let fingerprintError = error as? FingerprintError,
                  case .invalidPublicKey = fingerprintError else {
                return XCTFail("非法 PEM 应抛出 .invalidPublicKey，实际：\(error)")
            }
        }
    }

    // MARK: - Helpers

    private func makeRSAKeyPair() throws -> SecKey {
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits as String: 2048
        ]
        var error: Unmanaged<CFError>?
        let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error)
        return try XCTUnwrap(key, "生成 RSA 测试密钥失败：\(String(describing: error))")
    }

    private func decrypt(_ cipher: Data, with privateKey: SecKey) throws -> Data {
        var error: Unmanaged<CFError>?
        guard let plain = SecKeyCreateDecryptedData(privateKey, .rsaEncryptionOAEPSHA256, cipher as CFData, &error) else {
            throw NSError(
                domain: "CryptoEngineTests",
                code: -1,
                userInfo: [NSLocalizedDescriptionKey: "RSA 解密失败：\(String(describing: error))"]
            )
        }
        return plain as Data
    }

    /// 将 PKCS#1 `RSAPublicKey` 包装为 X.509 SubjectPublicKeyInfo PEM。
    private static func spkiPEM(fromPKCS1 pkcs1: Data) -> String {
        // AlgorithmIdentifier: SEQUENCE { OID 1.2.840.113549.1.1.1, NULL }
        let algorithmIdentifier = der(0x30, Data([
            0x06, 0x09,
            0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01,
            0x05, 0x00
        ]))
        let bitString = der(0x03, Data([0x00]) + pkcs1)
        let spki = der(0x30, algorithmIdentifier + bitString)
        return pem(body: spki, header: "PUBLIC KEY")
    }

    private static func pem(body: Data, header: String) -> String {
        let base64 = body.base64EncodedString(options: [.lineLength64Characters, .endLineWithLineFeed])
        return "-----BEGIN \(header)-----\n\(base64)\n-----END \(header)-----"
    }

    private static func der(_ tag: UInt8, _ content: Data) -> Data {
        var data = Data([tag])
        let length = content.count
        if length < 0x80 {
            data.append(UInt8(length))
        } else {
            var bytes: [UInt8] = []
            var remaining = length
            while remaining > 0 {
                bytes.insert(UInt8(remaining & 0xFF), at: 0)
                remaining >>= 8
            }
            data.append(0x80 | UInt8(bytes.count))
            data.append(contentsOf: bytes)
        }
        data.append(content)
        return data
    }
}
