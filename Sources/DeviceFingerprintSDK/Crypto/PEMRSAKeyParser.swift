import Foundation

/// 解析后的 RSA 公钥。
struct ParsedRSAPublicKey {
    /// PKCS#1 格式的 DER 数据，`SecKeyCreateWithData` 在 iOS 上只接受该格式。
    let pkcs1DER: Data
    /// 模数位数，如 2048。
    let modulusBits: Int
}

/// 将服务端下发的 PEM 公钥转换为 `Security` 框架可用的 PKCS#1 DER。
///
/// 兼容两种常见 PEM：
/// - `-----BEGIN RSA PUBLIC KEY-----`：内容本身就是 PKCS#1 `RSAPublicKey`；
/// - `-----BEGIN PUBLIC KEY-----`：内容是 X.509 `SubjectPublicKeyInfo`，
///   需要剥离 `AlgorithmIdentifier` 与 `BIT STRING` 外壳。
///
/// 具体以 DER 结构判断而非 PEM 头，避免服务端头部书写不规范导致解析失败。
enum PEMRSAKeyParser {

    enum ParseError: Error, CustomStringConvertible {
        case emptyBody
        case invalidBase64
        case malformedDER
        case unsupportedKey

        var description: String {
            switch self {
            case .emptyBody: return "PEM 内容为空"
            case .invalidBase64: return "PEM 主体不是合法的 Base64"
            case .malformedDER: return "DER 结构不合法"
            case .unsupportedKey: return "不是受支持的 RSA 公钥"
            }
        }
    }

    static func parse(pem: String) throws -> ParsedRSAPublicKey {
        let der = try derData(fromPEM: pem)

        let pkcs1: Data
        if let stripped = try? extractPKCS1(fromSPKI: der) {
            pkcs1 = stripped
        } else {
            pkcs1 = der
        }

        guard let bits = try? modulusBitCount(pkcs1), bits > 0 else {
            throw ParseError.unsupportedKey
        }
        return ParsedRSAPublicKey(pkcs1DER: pkcs1, modulusBits: bits)
    }

    // MARK: - PEM -> DER

    private static func derData(fromPEM pem: String) throws -> Data {
        // 同时兼容多行与单行 PEM：先去掉固定的页眉页脚，再剔除所有空白字符。
        let body = pem
            .replacingOccurrences(of: "-----BEGIN RSA PUBLIC KEY-----", with: "")
            .replacingOccurrences(of: "-----END RSA PUBLIC KEY-----", with: "")
            .replacingOccurrences(of: "-----BEGIN PUBLIC KEY-----", with: "")
            .replacingOccurrences(of: "-----END PUBLIC KEY-----", with: "")
            .components(separatedBy: .whitespacesAndNewlines)
            .joined()

        guard !body.isEmpty else { throw ParseError.emptyBody }
        guard let data = Data(base64Encoded: body) else {
            throw ParseError.invalidBase64
        }
        return data
    }

    // MARK: - X.509 SPKI -> PKCS#1

    private static func extractPKCS1(fromSPKI der: Data) throws -> Data {
        let bytes = [UInt8](der)

        let outer = try DER.element(bytes, at: 0)
        guard outer.tag == 0x30 else { throw ParseError.malformedDER }

        // 第一个子元素必须是 AlgorithmIdentifier（SEQUENCE）；
        // 若为 INTEGER 说明已是 PKCS#1 RSAPublicKey，交给调用方回退处理。
        let algorithm = try DER.element(bytes, at: outer.contentStart)
        guard algorithm.tag == 0x30 else { throw ParseError.unsupportedKey }

        let bitString = try DER.element(bytes, at: algorithm.contentEnd)
        guard bitString.tag == 0x03,
              bitString.contentEnd - bitString.contentStart > 1 else {
            throw ParseError.malformedDER
        }

        // BIT STRING 首字节为「未使用位数」，RSA 公钥恒为 0。
        return Data(bytes[(bitString.contentStart + 1)..<bitString.contentEnd])
    }

    // MARK: - 模数位数

    private static func modulusBitCount(_ pkcs1: Data) throws -> Int {
        let bytes = [UInt8](pkcs1)

        let sequence = try DER.element(bytes, at: 0)
        guard sequence.tag == 0x30 else { throw ParseError.malformedDER }

        let modulus = try DER.element(bytes, at: sequence.contentStart)
        guard modulus.tag == 0x02 else { throw ParseError.unsupportedKey }

        var content = Array(bytes[modulus.contentStart..<modulus.contentEnd])
        while let first = content.first, first == 0 {
            content.removeFirst()
        }
        guard let first = content.first else { throw ParseError.malformedDER }

        return content.count * 8 - first.leadingZeroBitCount
    }
}

/// 最小 ASN.1 DER 读取器（仅支持单字节 Tag + 短/长格式长度）。
enum DER {

    struct Element {
        let tag: UInt8
        let contentStart: Int
        let contentEnd: Int
    }

    static func element(_ bytes: [UInt8], at index: Int) throws -> Element {
        guard index >= 0, index + 2 <= bytes.count else {
            throw PEMRSAKeyParser.ParseError.malformedDER
        }

        let tag = bytes[index]
        var cursor = index + 1
        let firstLengthByte = Int(bytes[cursor])
        cursor += 1

        let length: Int
        if firstLengthByte & 0x80 == 0 {
            length = firstLengthByte
        } else {
            let lengthBytes = firstLengthByte & 0x7F
            guard lengthBytes > 0, lengthBytes <= 4, cursor + lengthBytes <= bytes.count else {
                throw PEMRSAKeyParser.ParseError.malformedDER
            }
            var value = 0
            for _ in 0..<lengthBytes {
                value = (value << 8) | Int(bytes[cursor])
                cursor += 1
            }
            length = value
        }

        guard cursor + length <= bytes.count else {
            throw PEMRSAKeyParser.ParseError.malformedDER
        }
        return Element(tag: tag, contentStart: cursor, contentEnd: cursor + length)
    }
}
