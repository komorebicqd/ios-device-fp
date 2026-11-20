import Foundation

/// 待签名字符串拼装规则。
///
/// `timestamp|tempId|nonce|encryptedAesKey|encryptedData`
///
/// 单独抽成纯函数，便于测试固定签名协议，而不必走完整网络链路。
public enum SignatureComposer {

    public static func stringToSign(
        timestamp: Int64,
        tempId: String,
        nonce: String,
        encryptedAesKey: String,
        encryptedData: String
    ) -> String {
        [
            String(timestamp),
            tempId,
            nonce,
            encryptedAesKey,
            encryptedData
        ].joined(separator: "|")
    }
}
