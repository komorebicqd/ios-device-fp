import Foundation
import Security

/// 基于 `Security` 框架的 Keychain 实现。
///
/// - 使用 `kSecClassGenericPassword`，权限固定为
///   `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`：
///   设备首次解锁后即可访问（支持后台冷启动读取），且不会随 iCloud 备份迁移到其它设备。
/// - 不设置 `kSecAttrSynchronizable`，保证数据只存在于当前设备。
public final class KeychainStore: KeychainStoring {

    public static let defaultService = "com.devicefingerprint.sdk.keychain"

    private let service: String

    public init(service: String = KeychainStore.defaultService) {
        self.service = service
    }

    public func setString(_ value: String, forKey key: String) throws {
        let data = Data(value.utf8)
        let query = baseQuery(forKey: key)
        let attributes: [String: Any] = [
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        ]

        let updateStatus = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
        switch updateStatus {
        case errSecSuccess:
            return
        case errSecItemNotFound:
            var addQuery = query
            attributes.forEach { addQuery[$0.key] = $0.value }
            let addStatus = SecItemAdd(addQuery as CFDictionary, nil)
            guard addStatus == errSecSuccess else {
                throw FingerprintError.keychain(addStatus)
            }
        default:
            throw FingerprintError.keychain(updateStatus)
        }
    }

    public func string(forKey key: String) throws -> String? {
        var query = baseQuery(forKey: key)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        switch status {
        case errSecSuccess:
            guard let data = item as? Data,
                  let value = String(data: data, encoding: .utf8) else {
                throw FingerprintError.invalidResponse("Keychain 中的 \(key) 不是合法的 UTF-8 字符串")
            }
            return value
        case errSecItemNotFound:
            return nil
        default:
            throw FingerprintError.keychain(status)
        }
    }

    public func removeString(forKey key: String) throws {
        let status = SecItemDelete(baseQuery(forKey: key) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw FingerprintError.keychain(status)
        }
    }

    private func baseQuery(forKey key: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key
        ]
    }
}
