import Foundation

/// Keychain 能力抽象。单元测试可注入内存实现，避免在模拟器或 CI 上触碰真实 Keychain。
public protocol KeychainStoring {

    /// 写入（存在则更新，不存在则新增）字符串。
    func setString(_ value: String, forKey key: String) throws

    /// 读取字符串，不存在时返回 `nil`。
    func string(forKey key: String) throws -> String?

    /// 删除指定键，键不存在不视为失败。
    func removeString(forKey key: String) throws
}

/// SDK 内部使用的 Keychain 键名。
enum StorageKey {
    /// 客户端首次生成的 UUID，卸载重装后仍然保留。
    static let clientAnchorId = "clientAnchorId"
    /// 服务端返回的最终设备指纹 ID。
    static let deviceId = "deviceId"
}
