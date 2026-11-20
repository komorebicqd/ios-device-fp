import Foundation

/// 设备特征采集抽象。
///
/// 单元测试注入固定数据即可完全脱离真机 / 模拟器环境。
public protocol DeviceInfoCollecting {
    /// 采集当前设备特征。
    /// - Parameter clientAnchorId: 已从 Keychain 读取（或刚生成并写入）的客户端锚点。
    func collect(clientAnchorId: String) -> RawDeviceInfo
}
