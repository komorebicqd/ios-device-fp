import Foundation

/// 一次采集得到的原始设备特征。
///
/// 字段顺序与 `orderedJSONString()` 的输出顺序一致，保证同一台设备每次生成的 `rawData`
/// 字节序列稳定，避免因 JSON 键顺序抖动导致指纹漂移。
public struct RawDeviceInfo: Equatable {

    /// 锚点：Keychain 中持久化的客户端 UUID（卸载重装不丢失）。
    public var clientAnchorId: String
    /// `UIDevice.current.identifierForVendor?.uuidString`
    public var idfv: String
    /// 硬件标识，如 `iPhone16,1`（来自 `uname`）。
    public var deviceModel: String
    /// 系统版本，如 `17.2`。
    public var osVersion: String
    /// 屏幕宽（point，四舍五入取整）。
    public var screenWidth: Int
    /// 屏幕高（point，四舍五入取整）。
    public var screenHeight: Int
    /// 屏幕缩放倍率。
    public var screenScale: Double
    /// 物理内存字节数。
    public var physicalMemory: UInt64
    /// 磁盘总容量字节数。
    public var totalDiskSpace: UInt64
    /// CPU 核心数。
    public var cpuCount: Int
    /// 系统首选语言列表。
    public var systemLanguages: [String]
    /// 地区码，如 `CN`。
    public var regionCode: String
    /// 时区标识，如 `Asia/Shanghai`。
    public var timeZone: String
    /// 是否运行在模拟器。
    public var isSimulator: Bool

    public init(
        clientAnchorId: String,
        idfv: String,
        deviceModel: String,
        osVersion: String,
        screenWidth: Int,
        screenHeight: Int,
        screenScale: Double,
        physicalMemory: UInt64,
        totalDiskSpace: UInt64,
        cpuCount: Int,
        systemLanguages: [String],
        regionCode: String,
        timeZone: String,
        isSimulator: Bool
    ) {
        self.clientAnchorId = clientAnchorId
        self.idfv = idfv
        self.deviceModel = deviceModel
        self.osVersion = osVersion
        self.screenWidth = screenWidth
        self.screenHeight = screenHeight
        self.screenScale = screenScale
        self.physicalMemory = physicalMemory
        self.totalDiskSpace = totalDiskSpace
        self.cpuCount = cpuCount
        self.systemLanguages = systemLanguages
        self.regionCode = regionCode
        self.timeZone = timeZone
        self.isSimulator = isSimulator
    }
}

extension RawDeviceInfo {

    /// 序列化为「键名有序」的 JSON 字符串。
    ///
    /// 不使用 `JSONSerialization`，因为其键顺序依赖底层字典实现，无法保证跨版本稳定。
    func orderedJSONString() -> String {
        OrderedJSON.object([
            ("clientAnchorId", .string(clientAnchorId)),
            ("idfv", .string(idfv)),
            ("deviceModel", .string(deviceModel)),
            ("osVersion", .string(osVersion)),
            ("screenWidth", .integer(screenWidth)),
            ("screenHeight", .integer(screenHeight)),
            ("screenScale", .double(screenScale)),
            ("physicalMemory", .unsignedInteger(physicalMemory)),
            ("totalDiskSpace", .unsignedInteger(totalDiskSpace)),
            ("cpuCount", .integer(cpuCount)),
            ("systemLanguages", .array(systemLanguages.map { .string($0) })),
            ("regionCode", .string(regionCode)),
            ("timeZone", .string(timeZone)),
            ("isSimulator", .bool(isSimulator))
        ])
    }
}
