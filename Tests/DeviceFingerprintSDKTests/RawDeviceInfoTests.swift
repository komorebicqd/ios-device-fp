import XCTest
@testable import DeviceFingerprintSDK

/// 验证 rawData 序列化结果稳定、键名有序且是合法 JSON。
final class RawDeviceInfoTests: XCTestCase {

    private func makeInfo() -> RawDeviceInfo {
        RawDeviceInfo(
            clientAnchorId: "anchor-1",
            idfv: "IDFV-0001",
            deviceModel: "iPhone16,1",
            osVersion: "17.2",
            screenWidth: 393,
            screenHeight: 852,
            screenScale: 3,
            physicalMemory: 8_589_934_592,
            totalDiskSpace: 127_000_000_000,
            cpuCount: 6,
            systemLanguages: ["zh-Hans-CN", "en-CN"],
            regionCode: "CN",
            timeZone: "Asia/Shanghai",
            isSimulator: false
        )
    }

    func testOrderedJSONStringMatchesDeclaredOrder() {
        let expected = """
        {"clientAnchorId":"anchor-1","idfv":"IDFV-0001","deviceModel":"iPhone16,1","osVersion":"17.2","screenWidth":393,"screenHeight":852,"screenScale":3,"physicalMemory":8589934592,"totalDiskSpace":127000000000,"cpuCount":6,"systemLanguages":["zh-Hans-CN","en-CN"],"regionCode":"CN","timeZone":"Asia/Shanghai","isSimulator":false}
        """
        XCTAssertEqual(makeInfo().orderedJSONString(), expected)
    }

    func testOrderedJSONStringIsStableAcrossCalls() {
        XCTAssertEqual(makeInfo().orderedJSONString(), makeInfo().orderedJSONString())
    }

    func testOutputIsValidJSON() throws {
        let json = makeInfo().orderedJSONString()
        let object = try XCTUnwrap(
            try JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: Any]
        )
        XCTAssertEqual(object["clientAnchorId"] as? String, "anchor-1")
        XCTAssertEqual(object["screenScale"] as? Int, 3)
        XCTAssertEqual(object["isSimulator"] as? Bool, false)
        XCTAssertEqual(object["systemLanguages"] as? [String], ["zh-Hans-CN", "en-CN"])
        XCTAssertEqual(object.count, 14)
    }

    func testEscapingHandlesQuotesAndControlCharacters() throws {
        var info = makeInfo()
        info.clientAnchorId = "a\"b\\c\nd"

        let json = info.orderedJSONString()
        let object = try XCTUnwrap(
            try JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: Any]
        )
        XCTAssertEqual(object["clientAnchorId"] as? String, "a\"b\\c\nd")
    }
}
