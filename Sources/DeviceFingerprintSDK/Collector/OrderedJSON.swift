import Foundation

/// 极简有序 JSON 序列化器。
///
/// 只覆盖指纹采集所需的类型（字符串、整数、浮点、布尔、字符串数组），
/// 输出不含多余空格，且严格按传入顺序排列键名。
enum OrderedJSON {

    static func object(_ pairs: [(String, JSONValue)]) -> String {
        let body = pairs
            .map { "\"\(escape($0.0))\":\($0.1.serialized)" }
            .joined(separator: ",")
        return "{" + body + "}"
    }

    static func escape(_ string: String) -> String {
        var result = ""
        for scalar in string.unicodeScalars {
            switch scalar {
            case "\"": result += "\\\""
            case "\\": result += "\\\\"
            case "\n": result += "\\n"
            case "\r": result += "\\r"
            case "\t": result += "\\t"
            case "\u{08}": result += "\\b"
            case "\u{0C}": result += "\\f"
            default:
                if scalar.value < 0x20 {
                    result += String(format: "\\u%04x", scalar.value)
                } else {
                    result.unicodeScalars.append(scalar)
                }
            }
        }
        return result
    }

    static func format(double value: Double) -> String {
        guard value.isFinite else { return "0" }
        if value == value.rounded(), abs(value) < 1e15 {
            return String(Int64(value))
        }
        return String(value)
    }
}

enum JSONValue {
    case string(String)
    case integer(Int)
    case unsignedInteger(UInt64)
    case double(Double)
    case bool(Bool)
    case array([JSONValue])

    var serialized: String {
        switch self {
        case .string(let value):
            return "\"\(OrderedJSON.escape(value))\""
        case .integer(let value):
            return String(value)
        case .unsignedInteger(let value):
            return String(value)
        case .double(let value):
            return OrderedJSON.format(double: value)
        case .bool(let value):
            return value ? "true" : "false"
        case .array(let values):
            return "[" + values.map { $0.serialized }.joined(separator: ",") + "]"
        }
    }
}
