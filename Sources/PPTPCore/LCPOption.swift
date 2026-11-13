import Foundation

public struct LCPOption: Equatable, Sendable {
    public let type: UInt8
    public let value: [UInt8]

    public init(type: UInt8, value: [UInt8]) {
        self.type = type
        self.value = value
    }

    public func encoded() throws -> [UInt8] {
        guard let length = UInt8(exactly: value.count + 2) else { throw PPTPError("LCP option is too large") }
        return [type, length] + value
    }

    public static func parse(_ bytes: [UInt8]) throws -> [LCPOption] {
        var result: [LCPOption] = []
        var offset = 0
        while offset < bytes.count {
            guard bytes.count - offset >= 2 else { throw PPTPError("truncated LCP option") }
            let length = Int(bytes[offset + 1])
            guard length >= 2, length <= bytes.count - offset else { throw PPTPError("invalid LCP option length") }
            result.append(LCPOption(type: bytes[offset], value: Array(bytes[(offset + 2)..<(offset + length)])))
            offset += length
        }
        return result
    }

    public func authenticationName() throws -> String? {
        guard type == 3 else { return nil }
        guard value.count >= 2 else { throw PPTPError("truncated authentication option") }
        switch Wire.read16(value, 0) {
        case 0xc023:
            guard value.count == 2 else { throw PPTPError("invalid PAP authentication option") }
            return "PAP"
        case 0xc227:
            guard value.count == 2 else { throw PPTPError("invalid EAP authentication option") }
            return "EAP"
        case 0xc223:
            guard value.count == 3 else { throw PPTPError("invalid CHAP authentication option") }
            switch value[2] {
            case 5: return "CHAP-MD5"
            case 0x80: return "MS-CHAPv1"
            case 0x81: return "MS-CHAPv2"
            default: return "CHAP (algorithm \(value[2]))"
            }
        default: return "unknown PPP authentication protocol"
        }
    }

    /// Only LCP configuration metadata is rendered, never authentication packets.
    public var summary: String {
        switch (type, value.count) {
        case (1, 2): return "MRU=\(Wire.read16(value, 0))"
        case (2, 4): return "ACCM=\(String(format: "0x%08x", Wire.read32(value, 0)))"
        case (3, _):
            do { return "authentication=\(try authenticationName() ?? "unknown")" }
            catch { return "malformed authentication option" }
        case (5, 4): return "magic=\(String(format: "0x%08x", Wire.read32(value, 0)))"
        case (7, 0): return "protocol field compression"
        case (8, 0): return "address/control field compression"
        default: return "option \(type) (\(value.count + 2) bytes)"
        }
    }
}
