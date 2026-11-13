import Foundation

/// LCP framing. Configuration negotiation is handled separately.
public struct LCPPacket: Equatable, Sendable {
    public let code: UInt8
    public let identifier: UInt8
    public let data: [UInt8]

    public init(code: UInt8, identifier: UInt8, data: [UInt8]) {
        self.code = code
        self.identifier = identifier
        self.data = data
    }

    public static func configureRequest(identifier: UInt8, magic: UInt32) -> LCPPacket {
        LCPPacket(code: 1, identifier: identifier, data: [1, 4, 0x05, 0x78, 5, 6] + Wire.u32(magic))
    }

    public func pppEncoded() throws -> [UInt8] {
        guard let length = UInt16(exactly: data.count + 4) else { throw PPTPError("LCP packet is too large") }
        return [0xff, 3, 0xc0, 0x21, code, identifier] + Wire.u16(length) + data
    }

    public static func decodePPP(_ bytes: [UInt8]) throws -> LCPPacket? {
        let offset = bytes.starts(with: [0xff, 3]) ? 2 : 0
        guard bytes.count >= offset + 2 else { throw PPTPError("truncated PPP protocol field") }
        guard bytes[offset..<offset + 2].elementsEqual([0xc0, 0x21]) else { return nil }
        let start = offset + 2
        guard bytes.count >= start + 4 else { throw PPTPError("truncated LCP header") }
        let length = Int(Wire.read16(bytes, start + 2))
        guard length >= 4, length <= bytes.count - start else { throw PPTPError("invalid LCP length") }
        // LCP permits padding after the length indicated in its header.
        return LCPPacket(code: bytes[start], identifier: bytes[start + 1],
                         data: Array(bytes[(start + 4)..<(start + length)]))
    }

    public func requestedAuthentication() throws -> String? {
        guard code == 1 else { return nil }
        let options = try LCPOption.parse(data)
        let auth = options.filter { $0.type == 3 }
        guard auth.count <= 1 else { throw PPTPError("duplicate authentication options") }
        return try auth.first?.authenticationName()
    }

    public func configurationSummary() throws -> String {
        guard (1...4).contains(code) else { throw PPTPError("not an LCP configuration packet") }
        let options = try LCPOption.parse(data)
        return options.isEmpty ? "no options" : options.map(\.summary).joined(separator: ", ")
    }
}
