import Foundation

public struct IPv4Value: Equatable, Hashable, Sendable, CustomStringConvertible {
    public let value: UInt32
    public var bytes: [UInt8] { Wire.u32(value) }
    public var description: String { bytes.map(String.init).joined(separator: ".") }
    public var isUnicast: Bool { value != 0 && bytes[0] != 0 && bytes[0] != 127 && bytes[0] < 224 }

    public init(bytes: [UInt8]) throws {
        guard bytes.count == 4 else { throw PPTPError("invalid IPv4 address length") }
        value = Wire.read32(bytes, 0)
    }

    public init(_ text: String) throws {
        let parts = text.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4 else { throw PPTPError("expected a literal IPv4 address") }
        let octets = try parts.map { part -> UInt8 in
            guard !part.isEmpty, part.utf8.allSatisfy({ (48...57).contains($0) }),
                  let octet = UInt8(part), String(octet) == part else { throw PPTPError("invalid IPv4 address") }
            return octet
        }
        try self.init(bytes: octets)
    }
}

public struct IPv4CIDR: Equatable, Sendable, CustomStringConvertible {
    public let network: IPv4Value
    public let prefix: Int
    private let mask: UInt32
    public var description: String { "\(network)/\(prefix)" }

    public init(_ text: String) throws {
        let parts = text.split(separator: "/", omittingEmptySubsequences: false)
        guard parts.count == 2, let prefix = Int(parts[1]), (0...32).contains(prefix) else {
            throw PPTPError("route must be IPv4 CIDR, such as 10.20.0.0/16")
        }
        let address = try IPv4Value(String(parts[0]))
        self.prefix = prefix
        mask = prefix == 0 ? 0 : UInt32.max << (32 - prefix)
        network = try IPv4Value(bytes: Wire.u32(address.value & mask))
    }

    public func contains(_ address: IPv4Value) -> Bool { address.value & mask == network.value }
}
