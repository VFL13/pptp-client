import Foundation

/// Enhanced GRE v1, RFC 2637 §4.1. This codec is not a full sliding-window implementation.
public struct GREPacket: Equatable, Sendable {
    public let callID: UInt16
    public let sequence: UInt32?
    public let acknowledgment: UInt32?
    public let payload: [UInt8]

    public init(callID: UInt16, sequence: UInt32?, acknowledgment: UInt32?, payload: [UInt8]) {
        self.callID = callID
        self.sequence = sequence
        self.acknowledgment = acknowledgment
        self.payload = payload
    }

    public func encoded() throws -> [UInt8] {
        guard payload.count <= 1532, (sequence != nil) == !payload.isEmpty,
              sequence != nil || acknowledgment != nil else { throw PPTPError("invalid GRE payload or flags") }
        var flags: UInt16 = 0x2001
        if sequence != nil { flags |= 0x1000 }
        if acknowledgment != nil { flags |= 0x0080 }
        var bytes = Wire.u16(flags) + [0x88, 0x0b] + Wire.u16(UInt16(payload.count)) + Wire.u16(callID)
        if let sequence { bytes += Wire.u32(sequence) }
        if let acknowledgment { bytes += Wire.u32(acknowledgment) }
        return bytes + payload
    }

    public static func decode(_ bytes: [UInt8]) throws -> GREPacket {
        guard bytes.count >= 8 else { throw PPTPError("truncated GRE header") }
        let flags = Wire.read16(bytes, 0)
        guard flags & ~UInt16(0x1080) == 0x2001, Wire.read16(bytes, 2) == 0x880b else {
            throw PPTPError("invalid PPTP GRE flags, version or protocol")
        }
        let hasSequence = flags & 0x1000 != 0
        let hasAck = flags & 0x0080 != 0
        let length = Int(Wire.read16(bytes, 4))
        let headerLength = 8 + (hasSequence ? 4 : 0) + (hasAck ? 4 : 0)
        guard length <= 1532, hasSequence == (length > 0), hasSequence || hasAck,
              bytes.count == headerLength + length else { throw PPTPError("invalid GRE frame length") }
        let sequence = hasSequence ? Wire.read32(bytes, 8) : nil
        let ack = hasAck ? Wire.read32(bytes, hasSequence ? 12 : 8) : nil
        return GREPacket(callID: Wire.read16(bytes, 6), sequence: sequence, acknowledgment: ack,
                         payload: Array(bytes.dropFirst(headerLength)))
    }

    /// Darwin raw sockets return the IPv4 header; ip_len has BSD-specific semantics,
    /// so use the actual received byte count and GRE's own payload length.
    public static func decodeIPv4(_ bytes: [UInt8], expectedSource: [UInt8]) throws -> GREPacket {
        guard bytes.count >= 20, bytes[0] >> 4 == 4, bytes[9] == 47,
              expectedSource.count == 4, bytes[12..<16].elementsEqual(expectedSource) else {
            throw PPTPError("unexpected IPv4 GRE source or protocol")
        }
        let headerLength = Int(bytes[0] & 15) * 4
        guard headerLength >= 20, bytes.count >= headerLength else { throw PPTPError("invalid IPv4 header length") }
        return try decode(Array(bytes.dropFirst(headerLength)))
    }
}
