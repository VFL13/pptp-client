import Foundation

public struct PPPFrame: Equatable, Sendable {
    public let protocolNumber: UInt16
    public let payload: [UInt8]

    public init(protocolNumber: UInt16, payload: [UInt8]) {
        self.protocolNumber = protocolNumber
        self.payload = payload
    }

    public func encoded() -> [UInt8] { [0xff, 3] + Wire.u16(protocolNumber) + payload }

    public static func decode(_ bytes: [UInt8]) throws -> PPPFrame {
        var offset = bytes.starts(with: [0xff, 3]) ? 2 : 0
        guard bytes.count > offset else { throw PPTPError("truncated PPP protocol") }
        let proto: UInt16
        if bytes[offset] & 1 != 0 { proto = UInt16(bytes[offset]); offset += 1 }
        else {
            guard bytes.count >= offset + 2, bytes[offset + 1] & 1 != 0 else { throw PPTPError("invalid PPP protocol") }
            proto = Wire.read16(bytes, offset)
            offset += 2
        }
        return PPPFrame(protocolNumber: proto, payload: Array(bytes.dropFirst(offset)))
    }
}

/// Control framing shared by PAP, IPCP, CCP and LCP. Never render payloads in logs.
public struct PPPControl: Equatable, Sendable {
    public let code: UInt8
    public let identifier: UInt8
    public let data: [UInt8]

    public init(code: UInt8, identifier: UInt8, data: [UInt8]) {
        self.code = code
        self.identifier = identifier
        self.data = data
    }

    public func frame(protocolNumber: UInt16) throws -> PPPFrame {
        guard let length = UInt16(exactly: data.count + 4) else { throw PPTPError("PPP control packet is too large") }
        return PPPFrame(protocolNumber: protocolNumber, payload: [code, identifier] + Wire.u16(length) + data)
    }

    public static func decode(_ bytes: [UInt8]) throws -> PPPControl {
        guard bytes.count >= 4 else { throw PPTPError("truncated PPP control packet") }
        let length = Int(Wire.read16(bytes, 2))
        guard length >= 4, length <= bytes.count else { throw PPTPError("invalid PPP control length") }
        return PPPControl(code: bytes[0], identifier: bytes[1], data: Array(bytes[4..<length]))
    }
}

public enum PAP {
    public static func request(identifier: UInt8, username: [UInt8], password: [UInt8]) throws -> PPPFrame {
        guard !username.isEmpty, let nameLength = UInt8(exactly: username.count),
              let passwordLength = UInt8(exactly: password.count) else { throw PPTPError("PAP credentials exceed protocol limits") }
        return try PPPControl(code: 1, identifier: identifier,
                              data: [nameLength] + username + [passwordLength] + password).frame(protocolNumber: 0xc023)
    }

    public static func accepted(_ packet: PPPControl, identifier: UInt8) throws -> Bool? {
        guard packet.identifier == identifier, packet.code == 2 || packet.code == 3 else { return nil }
        guard let count = packet.data.first, Int(count) == packet.data.count - 1 else {
            throw PPTPError("malformed PAP response")
        }
        // A server's message may contain sensitive data; never include it in errors.
        return packet.code == 2
    }
}
