import Foundation

public struct PPTPError: Error, CustomStringConvertible, Sendable {
    public let description: String

    public init(_ description: String) {
        self.description = description
    }
}

/// PPTP control messages from RFC 2637, sections 2.1–2.6.
/// No PPP authentication or tunnel data is carried by this diagnostic codec.
public struct ControlMessage: Equatable, Sendable {
    public let type: UInt16
    public let payload: [UInt8]

    public init(type: UInt16, payload: [UInt8]) {
        self.type = type
        self.payload = payload
    }

    public static func startRequest() -> ControlMessage {
        var body: [UInt8] = [1, 0, 0, 0] // Version 1.0, reserved.
        body += [0, 0, 0, 3] // Asynchronous and synchronous framing.
        body += [0, 0, 0, 3] // Analog and digital bearers.
        body += [0, 0, 0, 1] // Maximum channels (PNS: 0), firmware revision.
        body += fixedString("pptp-client", length: 64)
        body += fixedString("PPTPClient diagnostic", length: 64)
        return ControlMessage(type: 1, payload: body)
    }

    public static let stopRequest = ControlMessage(type: 3, payload: [1, 0, 0, 0])
    public static let stopReply = ControlMessage(type: 4, payload: [1, 0, 0, 0])

    public func encoded() throws -> [UInt8] {
        guard let length = UInt16(exactly: payload.count + 12) else {
            throw PPTPError("control message is too large")
        }
        let bytes = [UInt8(length >> 8), UInt8(length & 0xff), 0, 1,
                     0x1a, 0x2b, 0x3c, 0x4d, UInt8(type >> 8), UInt8(type & 0xff), 0, 0]
        return bytes + payload
    }

    /// Validate the header before using a peer-supplied length for reading.
    public static func frameLength(header: [UInt8]) throws -> Int {
        guard header.count == 12 else { throw PPTPError("truncated control header") }
        guard header[2...7].elementsEqual([0, 1, 0x1a, 0x2b, 0x3c, 0x4d]) else {
            throw PPTPError("invalid PPTP message type or magic cookie")
        }
        let length = Int(header[0]) << 8 | Int(header[1])
        let type = UInt16(header[8]) << 8 | UInt16(header[9])
        let expected: [UInt16: Int] = [1: 156, 2: 156, 3: 16, 4: 16, 5: 16, 6: 20,
                                     7: 168, 8: 32, 12: 16, 13: 148, 14: 40, 15: 24]
        guard let expectedLength = expected[type] else {
            throw PPTPError("unexpected control message type \(type)")
        }
        guard length == expectedLength else {
            throw PPTPError("invalid length \(length) for control message \(type)")
        }
        // Reserved fields are ignored on reception, as required by RFC 2637 §1.4.
        return length
    }

    public static func decode(_ bytes: [UInt8]) throws -> ControlMessage {
        guard bytes.count >= 12 else { throw PPTPError("truncated control message") }
        let length = try frameLength(header: Array(bytes.prefix(12)))
        guard length == bytes.count else { throw PPTPError("control frame length mismatch") }
        return ControlMessage(type: UInt16(bytes[8]) << 8 | UInt16(bytes[9]),
                              payload: Array(bytes.dropFirst(12)))
    }

    public func startReply() throws -> ServerInfo {
        guard type == 2, payload.count == 144 else {
            throw PPTPError("expected Start-Control-Connection-Reply")
        }
        guard payload[2] == 1 else {
            throw PPTPError("server rejected PPTP control connection: result=\(payload[2]), error=\(payload[3])")
        }
        guard payload[0] == 1, payload[1] == 0 else {
            throw PPTPError("server selected unsupported PPTP version")
        }
        return ServerInfo(host: Self.displayString(payload[16..<80]),
                          vendor: Self.displayString(payload[80..<144]))
    }

    public func echoReply() throws -> ControlMessage {
        guard type == 5, payload.count == 4 else { throw PPTPError("invalid Echo-Request") }
        return ControlMessage(type: 6, payload: payload + [1, 0, 0, 0])
    }

    private static func fixedString(_ value: String, length: Int) -> [UInt8] {
        let bytes = Array(value.utf8.prefix(length))
        return bytes + [UInt8](repeating: 0, count: length - bytes.count)
    }

    private static func displayString(_ bytes: ArraySlice<UInt8>) -> String {
        // Untrusted peer strings must not inject terminal control sequences.
        String(bytes: bytes.prefix(while: { $0 != 0 }).map { (32...126).contains($0) ? $0 : 63 },
               encoding: .ascii) ?? ""
    }
}

public struct ServerInfo: Equatable, Sendable {
    public let host: String
    public let vendor: String
}
