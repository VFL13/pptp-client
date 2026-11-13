import Foundation

extension ControlMessage {
    public static func outgoingCallRequest(callID: UInt16, serial: UInt16) -> ControlMessage {
        var body = Wire.u16(callID) + Wire.u16(serial)
        body += Wire.u32(300) + Wire.u32(100_000_000) // Min/max BPS.
        body += Wire.u32(3) + Wire.u32(3) // Any bearer and framing type.
        body += Wire.u16(16) + Wire.u16(0) // Receive window, processing delay.
        body += [UInt8](repeating: 0, count: 132) // Phone length, reserved, phone, subaddress.
        return ControlMessage(type: 7, payload: body)
    }

    public func outgoingCallReply(localCallID: UInt16) throws -> CallInfo {
        guard type == 8, payload.count == 20 else { throw PPTPError("expected Outgoing-Call-Reply") }
        guard Wire.read16(payload, 2) == localCallID else { throw PPTPError("call reply has wrong peer call ID") }
        guard payload[4] == 1 else {
            throw PPTPError("server rejected PPTP call: result=\(payload[4]), error=\(payload[5])")
        }
        let window = Wire.read16(payload, 12)
        guard window > 0 else { throw PPTPError("server advertised a zero GRE receive window") }
        return CallInfo(peerCallID: Wire.read16(payload, 0), receiveWindow: window)
    }
}

public struct CallInfo: Sendable {
    public let peerCallID: UInt16
    public let receiveWindow: UInt16
}

// Bounds are checked by each protocol parser before accessing these offsets.
enum Wire {
    static func u16(_ value: UInt16) -> [UInt8] { [UInt8(value >> 8), UInt8(value & 255)] }
    static func u32(_ value: UInt32) -> [UInt8] {
        [UInt8(value >> 24), UInt8((value >> 16) & 255), UInt8((value >> 8) & 255), UInt8(value & 255)]
    }
    static func read16(_ bytes: [UInt8], _ offset: Int) -> UInt16 {
        UInt16(bytes[offset]) << 8 | UInt16(bytes[offset + 1])
    }
    static func read32(_ bytes: [UInt8], _ offset: Int) -> UInt32 {
        UInt32(bytes[offset]) << 24 | UInt32(bytes[offset + 1]) << 16
            | UInt32(bytes[offset + 2]) << 8 | UInt32(bytes[offset + 3])
    }
}

/// A bounded control session. Stopping the connection implicitly clears its calls.
public final class ControlChannel {
    private let transport: any ControlTransport
    private var established = false
    private var lastEchoAt: TimeInterval?
    private var echo: (id: UInt32, time: TimeInterval)?
    private var echoID: UInt32 = 0

    public init(transport: any ControlTransport) { self.transport = transport }

    public func start() throws -> ServerInfo {
        guard !established else { throw PPTPError("control channel already started") }
        try transport.write(ControlMessage.startRequest().encoded())
        let server = try readMessage().startReply()
        established = true
        return server
    }

    public func openCall(localCallID: UInt16, serial: UInt16) throws -> CallInfo {
        guard established else { throw PPTPError("control channel is not established") }
        try transport.write(ControlMessage.outgoingCallRequest(callID: localCallID, serial: serial).encoded())
        for _ in 0..<16 {
            let message = try readMessage()
            if message.type == 8 { return try message.outgoingCallReply(localCallID: localCallID) }
            if message.type == 5 { try transport.write(message.echoReply().encoded()); continue }
            if message.type == 3 {
                try transport.write(ControlMessage.stopReply.encoded())
                established = false
                throw PPTPError("server stopped control connection before call establishment")
            }
            throw PPTPError("unexpected message during call setup: \(message.type)")
        }
        throw PPTPError("too many messages during call setup")
    }

    public func stop() throws {
        guard established else { return }
        defer { established = false }
        try transport.write(ControlMessage.stopRequest.encoded())
        for _ in 0..<16 {
            let message = try readMessage()
            switch message.type {
            case 4:
                guard message.payload[0] == 1 else { throw PPTPError("server rejected control shutdown") }
                return
            case 5: try transport.write(message.echoReply().encoded())
            case 3:
                try transport.write(ControlMessage.stopReply.encoded())
                return
            // These may already be queued when shutdown clears a live call.
            case 6, 13, 14, 15: continue
            default: throw PPTPError("unexpected message during control shutdown: \(message.type)")
            }
        }
        throw PPTPError("too many messages during control shutdown")
    }

    public func service(now: TimeInterval) throws {
        guard established else { throw PPTPError("PPTP control connection is closed") }
        for _ in 0..<16 {
            guard let message = try transport.readAvailableMessage() else { break }
            switch message.type {
            case 5: try transport.write(message.echoReply().encoded())
            case 6:
                if Wire.read32(message.payload, 0) == echo?.id, message.payload[4] == 1 { echo = nil }
            case 3:
                try transport.write(ControlMessage.stopReply.encoded())
                established = false
                throw PPTPError("server closed PPTP control connection")
            case 13: throw PPTPError("server disconnected the PPTP call")
            case 14, 15: break
            default: throw PPTPError("unexpected message on active PPTP connection")
            }
        }
        if let echo, now - echo.time > 20 { throw PPTPError("PPTP control keepalive timed out") }
        if lastEchoAt == nil { lastEchoAt = now }
        if echo == nil, now - (lastEchoAt ?? now) >= 20 {
            echoID &+= 1
            try transport.write(ControlMessage(type: 5, payload: Wire.u32(echoID)).encoded())
            echo = (echoID, now)
            lastEchoAt = now
        }
    }

    private func readMessage() throws -> ControlMessage {
        let header = try transport.readExactly(12)
        let length = try ControlMessage.frameLength(header: header)
        return try ControlMessage.decode(header + transport.readExactly(length - 12))
    }
}
