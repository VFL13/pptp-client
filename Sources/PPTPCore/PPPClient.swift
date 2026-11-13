import Foundation

public enum PPPPhase: String, Sendable { case idle, lcp, credentials, pap, ipcp, network, closed }
public enum PPPAction: Sendable {
    case send(PPPFrame)
    case credentialsRequired
    case configured(PPPNetworkConfiguration)
    case ipv4([UInt8])
    case closed
}

/// A single IPv4 PAP session without MPPE. All I/O and credential collection
/// are supplied by the caller; this type never logs or persists credentials.
public final class PPPClient {
    public private(set) var phase: PPPPhase = .idle
    public private(set) var network: PPPNetworkConfiguration?
    public var mtu: Int { min(1400, Int(lcp.localMRU), Int(lcp.peerMRU)) }
    private let lcp = LCPConfiguration(policy: .requirePAP)
    private let ipcp = IPCPConfiguration()
    private let magic: UInt32
    private var startedAt: TimeInterval = 0
    private var retryAt: TimeInterval = 0
    private var retryPacket: PPPFrame?
    private var papIdentifier: UInt8 = 0
    private var peerLCPRequest: LCPPacket?
    private var peerLCPAck: LCPPacket?
    private var peerIPCPRequest: PPPControl?
    private var peerIPCPAck: PPPControl?
    private var lastEchoAt: TimeInterval = 0
    private var pendingEcho: (id: UInt8, time: TimeInterval?)?
    private var nextEcho: UInt8 = 0

    public init(magic: UInt32) { self.magic = magic }

    public func start(now: TimeInterval) throws -> [PPPAction] {
        guard phase == .idle else { throw PPTPError("PPP session already started") }
        phase = .lcp
        startedAt = now
        return try remember(lcp.start(identifier: 1, magic: magic), now: now)
    }

    public func authenticate(username: [UInt8], password: [UInt8], now: TimeInterval) throws -> [PPPAction] {
        guard phase == .credentials, lcp.authentication == "PAP" else { throw PPTPError("PAP was not agreed by LCP") }
        papIdentifier = UInt8.random(in: 1...UInt8.max)
        let frame = try PAP.request(identifier: papIdentifier, username: username, password: password)
        phase = .pap
        startedAt = now
        retryPacket = nil // Never automatically repeat an authentication attempt.
        return [.send(frame)]
    }

    public func receive(_ frame: PPPFrame, now: TimeInterval) throws -> [PPPAction] {
        guard phase != .idle, phase != .closed else { return [] }
        switch frame.protocolNumber {
        case 0xc021: return try handleLCP(PPPControl.decode(frame.payload), now: now)
        case 0xc023:
            guard phase == .pap else { return [] }
            guard let accepted = try PAP.accepted(PPPControl.decode(frame.payload), identifier: papIdentifier) else { return [] }
            guard accepted else { throw PPTPError("VPN authentication rejected; no automatic retry was made") }
            phase = .ipcp
            startedAt = now
            let request = try ipcp.start(identifier: 1)
            return try remember(request, proto: 0x8021, now: now)
        case 0x8021: return try handleIPCP(PPPControl.decode(frame.payload), now: now)
        case 0x80fd:
            guard phase == .ipcp || phase == .network else { return [] }
            let control = try PPPControl.decode(frame.payload)
            if control.code == 1 {
                // Plain PPP only: reject every advertised compression/MPPE option.
                return [.send(try PPPControl(code: control.data.isEmpty ? 2 : 4, identifier: control.identifier,
                                              data: control.data).frame(protocolNumber: 0x80fd))]
            }
            if control.code == 5 {
                return [.send(try PPPControl(code: 6, identifier: control.identifier, data: []).frame(protocolNumber: 0x80fd))]
            }
            return []
        case 0x21:
            guard phase == .network, let network,
                  Self.validIPv4(frame.payload, address: network.localAddress, source: false) else { return [] }
            return [.ipv4(frame.payload)]
        default:
            guard phase == .network else { return [] }
            let rejected = Wire.u16(frame.protocolNumber) + Array(frame.payload.prefix(mtu - 6))
            return [.send(try PPPControl(code: 8, identifier: 0, data: rejected).frame(protocolNumber: 0xc021))]
        }
    }

    public func outboundIPv4(_ bytes: [UInt8]) throws -> PPPFrame? {
        guard phase == .network, let network, bytes.count <= mtu,
              Self.validIPv4(bytes, address: network.localAddress, source: true) else { return nil }
        return PPPFrame(protocolNumber: 0x21, payload: bytes)
    }

    public func tick(now: TimeInterval) throws -> [PPPAction] {
        if [.lcp, .credentials, .pap, .ipcp].contains(phase), now - startedAt > 30 {
            throw PPTPError("PPP \(phase.rawValue) phase timed out")
        }
        if let retryPacket, now - retryAt >= 3 {
            retryAt = now
            return [.send(retryPacket)]
        }
        guard phase == .network else { return [] }
        if let time = pendingEcho?.time, now - time > 20 { throw PPTPError("PPP keepalive timed out") }
        if pendingEcho == nil, now - lastEchoAt >= 20 {
            nextEcho &+= 1
            pendingEcho = (nextEcho, nil)
            lastEchoAt = now
            return [.send(try PPPControl(code: 9, identifier: nextEcho, data: Wire.u32(lcp.localMagic ?? 0)).frame(protocolNumber: 0xc021))]
        }
        return []
    }

    /// A queued echo is not yet on the network. Start its response timer only
    /// after the GRE transport actually sends it, not while waiting for credit.
    public func transmitted(_ frame: PPPFrame, now: TimeInterval) {
        guard frame.protocolNumber == 0xc021, frame.payload.count >= 2,
              frame.payload[0] == 9, frame.payload[1] == pendingEcho?.id,
              pendingEcho?.time == nil else { return }
        pendingEcho?.time = now
    }

    private func handleLCP(_ control: PPPControl, now: TimeInterval) throws -> [PPPAction] {
        let packet = LCPPacket(code: control.code, identifier: control.identifier, data: control.data)
        if control.code == 5 {
            phase = .closed
            retryPacket = nil
            return [.send(try PPPControl(code: 6, identifier: control.identifier, data: []).frame(protocolNumber: 0xc021)), .closed]
        }
        if control.code == 9, phase != .lcp, control.data.count >= 4 {
            return [.send(try PPPControl(code: 10, identifier: control.identifier,
                                          data: Wire.u32(lcp.localMagic ?? 0) + control.data.dropFirst(4)).frame(protocolNumber: 0xc021))]
        }
        if control.code == 10, control.identifier == pendingEcho?.id, pendingEcho?.time != nil, control.data.count >= 4 {
            pendingEcho = nil
            return []
        }
        if phase != .lcp {
            if control.code == 1, packet == peerLCPRequest, let peerLCPAck { return [.send(try frame(peerLCPAck))] }
            if control.code == 1 { throw PPTPError("server restarted LCP; reconnect required") }
            if control.code == 8, control.data.count >= 2, [UInt16(0xc021), 0xc023, 0x8021].contains(Wire.read16(control.data, 0)) {
                throw PPTPError("server rejected a required PPP protocol")
            }
            return []
        }
        let replies = try lcp.receive(packet)
        var actions: [PPPAction] = []
        for reply in replies {
            if reply.code == 1 { actions += try remember(reply, now: now) }
            else { actions.append(.send(try frame(reply))) }
            if reply.code == 2 { peerLCPRequest = packet; peerLCPAck = reply }
        }
        if lcp.readyForAuthentication {
            phase = .credentials
            startedAt = now
            retryPacket = nil
            actions.append(.credentialsRequired)
        }
        return actions
    }

    private func handleIPCP(_ packet: PPPControl, now: TimeInterval) throws -> [PPPAction] {
        if phase == .network {
            if packet == peerIPCPRequest, let peerIPCPAck { return [.send(try peerIPCPAck.frame(protocolNumber: 0x8021))] }
            if packet.code == 1 || packet.code == 5 { throw PPTPError("server restarted or stopped IPCP; reconnect required") }
            return []
        }
        guard phase == .ipcp else { return [] }
        var actions: [PPPAction] = []
        for reply in try ipcp.receive(packet) {
            if reply.code == 1 { actions += try remember(reply, proto: 0x8021, now: now) }
            else { actions.append(.send(try reply.frame(protocolNumber: 0x8021))) }
            if reply.code == 2 { peerIPCPRequest = packet; peerIPCPAck = reply }
        }
        if let configuration = ipcp.configuration {
            network = configuration
            phase = .network
            retryPacket = nil
            pendingEcho = nil
            lastEchoAt = now
            actions.append(.configured(configuration))
        }
        return actions
    }

    private func remember(_ packet: LCPPacket, now: TimeInterval) throws -> [PPPAction] {
        try remember(PPPControl(code: packet.code, identifier: packet.identifier, data: packet.data), proto: 0xc021, now: now)
    }
    private func remember(_ packet: PPPControl, proto: UInt16, now: TimeInterval) throws -> [PPPAction] {
        let output = try packet.frame(protocolNumber: proto)
        retryPacket = output
        retryAt = now
        return [.send(output)]
    }
    private func frame(_ packet: LCPPacket) throws -> PPPFrame {
        try PPPControl(code: packet.code, identifier: packet.identifier, data: packet.data).frame(protocolNumber: 0xc021)
    }
    private static func validIPv4(_ bytes: [UInt8], address: IPv4Value, source: Bool) -> Bool {
        guard bytes.count >= 20, bytes[0] >> 4 == 4 else { return false }
        let header = Int(bytes[0] & 15) * 4
        guard header >= 20, header <= bytes.count, Int(Wire.read16(bytes, 2)) == bytes.count else { return false }
        let offset = source ? 12 : 16
        return bytes[offset..<offset + 4].elementsEqual(address.bytes)
    }
}
