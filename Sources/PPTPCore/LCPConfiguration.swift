import Foundation

/// An explicit policy: no implicit fallback from MS-CHAPv2 to PAP.
public enum LCPAuthenticationPolicy: String, Sendable {
    case requireMSCHAPv2 = "MS-CHAPv2"
    case requirePAP = "PAP"

    var option: LCPOption {
        LCPOption(type: 3, value: self == .requireMSCHAPv2 ? [0xc2, 0x23, 0x81] : [0xc0, 0x23])
    }
}

/// Establishment-only configuration engine (RFC 1661 §5.1–5.4).
/// No sockets, credentials, authentication packets, timers or interface changes.
/// The eventual session runner must supply retransmission/deadline handling.
public final class LCPConfiguration {
    public private(set) var localAcknowledged = false
    public private(set) var peerAcknowledged = false
    public private(set) var peerMRU: UInt16 = 1500
    public private(set) var localMRU: UInt16 = 1400
    public private(set) var localMagic: UInt32?
    public private(set) var authentication: String?
    public var readyForAuthentication: Bool { localAcknowledged && peerAcknowledged }

    private let policy: LCPAuthenticationPolicy
    private let newMagic: () -> UInt32
    private var pending: LCPPacket?
    private var proposals = 0
    private var exchanges = 0

    public init(policy: LCPAuthenticationPolicy, newMagic: @escaping () -> UInt32 = { UInt32.random(in: 1...UInt32.max) }) {
        self.policy = policy
        self.newMagic = newMagic
    }

    public func start(identifier: UInt8, magic: UInt32) throws -> LCPPacket {
        guard pending == nil else { throw PPTPError("LCP configuration already started") }
        let request = LCPPacket.configureRequest(identifier: identifier, magic: magic)
        pending = request
        proposals = 1
        return request
    }

    /// Returns LCP replies or a revised local proposal. Completion means only
    /// that configuration is agreed, never that authentication or MPPE succeeded.
    public func receive(_ packet: LCPPacket) throws -> [LCPPacket] {
        guard let request = pending else { throw PPTPError("LCP configuration has not started") }
        guard !readyForAuthentication else { throw PPTPError("LCP configuration already complete") }
        exchanges += 1
        guard exchanges <= 64 else { throw PPTPError("LCP configuration exchange limit reached") }
        if packet.code == 1 { return [try reply(to: packet, request: request)] }
        guard packet.identifier == request.identifier else { return [] }
        switch packet.code {
        case 2:
            // RFC: an Ack must copy all options, unmodified and in order.
            guard packet.data == request.data else { return [] }
            let options = try LCPOption.parse(request.data)
            let mru = options.first { $0.type == 1 }
            localMRU = mru.map { Wire.read16($0.value, 0) } ?? 1500
            localMagic = options.first { $0.type == 5 }.map { Wire.read32($0.value, 0) }
            localAcknowledged = true
            return []
        case 3: return try revise(request, nak: packet)
        case 4: return try revise(request, rejection: packet)
        default: return []
        }
    }

    private func reply(to peer: LCPPacket, request: LCPPacket) throws -> LCPPacket {
        let options = try uniqueOptions(peer.data)
        peerAcknowledged = false
        authentication = nil
        var rejected: [LCPOption] = []
        var corrections: [LCPOption] = []
        var mru: UInt16 = 1500
        let ownMagic = try LCPOption.parse(request.data).first { $0.type == 5 }?.value
        for option in options {
            switch (option.type, option.value.count) {
            case (1, 2):
                mru = Wire.read16(option.value, 0)
                if mru < 128 { corrections.append(LCPOption(type: 1, value: Wire.u16(128))) }
            case (2, 4), (7, 0), (8, 0): break
            case (3, _):
                // Reject malformed authentication fields; Nak an unsupported method.
                _ = try option.authenticationName()
                if option != policy.option { corrections.append(policy.option) }
            case (5, 4):
                if option.value == ownMagic {
                    corrections.append(LCPOption(type: 5, value: Wire.u32(try distinctMagic(from: ownMagic))))
                }
            default: rejected.append(option)
            }
        }
        if !rejected.isEmpty { return try response(4, to: peer, options: rejected) }
        if !options.contains(where: { $0.type == 3 }) { corrections.append(policy.option) }
        if !corrections.isEmpty { return try response(3, to: peer, options: corrections) }
        peerAcknowledged = true
        authentication = policy.rawValue
        peerMRU = mru
        return LCPPacket(code: 2, identifier: peer.identifier, data: peer.data)
    }

    private func revise(_ request: LCPPacket, nak: LCPPacket) throws -> [LCPPacket] {
        let suggestions = try uniqueOptions(nak.data)
        var options = try LCPOption.parse(request.data)
        for suggestion in suggestions {
            switch (suggestion.type, suggestion.value.count) {
            case (1, 2):
                let mru = Wire.read16(suggestion.value, 0)
                guard (128...1500).contains(mru) else { throw PPTPError("server proposed an unsupported MRU") }
            case (2, 4): break
            case (5, 4):
                let replacement = LCPOption(type: 5, value: Wire.u32(try distinctMagic(from: suggestion.value)))
                replace(replacement, in: &options)
                continue
            case (3, _):
                // Copying this into our request would ask the server to authenticate
                // to us, which is a different direction of PPP authentication.
                throw PPTPError("server requested peer authentication; mutual PPP authentication is not implemented")
            case (7, _), (8, _): return [] // Boolean options cannot be Nak'd.
            default: continue // Do not echo arbitrary peer-supplied options.
            }
            replace(suggestion, in: &options)
        }
        return [try nextRequest(after: request, options: options)]
    }

    private func revise(_ request: LCPPacket, rejection: LCPPacket) throws -> [LCPPacket] {
        let rejected = try uniqueOptions(rejection.data)
        let options = try LCPOption.parse(request.data)
        guard !rejected.isEmpty else { return [] }
        var cursor = 0
        for option in rejected {
            guard let match = options[cursor...].firstIndex(of: option) else { return [] }
            cursor = match + 1
        }
        return [try nextRequest(after: request, options: options.filter { !rejected.contains($0) })]
    }

    private func nextRequest(after previous: LCPPacket, options: [LCPOption]) throws -> LCPPacket {
        guard proposals < 10 else { throw PPTPError("LCP configuration proposal limit reached") }
        let data = try options.flatMap { try $0.encoded() }
        let request = LCPPacket(code: 1, identifier: previous.identifier &+ 1, data: data)
        proposals += 1
        pending = request
        localAcknowledged = false
        return request
    }

    private func uniqueOptions(_ data: [UInt8]) throws -> [LCPOption] {
        let options = try LCPOption.parse(data)
        guard Set(options.map(\.type)).count == options.count else { throw PPTPError("duplicate LCP configuration options") }
        return options
    }

    private func distinctMagic(from bytes: [UInt8]?) throws -> UInt32 {
        for _ in 0..<8 {
            let candidate = newMagic()
            if candidate != 0, Wire.u32(candidate) != bytes { return candidate }
        }
        throw PPTPError("could not choose a distinct LCP magic number")
    }

    private func replace(_ option: LCPOption, in options: inout [LCPOption]) {
        if let index = options.firstIndex(where: { $0.type == option.type }) { options[index] = option }
        else { options.append(option) }
    }

    private func response(_ code: UInt8, to request: LCPPacket, options: [LCPOption]) throws -> LCPPacket {
        LCPPacket(code: code, identifier: request.identifier, data: try options.flatMap { try $0.encoded() })
    }
}
