import Foundation

public struct PPPNetworkConfiguration: Equatable, Sendable {
    public let localAddress: IPv4Value
    public let peerAddress: IPv4Value
    public let dnsServers: [IPv4Value]
}

/// IPv4-only IPCP, RFC 1332 and RFC 1877. No VJ compression or IPv6.
public final class IPCPConfiguration {
    public private(set) var configuration: PPPNetworkConfiguration?
    private var pending: PPPControl?
    private var localAck = false
    private var peerAddress: IPv4Value?
    private var proposals = 0
    private var exchanges = 0

    public init() {}

    public func start(identifier: UInt8) throws -> PPPControl {
        guard pending == nil else { throw PPTPError("IPCP already started") }
        let options = [UInt8(3), 129, 131].flatMap { type -> [UInt8] in [type, 6, 0, 0, 0, 0] }
        let request = PPPControl(code: 1, identifier: identifier, data: options)
        pending = request
        proposals = 1
        return request
    }

    public func receive(_ packet: PPPControl) throws -> [PPPControl] {
        guard let request = pending else { throw PPTPError("IPCP has not started") }
        exchanges += 1
        guard exchanges <= 64 else { throw PPTPError("IPCP exchange limit reached") }
        var output: [PPPControl] = []
        if packet.code == 1 {
            peerAddress = nil
            let options = try unique(packet.data)
            let rejected = options.filter { $0.type != 3 || $0.value.count != 4 }
            if !rejected.isEmpty {
                output = [PPPControl(code: 4, identifier: packet.identifier, data: try rejected.flatMap { try $0.encoded() })]
            } else {
                guard let addressOption = options.first(where: { $0.type == 3 }) else {
                    throw PPTPError("server omitted its IPCP address")
                }
                let address = try IPv4Value(bytes: addressOption.value)
                guard address.isUnicast else { throw PPTPError("server proposed an invalid IPCP peer address") }
                peerAddress = address
                output = [PPPControl(code: 2, identifier: packet.identifier, data: packet.data)]
            }
        } else if packet.identifier == request.identifier {
            switch packet.code {
            case 2:
                if packet.data == request.data { localAck = true }
            case 3:
                let suggestions = try unique(packet.data)
                var options = try LCPOption.parse(request.data)
                for suggestion in suggestions where [3, 129, 131].contains(suggestion.type) {
                    let address = try IPv4Value(bytes: suggestion.value)
                    guard address.isUnicast else { throw PPTPError("server proposed an invalid IPCP address") }
                    if let index = options.firstIndex(where: { $0.type == suggestion.type }) { options[index] = suggestion }
                }
                output = [try next(request, options: options)]
            case 4:
                let rejected = try unique(packet.data)
                let options = try LCPOption.parse(request.data)
                var cursor = 0
                guard !rejected.isEmpty else { return [] }
                for option in rejected {
                    guard let index = options[cursor...].firstIndex(of: option) else { return [] }
                    cursor = index + 1
                }
                guard !rejected.contains(where: { $0.type == 3 }) else { throw PPTPError("server rejected IPCP address assignment") }
                output = [try next(request, options: options.filter { !rejected.contains($0) })]
            default: break
            }
        }
        if localAck, let peerAddress, let pending {
            let options = try LCPOption.parse(pending.data)
            guard let assigned = options.first(where: { $0.type == 3 }) else { throw PPTPError("no assigned IPCP address") }
            let local = try IPv4Value(bytes: assigned.value)
            guard local.isUnicast, local != peerAddress else { throw PPTPError("invalid assigned IPCP address") }
            let dns = try options.filter { $0.type == 129 || $0.type == 131 }.map { try IPv4Value(bytes: $0.value) }.filter(\.isUnicast)
            configuration = PPPNetworkConfiguration(localAddress: local, peerAddress: peerAddress, dnsServers: dns)
        }
        return output
    }

    private func next(_ previous: PPPControl, options: [LCPOption]) throws -> PPPControl {
        guard proposals < 10 else { throw PPTPError("IPCP proposal limit reached") }
        let request = PPPControl(code: 1, identifier: previous.identifier &+ 1, data: try options.flatMap { try $0.encoded() })
        pending = request
        proposals += 1
        localAck = false
        return request
    }

    private func unique(_ data: [UInt8]) throws -> [LCPOption] {
        let options = try LCPOption.parse(data)
        guard Set(options.map(\.type)).count == options.count else { throw PPTPError("duplicate IPCP options") }
        return options
    }
}
