import Darwin
import Dispatch
import Foundation
import PPTPCore

public enum SessionRunError: Error { case cancelled }

public enum VPNRunner {
    /// Blocking worker entry point shared by the CLI and the privileged helper.
    public static func run(profile: ClientConfiguration, credentials: SessionCredentials,
                           checkOnly: Bool = false, cancelled: @escaping @Sendable () -> Bool,
                           update: @escaping @Sendable (SessionUpdate) -> Void) throws {
        defer { credentials.erase() }
        try profile.validate()
        if cancelled() { throw SessionRunError.cancelled }
        guard geteuid() == 0 else { throw PPTPError("VPN requires the privileged helper") }
        update(SessionUpdate(.connecting, "Соединение с сервером"))
        let raw = try RawGRETransport(ip: profile.server, deadline: .now() + 10)
        let transport = try NetworkTransport(host: profile.server, port: profile.port ?? 1723,
                                             deadline: .now() + 10, cancelled: cancelled)
        let control = ControlChannel(transport: transport)
        _ = try control.start()
        var tunnel: TunnelInterface?
        var settings: NetworkSettings?
        defer {
            update(SessionUpdate(.stopping, "Удаление маршрутов и завершение соединения"))
            if let settings {
                for message in settings.remove() { update(SessionUpdate(.stopping, message)) }
            }
            tunnel?.closeInterface()
            transport.setDeadline(.now() + 2)
            do { try control.stop() }
            catch { update(SessionUpdate(.stopping, "Управляющий канал будет закрыт")) }
            update(SessionUpdate(.disconnected, "Отключено"))
        }
        if cancelled() { return }
        let localID = UInt16.random(in: 1...UInt16.max)
        let call = try control.openCall(localCallID: localID, serial: UInt16.random(in: 0...UInt16.max))
        let client = PPPClient(magic: UInt32.random(in: 1...UInt32.max))
        let gre = try GRESession(transport: raw, localCallID: localID, peerCallID: call.peerCallID,
                                 peerWindow: call.receiveWindow, onTransmit: { client.transmitted($0, now: $1) })
        var closedByPeer = false
        var lastPhase = PPPPhase.idle

        func perform(_ actions: [PPPAction], now: TimeInterval) throws {
            for action in actions {
                switch action {
                case .send(let frame): try gre.send(frame, now: now)
                case .credentialsRequired: try perform(credentials.authenticate(client, now: now), now: now)
                case .configured(let network):
                    update(SessionUpdate(.configuring, "Настройка сети", address: network.localAddress.description, authenticated: true))
                    if !checkOnly {
                        let server = try IPv4Value(profile.server)
                        guard network.peerAddress != server, network.localAddress != server else {
                            throw PPTPError("assigned PPP address conflicts with the public VPN server")
                        }
                        let interface = try TunnelInterface(configuration: network, mtu: client.mtu)
                        tunnel = interface
                        let networkSettings = NetworkSettings(interface: interface.name)
                        settings = networkSettings
                        try networkSettings.apply(profile: profile, network: network)
                    }
                    update(SessionUpdate(.connected, checkOnly ? "Авторизация и IPCP проверены" : "VPN подключён",
                                         interface: tunnel?.name, address: network.localAddress.description, authenticated: true))
                case .ipv4(let packet): try tunnel?.writeIPv4(packet)
                case .closed: closedByPeer = true
                }
            }
        }

        try perform(client.start(now: ProcessInfo.processInfo.systemUptime), now: ProcessInfo.processInfo.systemUptime)
        while !cancelled(), !closedByPeer, !(checkOnly && client.phase == .network) {
            raw.setDeadline(.now() + 2)
            transport.setDeadline(.now() + 2)
            let now = ProcessInfo.processInfo.systemUptime
            try control.service(now: now)
            for _ in 0..<64 {
                guard let packet = try raw.receiveAvailable() else { break }
                if let frame = try gre.ingest(packet, now: now) { try perform(client.receive(frame, now: now), now: now) }
            }
            if let tunnel, gre.hasCapacity, let packet = try tunnel.readIPv4(), let frame = try client.outboundIPv4(packet) {
                try gre.send(frame, now: now)
            }
            try perform(client.tick(now: now), now: now)
            try gre.tick(now: now)
            if lastPhase != client.phase {
                let phase: SessionPhase?
                switch client.phase {
                case .lcp: phase = .lcp
                case .pap: phase = .authenticating
                case .ipcp: phase = .ipcp
                default: phase = nil
                }
                if let phase { update(SessionUpdate(phase, "", authenticated: phase == .ipcp)) }
                lastPhase = client.phase
            }
            var items = [pollfd(fd: raw.descriptor, events: Int16(POLLIN), revents: 0)]
            if let tunnel, gre.hasCapacity { items.append(pollfd(fd: tunnel.descriptor, events: Int16(POLLIN), revents: 0)) }
            let result = items.withUnsafeMutableBufferPointer { poll($0.baseAddress, nfds_t($0.count), 100) }
            if result < 0, errno != EINTR { throw PPTPError("VPN event loop failed") }
        }
        if closedByPeer { throw PPTPError("server closed the PPP link") }
    }
}
