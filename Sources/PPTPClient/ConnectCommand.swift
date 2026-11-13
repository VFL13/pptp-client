import CMacSupport
import Darwin
import Dispatch
import Foundation
import PPTPCore

func loadProfile(_ args: [String], allowCheck: Bool) throws -> (ClientConfiguration, Bool) {
    var path: String?
    var checkOnly = false
    var index = 0
    while index < args.count {
        switch args[index] {
        case "--config":
            guard path == nil, index + 1 < args.count else { throw PPTPError("provide one --config JSON path") }
            path = args[index + 1]
            index += 2
        case "--check-only" where allowCheck && !checkOnly:
            checkOnly = true
            index += 1
        default: throw PPTPError("unsupported connect option; use --config PATH and optionally --check-only")
        }
    }
    guard let path else { throw PPTPError("--config PATH is required") }
    let url = URL(fileURLWithPath: path)
    let size = try url.resourceValues(forKeys: [.fileSizeKey]).fileSize ?? 0
    guard size <= 65536 else { throw PPTPError("configuration file is too large") }
    return (try ClientConfiguration.load(Data(contentsOf: url)), checkOnly)
}

func checkConfiguration(_ args: [String]) throws {
    let (profile, _) = try loadProfile(args, allowCheck: false)
    print("Configuration: valid")
    print("Server: \(profile.server):\(profile.port ?? 1723)")
    print("Authentication: PAP; encryption: NONE")
    print("Routes: \(try profile.routes.map { try IPv4CIDR($0).description }.joined(separator: ", "))")
    print("DNS domains: \((profile.dnsDomains ?? []).joined(separator: ", "))")
}

func connectVPN(_ args: [String]) throws {
    let (profile, checkOnly) = try loadProfile(args, allowCheck: true)
    guard geteuid() == 0 else { throw PPTPError("connect requires administrator privileges (sudo)") }
    print("Mode: PPTP / PAP / NO ENCRYPTION")
    print(checkOnly ? "Check only: no interface, routes or DNS changes." : "Only routes from the configuration will use the VPN. Stop with Ctrl+C.")
    let credentials = try Credentials.prompt()
    guard pptp_install_signals() == 0 else { throw PPTPError("could not install signal handlers") }
    defer { pptp_restore_signals() }
    let raw = try RawGRETransport(ip: profile.server, deadline: .now() + 10)
    let controlTransport = try NetworkTransport(host: profile.server, port: profile.port ?? 1723, timeout: 10)
    let control = ControlChannel(transport: controlTransport)
    _ = try control.start()
    var tunnel: TunnelInterface?
    var settings: NetworkSettings?
    defer {
        if let settings { for warning in settings.remove() { print("Cleanup: \(warning)") } }
        tunnel?.closeInterface()
        controlTransport.setDeadline(.now() + 2)
        do { try control.stop(); print("PPTP disconnected.") }
        catch { print("PPTP shutdown unconfirmed; TCP connection will be closed.") }
    }
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
            case .configured(let configuration):
                print("PAP authentication: accepted")
                print("PPP IPv4: \(configuration.localAddress); peer: \(configuration.peerAddress)")
                print("Assigned DNS: \(configuration.dnsServers.map(\.description).joined(separator: ", "))")
                if !checkOnly {
                    let publicServer = try IPv4Value(profile.server)
                    guard configuration.peerAddress != publicServer, configuration.localAddress != publicServer else {
                        throw PPTPError("assigned PPP address conflicts with the public VPN server; refusing a recursive tunnel route")
                    }
                    let interface = try TunnelInterface(configuration: configuration, mtu: client.mtu)
                    tunnel = interface
                    let networkSettings = NetworkSettings(interface: interface.name)
                    settings = networkSettings // Retain before apply so partial failures roll back.
                    try networkSettings.apply(profile: profile, network: configuration)
                    print("VPN connected on \(interface.name). Configured routes: \(profile.routes.count).")
                    if (profile.dnsDomains ?? []).isEmpty { print("DNS settings unchanged (no DNS domains configured).") }
                }
            case .ipv4(let packet): try tunnel?.writeIPv4(packet)
            case .closed: closedByPeer = true
            }
        }
    }

    try perform(client.start(now: ProcessInfo.processInfo.systemUptime), now: ProcessInfo.processInfo.systemUptime)
    while pptp_cancelled() == 0, !closedByPeer, !(checkOnly && client.phase == .network) {
        raw.setDeadline(.now() + 2)
        controlTransport.setDeadline(.now() + 2)
        let now = ProcessInfo.processInfo.systemUptime
        try control.service(now: now)
        // Bound work per iteration so control keepalives and signals cannot starve.
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
            print("PPP phase: \(client.phase.rawValue)")
            lastPhase = client.phase
        }
        var items = [pollfd(fd: raw.descriptor, events: Int16(POLLIN), revents: 0)]
        if let tunnel, gre.hasCapacity { items.append(pollfd(fd: tunnel.descriptor, events: Int16(POLLIN), revents: 0)) }
        let result = items.withUnsafeMutableBufferPointer { poll($0.baseAddress, nfds_t($0.count), 100) }
        if result < 0, errno != EINTR { throw PPTPError("VPN event loop failed") }
    }
    if closedByPeer { throw PPTPError("server closed the PPP link") }
    if checkOnly, client.phase == .network { print("Authentication and IPCP check completed; VPN interface was not created.") }
}
