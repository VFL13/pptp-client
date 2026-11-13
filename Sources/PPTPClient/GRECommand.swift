import Dispatch
import PPTPCore

func greProbe(_ args: [String]) throws -> Bool {
    let options = try ProbeOptions(args)
    let deadline = DispatchTime.now() + options.timeout
    // Open the socket before creating a call, so early server LCP packets queue.
    let gre = try RawGRETransport(ip: options.host, deadline: deadline)
    print("GRE socket: ready")
    let transport = try NetworkTransport(host: options.host, port: options.port, deadline: deadline + 2)
    let channel = ControlChannel(transport: transport)
    let server = try channel.start()
    print("PPTP control channel: established (\(server.host), \(server.vendor))")
    let report: GREProbeReport
    do {
        let localID = UInt16.random(in: 1...UInt16.max)
        let call = try channel.openCall(localCallID: localID, serial: UInt16.random(in: 0...UInt16.max))
        print("PPTP call: established")
        report = GREProbe.run(over: gre, localCallID: localID, peerCallID: call.peerCallID,
                              identifier: UInt8.random(in: 1...UInt8.max), magic: UInt32.random(in: 1...UInt32.max))
    } catch {
        _ = stop(channel)
        throw error
    }
    let clean = stop(channel)
    print("GRE data packets received for our call: \(report.receivedDataPackets)")
    print("PPP LCP received: \(report.sawLCP ? "yes" : "no")")
    print("Bidirectional GRE/PPP exchange: \(report.bidirectionalLCP ? "confirmed" : "unverified")")
    print("Server authentication request: \(report.requestedAuthentication ?? "not observed")")
    print("Detail: \(report.detail)")
    print("VPN is NOT connected. No credentials were sent; routes and DNS were not changed.")
    return report.bidirectionalLCP && clean
}

private func stop(_ channel: ControlChannel) -> Bool {
    do {
        try channel.stop()
        print("Control shutdown: confirmed")
        return true
    } catch {
        print("Control shutdown: unconfirmed (\(error))")
        return false
    }
}
