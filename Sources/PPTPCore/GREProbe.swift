import Foundation

public protocol GRETransport: AnyObject {
    func send(_ packet: GREPacket) throws
    func receive() throws -> GREPacket
}

public struct GREProbeReport: Sendable {
    public let receivedDataPackets: Int
    public let sawLCP: Bool
    public let bidirectionalLCP: Bool
    public let requestedAuthentication: String?
    public let detail: String
}

/// Sends exactly one LCP Configure-Request. Never acknowledges the peer's PPP
/// Configure-Request, so the link cannot advance to authentication. GRE-level
/// acknowledgments are independent and do not open the PPP link.
public enum GREProbe {
    public static func run(over transport: any GRETransport, localCallID: UInt16,
                           peerCallID: UInt16, identifier: UInt8, magic: UInt32) -> GREProbeReport {
        var received = 0
        var sawLCP = false
        var authentication: String?
        var lastSequence: UInt32?
        func report(_ confirmed: Bool, _ detail: String) -> GREProbeReport {
            GREProbeReport(receivedDataPackets: received, sawLCP: sawLCP, bidirectionalLCP: confirmed,
                           requestedAuthentication: authentication, detail: detail)
        }
        do {
            let request = LCPPacket.configureRequest(identifier: identifier, magic: magic)
            try transport.send(GREPacket(callID: peerCallID, sequence: 0, acknowledgment: nil,
                                         payload: request.pppEncoded()))
            // Also bounded by the transport's overall monotonic deadline.
            for _ in 0..<128 {
                let packet = try transport.receive()
                guard packet.callID == localCallID, let sequence = packet.sequence else { continue }
                let fresh = lastSequence.map { Int32(bitPattern: sequence &- $0) > 0 } ?? true
                if fresh { lastSequence = sequence }
                try transport.send(GREPacket(callID: peerCallID, sequence: nil,
                                             acknowledgment: lastSequence, payload: []))
                guard fresh else { continue }
                received += 1
                guard let lcp = try LCPPacket.decodePPP(packet.payload) else { continue }
                sawLCP = true
                if let auth = try lcp.requestedAuthentication() { authentication = auth }
                guard lcp.identifier == identifier else { continue }
                if lcp.code == 2, lcp.data == request.data {
                    return report(true, "server acknowledged our LCP Configure-Request")
                }
                if lcp.code == 3 || lcp.code == 4 {
                    return report(true, "server answered our LCP request with Configure-\(lcp.code == 3 ? "Nak" : "Reject"): \(try lcp.configurationSummary())")
                }
            }
            return report(false, "packet limit reached without a matching LCP response")
        } catch {
            return report(false, String(describing: error))
        }
    }
}
