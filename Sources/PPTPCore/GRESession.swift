import Foundation

/// Bounded GRE flow control (RFC 2637 §4.2–4.4). Missing ACKs shrink the
/// window and release expired packets; they do not terminate the VPN or cause
/// GRE retransmission. PPP and PPTP keepalives detect an actual dead peer.
public final class GRESession {
    private let transport: any GRETransport
    private let localCallID: UInt16
    private let peerCallID: UInt16
    private let maximumWindow: Int
    private var window: Int
    private var acknowledgedInWindow = 0
    private let acknowledgmentTimeout: TimeInterval = 15
    private let onTransmit: (PPPFrame, TimeInterval) -> Void
    private var nextSequence: UInt32 = 0
    private var receivedSequence: UInt32?
    private var outstanding: [(sequence: UInt32, time: TimeInterval)] = []
    private var queued: [PPPFrame] = []
    public var hasCapacity: Bool { queued.filter { $0.protocolNumber == 0x21 }.count < 64 }

    public init(transport: any GRETransport, localCallID: UInt16, peerCallID: UInt16, peerWindow: UInt16,
                onTransmit: @escaping (PPPFrame, TimeInterval) -> Void = { _, _ in }) throws {
        guard peerWindow > 0 else { throw PPTPError("invalid GRE window") }
        self.transport = transport
        self.localCallID = localCallID
        self.peerCallID = peerCallID
        maximumWindow = min(16, Int(peerWindow))
        window = max(1, maximumWindow / 2)
        self.onTransmit = onTransmit
    }

    public func send(_ frame: PPPFrame, now: TimeInterval) throws {
        guard frame.encoded().count <= 1532 else { throw PPTPError("GRE payload is too large") }
        if frame.protocolNumber == 0x21 {
            guard hasCapacity else { throw PPTPError("GRE send queue capacity exceeded") }
            queued.append(frame)
        } else {
            // Reserve bounded capacity for PPP control even when data is backed
            // up. Preserve order among control packets (including PAP/IPCP).
            guard queued.filter({ $0.protocolNumber != 0x21 }).count < 8 else {
                throw PPTPError("GRE control queue capacity exceeded")
            }
            let firstData = queued.firstIndex { $0.protocolNumber == 0x21 } ?? queued.endIndex
            queued.insert(frame, at: firstData)
        }
        try flush(now: now)
    }

    public func ingest(_ packet: GREPacket, now: TimeInterval) throws -> PPPFrame? {
        guard packet.callID == localCallID else { return nil }
        if let ack = packet.acknowledgment, let index = outstanding.firstIndex(where: { $0.sequence == ack }) {
            acknowledgedInWindow += index + 1
            outstanding.removeFirst(index + 1)
            if acknowledgedInWindow >= window {
                window = min(maximumWindow, window + 1)
                acknowledgedInWindow = 0
            }
        }
        var payload: [UInt8]?
        if let sequence = packet.sequence {
            let fresh = receivedSequence.map { Int32(bitPattern: sequence &- $0) > 0 } ?? true
            if fresh { receivedSequence = sequence; payload = packet.payload }
            try transport.send(GREPacket(callID: peerCallID, sequence: nil, acknowledgment: receivedSequence, payload: []))
        }
        try flush(now: now)
        return try payload.map(PPPFrame.decode)
    }

    public func tick(now: TimeInterval) throws {
        let expired = outstanding.prefix { now - $0.time >= acknowledgmentTimeout }.count
        if expired > 0 {
            outstanding.removeFirst(expired)
            window = max(1, (window + 1) / 2)
            acknowledgedInWindow = 0
        }
        try flush(now: now)
    }

    private func flush(now: TimeInterval) throws {
        while outstanding.count < window, !queued.isEmpty {
            let frame = queued[0]
            try transport.send(GREPacket(callID: peerCallID, sequence: nextSequence,
                                         acknowledgment: receivedSequence, payload: frame.encoded()))
            queued.removeFirst()
            outstanding.append((nextSequence, now))
            nextSequence &+= 1
            onTransmit(frame, now)
        }
    }
}
