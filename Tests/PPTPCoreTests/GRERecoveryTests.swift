import XCTest
@testable import PPTPCore

final class GRERecoveryTests: XCTestCase {
    func testLostFinalAckDoesNotDisconnectOrRetransmitGRE() throws {
        let wire = RecoveryTransport()
        let session = try GRESession(transport: wire, localCallID: 10, peerCallID: 20, peerWindow: 2)
        try session.send(PPPFrame(protocolNumber: 0x21, payload: [1]), now: 0)
        try session.tick(now: 16)
        XCTAssertEqual(wire.dataSequences, [0])
        try session.send(PPPFrame(protocolNumber: 0x21, payload: [2]), now: 20)
        XCTAssertEqual(wire.dataSequences, [0, 1])
    }

    func testLostAckReleasesBlockedWindowAndAcceptsLaterCumulativeAck() throws {
        let wire = RecoveryTransport()
        let session = try GRESession(transport: wire, localCallID: 10, peerCallID: 20, peerWindow: 2)
        for byte: UInt8 in 1...3 { try session.send(PPPFrame(protocolNumber: 0x21, payload: [byte]), now: 0) }
        XCTAssertEqual(wire.dataSequences, [0])
        try session.tick(now: 16)
        XCTAssertEqual(wire.dataSequences, [0, 1])
        _ = try session.ingest(GREPacket(callID: 10, sequence: nil, acknowledgment: 0, payload: []), now: 17)
        XCTAssertEqual(wire.dataSequences, [0, 1]) // Late ACK must not free sequence 1.
        _ = try session.ingest(GREPacket(callID: 10, sequence: nil, acknowledgment: 1, payload: []), now: 18)
        XCTAssertEqual(wire.dataSequences, [0, 1, 2])
    }

    func testIncomingDataWithoutAckDoesNotCauseFalseDisconnect() throws {
        let wire = RecoveryTransport()
        let session = try GRESession(transport: wire, localCallID: 10, peerCallID: 20, peerWindow: 4)
        try session.send(PPPFrame(protocolNumber: 0x21, payload: [1]), now: 0)
        for second in 1...120 {
            let packet = GREPacket(callID: 10, sequence: UInt32(second), acknowledgment: nil,
                                   payload: PPPFrame(protocolNumber: 0x21, payload: [2]).encoded())
            XCTAssertNotNil(try session.ingest(packet, now: Double(second)))
            try session.tick(now: Double(second))
        }
        XCTAssertEqual(wire.dataSequences, [0])
    }

    func testControlPacketsOvertakeQueuedDataInOrder() throws {
        let wire = RecoveryTransport()
        let session = try GRESession(transport: wire, localCallID: 10, peerCallID: 20, peerWindow: 2)
        for byte: UInt8 in 1...3 { try session.send(PPPFrame(protocolNumber: 0x21, payload: [byte]), now: 0) }
        let first = PPPFrame(protocolNumber: 0xc021, payload: [9, 1, 0, 8, 0, 0, 0, 1])
        let second = PPPFrame(protocolNumber: 0xc021, payload: [10, 2, 0, 8, 0, 0, 0, 1])
        try session.send(first, now: 1)
        try session.send(second, now: 1)
        _ = try session.ingest(GREPacket(callID: 10, sequence: nil, acknowledgment: 0, payload: []), now: 2)
        let firstSent = try XCTUnwrap(wire.sent.filter { $0.sequence != nil }.dropFirst().first)
        XCTAssertEqual(try PPPFrame.decode(firstSent.payload), first)
        _ = try session.ingest(GREPacket(callID: 10, sequence: nil, acknowledgment: 1, payload: []), now: 3)
        let sent = try wire.sent.filter { $0.sequence != nil }.map { try PPPFrame.decode($0.payload) }
        XCTAssertEqual(Array(sent.prefix(3)), [PPPFrame(protocolNumber: 0x21, payload: [1]), first, second])
    }

    func testTimeoutShrinksWindowAndCumulativeAckGrowsItAgain() throws {
        let wire = RecoveryTransport()
        let session = try GRESession(transport: wire, localCallID: 10, peerCallID: 20, peerWindow: 8)
        for byte: UInt8 in 0..<10 { try session.send(PPPFrame(protocolNumber: 0x21, payload: [byte]), now: 0) }
        XCTAssertEqual(wire.dataSequences, [0, 1, 2, 3])
        try session.tick(now: 16)
        XCTAssertEqual(wire.dataSequences, [0, 1, 2, 3, 4, 5])
        _ = try session.ingest(GREPacket(callID: 10, sequence: nil, acknowledgment: 99, payload: []), now: 17)
        XCTAssertEqual(wire.dataSequences.count, 6)
        _ = try session.ingest(GREPacket(callID: 10, sequence: nil, acknowledgment: 5, payload: []), now: 18)
        XCTAssertEqual(wire.dataSequences, Array(UInt32(0)...8))
        _ = try session.ingest(GREPacket(callID: 10, sequence: nil, acknowledgment: 8, payload: []), now: 19)
        XCTAssertEqual(wire.dataSequences, Array(UInt32(0)...9))
    }

    func testWindowNeverExceedsWhatPeerAdvertised() throws {
        let wire = RecoveryTransport()
        let session = try GRESession(transport: wire, localCallID: 10, peerCallID: 20, peerWindow: 1)
        for byte: UInt8 in 0..<4 { try session.send(PPPFrame(protocolNumber: 0x21, payload: [byte]), now: 0) }
        XCTAssertEqual(wire.dataSequences, [0])
        for ack: UInt32 in 0..<3 {
            _ = try session.ingest(GREPacket(callID: 10, sequence: nil, acknowledgment: ack, payload: []), now: 1)
            XCTAssertEqual(wire.dataSequences.count, Int(ack) + 2)
        }
    }

    func testControlHasReservedCapacityWhenDataQueueIsFull() throws {
        let wire = RecoveryTransport()
        let session = try GRESession(transport: wire, localCallID: 10, peerCallID: 20, peerWindow: 1)
        for _ in 0..<65 { try session.send(PPPFrame(protocolNumber: 0x21, payload: [1]), now: 0) }
        XCTAssertFalse(session.hasCapacity)
        XCTAssertThrowsError(try session.send(PPPFrame(protocolNumber: 0x21, payload: [2]), now: 1))
        let control = PPPFrame(protocolNumber: 0xc021, payload: [9, 1, 0, 8, 0, 0, 0, 1])
        for _ in 0..<8 { try session.send(control, now: 1) }
        XCTAssertThrowsError(try session.send(control, now: 1))
        try session.tick(now: 16)
        XCTAssertEqual(try PPPFrame.decode(try XCTUnwrap(wire.sent.last).payload), control)
    }
}

private final class RecoveryTransport: GRETransport {
    var sent: [GREPacket] = []
    var dataSequences: [UInt32] { sent.compactMap(\.sequence) }
    func send(_ packet: GREPacket) throws { sent.append(packet) }
    func receive() throws -> GREPacket { throw PPTPError("unused blocking receive") }
}
