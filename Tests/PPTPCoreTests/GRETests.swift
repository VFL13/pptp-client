import XCTest
@testable import PPTPCore

final class GRETests: XCTestCase {
    func testEnhancedGREWireFormatAndAckOnly() throws {
        let packet = GREPacket(callID: 0x1234, sequence: 0x11223344, acknowledgment: 0x55667788,
                               payload: [0xff, 3, 0xc0, 0x21])
        let wire: [UInt8] = [0x30, 0x81, 0x88, 0x0b, 0, 4, 0x12, 0x34,
                             0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0xff, 3, 0xc0, 0x21]
        XCTAssertEqual(try packet.encoded(), wire)
        XCTAssertEqual(try GREPacket.decode(wire), packet)
        let ack: [UInt8] = [0x20, 0x81, 0x88, 0x0b, 0, 0, 0x12, 0x34, 0, 0, 0, 7]
        XCTAssertEqual(try GREPacket.decode(ack).acknowledgment, 7)
        XCTAssertEqual(try GREPacket.decode(ack).encoded(), ack)
    }

    func testRejectsTruncationsAndInvalidGREFlags() throws {
        let wire: [UInt8] = [0x30, 1, 0x88, 0x0b, 0, 4, 0, 1, 0, 0, 0, 0, 0xff, 3, 0xc0, 0x21]
        for length in 0..<wire.count { XCTAssertThrowsError(try GREPacket.decode(Array(wire.prefix(length)))) }
        for (index, byte): (Int, UInt8) in [(0, 0xb0), (0, 0x10), (1, 0), (1, 3), (2, 0), (5, 0)] {
            var invalid = wire
            invalid[index] = byte
            XCTAssertThrowsError(try GREPacket.decode(invalid))
        }
        XCTAssertThrowsError(try GREPacket.decode(wire + [0]))
        XCTAssertThrowsError(try GREPacket(callID: 1, sequence: nil, acknowledgment: nil, payload: []).encoded())
        XCTAssertThrowsError(try GREPacket(callID: 1, sequence: nil, acknowledgment: 0, payload: [1]).encoded())
    }

    func testIPv4SourceAndHeaderValidation() throws {
        let source: [UInt8] = [198, 51, 100, 7]
        var ip: [UInt8] = [0x46, 0, 0, 0, 0, 0, 0, 0, 64, 47, 0, 0] + source + [192, 0, 2, 1, 0, 0, 0, 0]
        let gre: [UInt8] = [0x20, 0x81, 0x88, 0x0b, 0, 0, 0, 2, 0, 0, 0, 0]
        XCTAssertEqual(try GREPacket.decodeIPv4(ip + gre, expectedSource: source).callID, 2)
        XCTAssertThrowsError(try GREPacket.decodeIPv4(ip + gre, expectedSource: [1, 2, 3, 4]))
        ip[0] = 0x44
        XCTAssertThrowsError(try GREPacket.decodeIPv4(ip + gre, expectedSource: source))
        XCTAssertThrowsError(try GREPacket.decodeIPv4([0x45], expectedSource: source))
    }

    func testLCPWireFormatPaddingAndAuthentication() throws {
        let request = LCPPacket.configureRequest(identifier: 7, magic: 0x11223344)
        XCTAssertEqual(try request.pppEncoded(), [0xff, 3, 0xc0, 0x21, 1, 7, 0, 14,
                                                1, 4, 5, 0x78, 5, 6, 0x11, 0x22, 0x33, 0x44])
        let peer: [UInt8] = [0xc0, 0x21, 1, 99, 0, 9, 3, 5, 0xc2, 0x23, 0x81]
        XCTAssertEqual(try LCPPacket.decodePPP(peer + [0, 0])?.requestedAuthentication(), "MS-CHAPv2")
        XCTAssertNil(try LCPPacket.decodePPP([0, 0x21, 1, 2]))
        XCTAssertThrowsError(try LCPPacket.decodePPP([0xc0, 0x21, 1, 1, 0, 255]))
        XCTAssertThrowsError(try LCPPacket(code: 1, identifier: 1, data: [3, 0]).requestedAuthentication())
        XCTAssertThrowsError(try LCPPacket(code: 1, identifier: 1, data: [3, 4, 0xc2, 0x23]).requestedAuthentication())
    }

    func testBidirectionalProofRequiresMatchingLCPResponse() throws {
        let request = LCPPacket.configureRequest(identifier: 7, magic: 0x11223344)
        let peer = LCPPacket(code: 1, identifier: 55, data: [3, 5, 0xc2, 0x23, 0x81])
        let ack = LCPPacket(code: 2, identifier: 7, data: request.data)
        let transport = GREFixture([
            GREPacket(callID: 99, sequence: 0, acknowledgment: nil, payload: try ack.pppEncoded()), // Other call.
            GREPacket(callID: 10, sequence: 0, acknowledgment: nil, payload: try peer.pppEncoded()),
            GREPacket(callID: 10, sequence: 0, acknowledgment: nil, payload: try peer.pppEncoded()), // Duplicate.
            GREPacket(callID: 10, sequence: 1, acknowledgment: 0, payload: try ack.pppEncoded()),
        ])
        let result = GREProbe.run(over: transport, localCallID: 10, peerCallID: 20, identifier: 7, magic: 0x11223344)
        XCTAssertTrue(result.bidirectionalLCP)
        XCTAssertEqual(result.receivedDataPackets, 2)
        XCTAssertEqual(result.requestedAuthentication, "MS-CHAPv2")
        XCTAssertEqual(transport.sent.map(\.callID), [20, 20, 20, 20])
        XCTAssertEqual(transport.sent.map(\.sequence), [0, nil, nil, nil])
        XCTAssertEqual(transport.sent.map(\.acknowledgment), [nil, 0, 0, 1])
        // Only one PPP request; no Configure-Ack and no authentication data.
        XCTAssertEqual(transport.sent.filter { !$0.payload.isEmpty }.count, 1)
        XCTAssertEqual(try LCPPacket.decodePPP(transport.sent[0].payload)?.code, 1)
    }

    func testInboundAloneAndMismatchedAckDoNotClaimBidirectionalProof() throws {
        let wrongAck = LCPPacket(code: 2, identifier: 7, data: [1, 4, 5, 0x78])
        let transport = GREFixture([GREPacket(callID: 10, sequence: 0, acknowledgment: 0,
                                              payload: try wrongAck.pppEncoded())])
        let result = GREProbe.run(over: transport, localCallID: 10, peerCallID: 20, identifier: 7, magic: 1)
        XCTAssertFalse(result.bidirectionalLCP)
        XCTAssertTrue(result.sawLCP)
        XCTAssertEqual(result.receivedDataPackets, 1)
    }

    func testNoGREAndWrongIdentifierRemainUnverified() throws {
        let request = LCPPacket.configureRequest(identifier: 8, magic: 1)
        let ack = LCPPacket(code: 2, identifier: 8, data: request.data)
        let transport = GREFixture([GREPacket(callID: 10, sequence: 0, acknowledgment: nil,
                                              payload: try ack.pppEncoded())])
        XCTAssertFalse(GREProbe.run(over: transport, localCallID: 10, peerCallID: 20, identifier: 7, magic: 1).bidirectionalLCP)
        let empty = GREProbe.run(over: GREFixture([]), localCallID: 10, peerCallID: 20, identifier: 7, magic: 1)
        XCTAssertFalse(empty.bidirectionalLCP)
        XCTAssertEqual(empty.receivedDataPackets, 0)
    }

    func testLCPRejectStillConfirmsAResponseWithoutOpeningPPP() throws {
        let rejected = LCPPacket(code: 4, identifier: 7, data: [5, 6, 0, 0, 0, 1])
        let transport = GREFixture([GREPacket(callID: 10, sequence: 0, acknowledgment: nil,
                                              payload: try rejected.pppEncoded())])
        let result = GREProbe.run(over: transport, localCallID: 10, peerCallID: 20, identifier: 7, magic: 1)
        XCTAssertTrue(result.bidirectionalLCP)
        XCTAssertTrue(result.detail.contains("Reject"))
    }

    func testCallRequestLayoutAndReplyCorrelation() throws {
        let wire = try ControlMessage.outgoingCallRequest(callID: 0x1234, serial: 0x5678).encoded()
        XCTAssertEqual(wire.count, 168)
        XCTAssertEqual(Array(wire.prefix(16)), [0, 168, 0, 1, 0x1a, 0x2b, 0x3c, 0x4d,
                                               0, 7, 0, 0, 0x12, 0x34, 0x56, 0x78])
        XCTAssertEqual(Array(wire[32..<40]), [0, 16, 0, 0, 0, 0, 0, 0])
        let reply = ControlMessage(type: 8, payload: [0, 42, 0x12, 0x34, 1, 0, 0, 0,
                                                     0, 0, 0, 1, 0, 16, 0, 0, 0, 0, 0, 0])
        XCTAssertEqual(try reply.outgoingCallReply(localCallID: 0x1234).peerCallID, 42)
        XCTAssertThrowsError(try reply.outgoingCallReply(localCallID: 1))
        var rejected = reply.payload
        rejected[4] = 7
        XCTAssertThrowsError(try ControlMessage(type: 8, payload: rejected).outgoingCallReply(localCallID: 0x1234))
    }
}

private final class GREFixture: GRETransport {
    var packets: [GREPacket]
    var sent: [GREPacket] = []
    init(_ packets: [GREPacket]) { self.packets = packets }
    func send(_ packet: GREPacket) throws { sent.append(packet) }
    func receive() throws -> GREPacket {
        guard !packets.isEmpty else { throw PPTPError("test transport timed out") }
        return packets.removeFirst()
    }
}
