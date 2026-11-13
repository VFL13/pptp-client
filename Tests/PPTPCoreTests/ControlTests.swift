import XCTest
@testable import PPTPCore

final class ControlTests: XCTestCase {
    // Independently laid out SCCRP fixture, RFC 2637 §2.2.
    private func serverReply(result: UInt8 = 1, version: UInt8 = 1) -> [UInt8] {
        [0, 156, 0, 1, 0x1a, 0x2b, 0x3c, 0x4d, 0, 2, 0, 0,
         version, 0, result, 0, 0, 0, 0, 3, 0, 0, 0, 3, 0, 1, 0, 1]
            + Array("server".utf8) + [UInt8](repeating: 0, count: 58)
            + Array("vendor".utf8) + [UInt8](repeating: 0, count: 58)
    }

    func testStartRequestWireLayout() throws {
        let bytes = try ControlMessage.startRequest().encoded()
        XCTAssertEqual(bytes.count, 156)
        XCTAssertEqual(Array(bytes.prefix(28)), [0, 156, 0, 1, 0x1a, 0x2b, 0x3c, 0x4d,
            0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 3, 0, 0, 0, 1])
        XCTAssertEqual(Array(bytes[28..<39]), Array("pptp-client".utf8))
        XCTAssertTrue(bytes[39..<92].allSatisfy { $0 == 0 })
    }

    func testRejectsEveryTruncationAndTrailingData() {
        let valid = serverReply()
        for length in 0..<valid.count {
            XCTAssertThrowsError(try ControlMessage.decode(Array(valid.prefix(length))))
        }
        XCTAssertThrowsError(try ControlMessage.decode(valid + [0]))
    }

    func testRejectsBadHeaderBeforeReadingBody() {
        let valid = Array(serverReply().prefix(12))
        for (offset, value): (Int, UInt8) in [(0, 255), (1, 0), (3, 2), (4, 0), (9, 99)] {
            var header = valid
            header[offset] = value
            XCTAssertThrowsError(try ControlMessage.frameLength(header: header))
        }
    }

    func testReservedHeaderIsIgnored() throws {
        var bytes = serverReply()
        bytes[10] = 255
        XCTAssertEqual(try ControlMessage.decode(bytes).startReply().host, "server")
    }

    func testServerRejectionAndVersionMismatch() {
        XCTAssertThrowsError(try ControlMessage.decode(serverReply(result: 4)).startReply())
        XCTAssertThrowsError(try ControlMessage.decode(serverReply(version: 2)).startReply())
    }

    func testServerTextCannotInjectTerminalEscapes() throws {
        var bytes = serverReply()
        bytes[28] = 0x1b
        XCTAssertEqual(try ControlMessage.decode(bytes).startReply().host, "?erver")
    }

    func testProbeAnswersEchoThenClosesWithoutCreatingCall() throws {
        let echo: [UInt8] = [0, 16, 0, 1, 0x1a, 0x2b, 0x3c, 0x4d, 0, 5, 0, 0, 1, 2, 3, 4]
        let stop: [UInt8] = [0, 16, 0, 1, 0x1a, 0x2b, 0x3c, 0x4d, 0, 4, 0, 0, 1, 0, 0, 0]
        let transport = FixtureTransport(serverReply() + echo + stop)
        let report = try ControlProbe.run(over: transport)
        XCTAssertTrue(report.cleanShutdown)
        XCTAssertEqual(report.server.vendor, "vendor")
        XCTAssertEqual(transport.writes.map { $0[9] }, [1, 3, 6])
        XCTAssertEqual(Array(transport.writes[2].suffix(8)), [1, 2, 3, 4, 1, 0, 0, 0])
        XCTAssertTrue(transport.incoming.isEmpty)
    }

    func testUnconfirmedShutdownIsNotReportedAsClean() throws {
        let report = try ControlProbe.run(over: FixtureTransport(serverReply()))
        XCTAssertFalse(report.cleanShutdown)
        XCTAssertNotNil(report.shutdownWarning)
    }

    func testRejectedStartDoesNotProceed() {
        let transport = FixtureTransport(serverReply(result: 4))
        XCTAssertThrowsError(try ControlProbe.run(over: transport))
        XCTAssertEqual(transport.writes.count, 1)
    }

    func testEchoFloodIsBounded() throws {
        let echo: [UInt8] = [0, 16, 0, 1, 0x1a, 0x2b, 0x3c, 0x4d, 0, 5, 0, 0, 0, 0, 0, 0]
        let transport = FixtureTransport(serverReply() + Array(repeating: echo, count: 20).flatMap { $0 })
        let report = try ControlProbe.run(over: transport)
        XCTAssertFalse(report.cleanShutdown)
        XCTAssertEqual(transport.writes.count, 18)
    }

    func testCallSetupAndShutdownConsumeQueuedLinkInfo() throws {
        let callReply = ControlMessage(type: 8, payload: [0, 99, 0, 42, 1, 0, 0, 0,
                                                         0, 0, 0, 1, 0, 16, 0, 0, 0, 0, 0, 0])
        let linkInfo = ControlMessage(type: 15, payload: [UInt8](repeating: 0, count: 12))
        let incoming = try serverReply() + callReply.encoded() + linkInfo.encoded() + ControlMessage.stopReply.encoded()
        let transport = FixtureTransport(incoming)
        let channel = ControlChannel(transport: transport)
        XCTAssertThrowsError(try channel.openCall(localCallID: 42, serial: 1))
        _ = try channel.start()
        XCTAssertThrowsError(try channel.start())
        XCTAssertEqual(try channel.openCall(localCallID: 42, serial: 1).peerCallID, 99)
        try channel.stop()
        try channel.stop()
        XCTAssertEqual(transport.writes.map { $0[9] }, [1, 7, 3])
        XCTAssertTrue(transport.incoming.isEmpty)
    }

    func testRejectedCallCanStillCloseControlConnection() throws {
        let reply = ControlMessage(type: 8, payload: [0, 99, 0, 42, 7, 0, 0, 0,
                                                     0, 0, 0, 1, 0, 16, 0, 0, 0, 0, 0, 0])
        let incoming = try serverReply() + reply.encoded() + ControlMessage.stopReply.encoded()
        let transport = FixtureTransport(incoming)
        let channel = ControlChannel(transport: transport)
        _ = try channel.start()
        XCTAssertThrowsError(try channel.openCall(localCallID: 42, serial: 1))
        try channel.stop()
        XCTAssertEqual(transport.writes.map { $0[9] }, [1, 7, 3])
    }
}

private final class FixtureTransport: ControlTransport {
    var incoming: [UInt8]
    var writes: [[UInt8]] = []

    init(_ incoming: [UInt8]) { self.incoming = incoming }

    func write(_ bytes: [UInt8]) throws { writes.append(bytes) }

    func readExactly(_ count: Int) throws -> [UInt8] {
        guard incoming.count >= count else { throw PPTPError("fixture connection closed") }
        let result = Array(incoming.prefix(count))
        incoming.removeFirst(count)
        return result
    }
}
