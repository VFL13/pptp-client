import Foundation
import XCTest
@testable import PPTPCore

final class SessionTests: XCTestCase {
    private func sent(_ actions: [PPPAction], proto: UInt16) throws -> PPPFrame {
        try XCTUnwrap(actions.compactMap { action -> PPPFrame? in
            if case .send(let frame) = action, frame.protocolNumber == proto { return frame }
            return nil
        }.first)
    }

    private func authenticated() throws -> (PPPClient, PPPControl) {
        let client = PPPClient(magic: 0x11223344)
        let own = try PPPControl.decode(sent(client.start(now: 0), proto: 0xc021).payload)
        let peer = try PPPControl(code: 1, identifier: 50, data: [3, 4, 0xc0, 0x23]).frame(protocolNumber: 0xc021)
        _ = try client.receive(peer, now: 1)
        _ = try client.receive(PPPControl(code: 2, identifier: own.identifier, data: own.data).frame(protocolNumber: 0xc021), now: 1)
        XCTAssertEqual(client.phase, .credentials)
        // Per-test generated values, never real or checked-in credentials.
        let auth = try sent(client.authenticate(username: Array(UUID().uuidString.utf8), password: Array(UUID().uuidString.utf8), now: 1), proto: 0xc023)
        let id = try PPPControl.decode(auth.payload).identifier
        let output = try client.receive(PPPControl(code: 2, identifier: id, data: [0]).frame(protocolNumber: 0xc023), now: 2)
        return (client, try PPPControl.decode(sent(output, proto: 0x8021).payload))
    }

    private func configured() throws -> PPPClient {
        let (client, request) = try authenticated()
        XCTAssertEqual(client.phase, .ipcp)
        let nak = PPPControl(code: 3, identifier: request.identifier, data: [3, 6, 10, 1, 2, 3, 129, 6, 10, 1, 2, 53])
        let revised = try PPPControl.decode(sent(client.receive(nak.frame(protocolNumber: 0x8021), now: 3), proto: 0x8021).payload)
        let peer = PPPControl(code: 1, identifier: 90, data: [3, 6, 10, 1, 2, 1])
        _ = try client.receive(peer.frame(protocolNumber: 0x8021), now: 3)
        let actions = try client.receive(PPPControl(code: 2, identifier: revised.identifier, data: revised.data).frame(protocolNumber: 0x8021), now: 4)
        XCTAssertTrue(actions.contains { if case .configured = $0 { return true }; return false })
        return client
    }

    func testPAPWireLayoutAndResponseCorrelation() throws {
        let username = Array(UUID().uuidString.utf8)
        let password = Array(UUID().uuidString.utf8)
        let request = try PAP.request(identifier: 42, username: username, password: password)
        let packet = try PPPControl.decode(request.payload)
        XCTAssertEqual(request.protocolNumber, 0xc023)
        XCTAssertEqual(packet.code, 1)
        XCTAssertEqual(packet.identifier, 42)
        XCTAssertEqual(packet.data.first, UInt8(username.count))
        XCTAssertEqual(Array(packet.data[1..<(1 + username.count)]), username)
        XCTAssertEqual(Array(packet.data.suffix(password.count)), password)
        XCTAssertEqual(try PAP.accepted(PPPControl(code: 2, identifier: 42, data: [0]), identifier: 42), true)
        XCTAssertEqual(try PAP.accepted(PPPControl(code: 3, identifier: 42, data: [0]), identifier: 42), false)
        XCTAssertNil(try PAP.accepted(PPPControl(code: 2, identifier: 41, data: [0]), identifier: 42))
        XCTAssertThrowsError(try PAP.accepted(PPPControl(code: 2, identifier: 42, data: [20]), identifier: 42))
        XCTAssertThrowsError(try PAP.request(identifier: 1, username: [1], password: [UInt8](repeating: 1, count: 256)))
    }

    func testPAPCannotBeSentBeforeBothLCPAcks() throws {
        let client = PPPClient(magic: 1)
        XCTAssertThrowsError(try client.authenticate(username: [1], password: [1], now: 0))
        _ = try client.start(now: 0)
        XCTAssertThrowsError(try client.authenticate(username: [1], password: [1], now: 0))
        let premature = try PPPControl(code: 2, identifier: 1, data: [0]).frame(protocolNumber: 0xc023)
        XCTAssertTrue(try client.receive(premature, now: 1).isEmpty)
        XCTAssertEqual(client.phase, .lcp)
    }

    func testCompletePAPIPCPAndDataAddressFiltering() throws {
        let client = try configured()
        XCTAssertEqual(client.phase, .network)
        XCTAssertTrue(try client.receive(PPPControl(code: 8, identifier: 0, data: [0x80, 0xfd]).frame(protocolNumber: 0xc021), now: 5).isEmpty)
        XCTAssertEqual(client.network?.localAddress.description, "10.1.2.3")
        XCTAssertEqual(client.network?.peerAddress.description, "10.1.2.1")
        XCTAssertEqual(client.network?.dnsServers.map(\.description), ["10.1.2.53"])
        var ip: [UInt8] = [0x45, 0, 0, 20, 0, 0, 0, 0, 64, 1, 0, 0, 10, 1, 2, 3, 10, 20, 30, 40]
        XCTAssertNotNil(try client.outboundIPv4(ip))
        XCTAssertTrue(try client.receive(PPPFrame(protocolNumber: 0x21, payload: ip), now: 5).isEmpty)
        ip[12] = 192
        XCTAssertNil(try client.outboundIPv4(ip))
        ip.replaceSubrange(16..<20, with: [10, 1, 2, 3])
        XCTAssertTrue(try client.receive(PPPFrame(protocolNumber: 0x21, payload: ip), now: 5).contains {
            if case .ipv4 = $0 { return true }; return false
        })
        ip[3] = 21
        XCTAssertNil(try client.outboundIPv4(ip))
    }

    func testPAPIsNotAutomaticallyRetriedAndMessagesDoNotLeakInErrors() throws {
        let client = PPPClient(magic: 1)
        let own = try PPPControl.decode(sent(client.start(now: 0), proto: 0xc021).payload)
        _ = try client.receive(PPPControl(code: 1, identifier: 5, data: [3, 4, 0xc0, 0x23]).frame(protocolNumber: 0xc021), now: 1)
        _ = try client.receive(PPPControl(code: 2, identifier: own.identifier, data: own.data).frame(protocolNumber: 0xc021), now: 1)
        let auth = try PPPControl.decode(sent(client.authenticate(username: [1], password: [2], now: 1), proto: 0xc023).payload)
        XCTAssertTrue(try client.tick(now: 10).isEmpty)
        let marker = Array(UUID().uuidString.utf8)
        XCTAssertThrowsError(try client.receive(PPPControl(code: 3, identifier: auth.identifier,
                                                           data: [UInt8(marker.count)] + marker).frame(protocolNumber: 0xc023), now: 11)) { error in
            XCTAssertFalse(String(describing: error).contains(String(decoding: marker, as: UTF8.self)))
        }
    }

    func testIPCPRejectsZeroAddressAndCanDropRejectedDNSOptions() throws {
        let ipcp = IPCPConfiguration()
        let request = try ipcp.start(identifier: 1)
        let rejectedDNS = Array(request.data.dropFirst(6))
        let revised = try XCTUnwrap(ipcp.receive(PPPControl(code: 4, identifier: 1, data: rejectedDNS)).first)
        XCTAssertEqual(revised.data, [3, 6, 0, 0, 0, 0])
        _ = try ipcp.receive(PPPControl(code: 1, identifier: 8, data: [3, 6, 10, 0, 0, 1]))
        XCTAssertThrowsError(try ipcp.receive(PPPControl(code: 2, identifier: revised.identifier, data: revised.data)))
        let other = IPCPConfiguration()
        _ = try other.start(identifier: 1)
        XCTAssertThrowsError(try other.receive(PPPControl(code: 4, identifier: 1, data: [3, 6, 0, 0, 0, 0])))
    }

    func testGREWindowQueueDuplicatesAndAckRecovery() throws {
        let transport = RecordingGRE()
        let session = try GRESession(transport: transport, localCallID: 10, peerCallID: 20, peerWindow: 2)
        try session.send(PPPFrame(protocolNumber: 0x21, payload: [1]), now: 0)
        try session.send(PPPFrame(protocolNumber: 0x21, payload: [2]), now: 0)
        XCTAssertEqual(transport.sent.count, 1)
        _ = try session.ingest(GREPacket(callID: 99, sequence: nil, acknowledgment: 0, payload: []), now: 1)
        XCTAssertEqual(transport.sent.count, 1)
        _ = try session.ingest(GREPacket(callID: 10, sequence: nil, acknowledgment: 0, payload: []), now: 1)
        XCTAssertEqual(transport.sent.compactMap(\.sequence), [0, 1])
        let incoming = GREPacket(callID: 10, sequence: 0, acknowledgment: 1, payload: [0xff, 3, 0, 0x21, 9])
        XCTAssertNotNil(try session.ingest(incoming, now: 2))
        XCTAssertNil(try session.ingest(incoming, now: 2))
        try session.tick(now: 100)
        try session.send(PPPFrame(protocolNumber: 0x21, payload: [3]), now: 100)
        XCTAssertNoThrow(try session.tick(now: 116))
    }

    func testPPPTimersEchoAndTermination() throws {
        let client = try configured()
        let frame = try sent(client.tick(now: 25), proto: 0xc021)
        client.transmitted(frame, now: 25)
        let echo = try PPPControl.decode(frame.payload)
        XCTAssertEqual(echo.code, 9)
        _ = try client.receive(PPPControl(code: 10, identifier: echo.identifier, data: [0, 0, 0, 1]).frame(protocolNumber: 0xc021), now: 26)
        XCTAssertTrue(try client.tick(now: 27).isEmpty)
        let termination = try client.receive(PPPControl(code: 5, identifier: 5, data: []).frame(protocolNumber: 0xc021), now: 28)
        XCTAssertEqual(client.phase, .closed)
        XCTAssertTrue(termination.contains { if case .closed = $0 { return true }; return false })
        let idle = PPPClient(magic: 1)
        _ = try idle.start(now: 0)
        XCTAssertThrowsError(try idle.tick(now: 31))
    }

    func testPPPKeepaliveClockStartsAtTransmissionNotEnqueue() throws {
        let client = try configured()
        let echo = try sent(client.tick(now: 25), proto: 0xc021)
        let packet = try PPPControl.decode(echo.payload)
        // A reply to an echo that has not gone on the wire cannot prove liveness.
        _ = try client.receive(PPPControl(code: 10, identifier: packet.identifier, data: [0, 0, 0, 1]).frame(protocolNumber: 0xc021), now: 26)
        XCTAssertTrue(try client.tick(now: 60).isEmpty)
        client.transmitted(echo, now: 60)
        XCTAssertTrue(try client.tick(now: 79).isEmpty)
        XCTAssertThrowsError(try client.tick(now: 81))
    }

    func testGRETimeoutRecoveryDoesNotHideADeadPPPLink() throws {
        let client = try configured()
        let transport = RecordingGRE()
        let gre = try GRESession(transport: transport, localCallID: 10, peerCallID: 20, peerWindow: 1,
                                 onTransmit: { client.transmitted($0, now: $1) })
        try gre.send(PPPFrame(protocolNumber: 0x21, payload: [1]), now: 4)
        let echo = try sent(client.tick(now: 25), proto: 0xc021)
        try gre.send(echo, now: 25)
        try gre.tick(now: 25) // Releases the lost data packet and sends the echo.
        try gre.tick(now: 41) // Losing this GRE ACK is also recoverable.
        XCTAssertThrowsError(try client.tick(now: 46)) { error in
            XCTAssertEqual(String(describing: error), "PPP keepalive timed out")
        }
    }

    func testTenMinutesOfLostGREACKsWithResponsivePPPStayConnected() throws {
        let client = try configured()
        let transport = RecordingGRE()
        let gre = try GRESession(transport: transport, localCallID: 10, peerCallID: 20, peerWindow: 1,
                                 onTransmit: { client.transmitted($0, now: $1) })
        var cursor = 0
        var serverSequence: UInt32 = 0
        var echoes = 0
        for second in 5...605 {
            let now = Double(second)
            if second % 11 == 0 { try gre.send(PPPFrame(protocolNumber: 0x21, payload: [1]), now: now) }
            for action in try client.tick(now: now) {
                if case .send(let frame) = action { try gre.send(frame, now: now) }
            }
            try gre.tick(now: now)
            while cursor < transport.sent.count {
                let packet = transport.sent[cursor]
                cursor += 1
                guard packet.sequence != nil else { continue }
                let frame = try PPPFrame.decode(packet.payload)
                guard frame.protocolNumber == 0xc021 else { continue }
                let control = try PPPControl.decode(frame.payload)
                guard control.code == 9 else { continue }
                echoes += 1
                let reply = try PPPControl(code: 10, identifier: control.identifier, data: [0, 0, 0, 1]).frame(protocolNumber: 0xc021)
                // Deliberately omit every GRE ACK, while PPP remains responsive.
                let incoming = GREPacket(callID: 10, sequence: serverSequence, acknowledgment: nil, payload: reply.encoded())
                serverSequence &+= 1
                if let received = try gre.ingest(incoming, now: now) { _ = try client.receive(received, now: now) }
            }
            XCTAssertEqual(client.phase, .network)
        }
        XCTAssertGreaterThan(echoes, 20)
        let sequences = transport.sent.compactMap(\.sequence)
        XCTAssertEqual(sequences, Array(0..<UInt32(sequences.count)))
    }

    func testConfigurationRoutesAndCredentialKeys() throws {
        let base: [String: Any] = ["server": "198.51.100.7", "authentication": "pap", "encryption": "none", "routes": ["10.20.0.0/16"]]
        XCTAssertNoThrow(try ClientConfiguration.load(JSONSerialization.data(withJSONObject: base)))
        for route in ["0.0.0.0/0", "198.51.100.0/24", "invalid"] {
            var invalid = base
            invalid["routes"] = [route]
            XCTAssertThrowsError(try ClientConfiguration.load(JSONSerialization.data(withJSONObject: invalid)))
        }
        var credentialKey = base
        credentialKey["password"] = UUID().uuidString
        XCTAssertThrowsError(try ClientConfiguration.load(JSONSerialization.data(withJSONObject: credentialKey)))
        XCTAssertEqual(try IPv4CIDR("10.20.3.4/16").description, "10.20.0.0/16")
        XCTAssertThrowsError(try IPv4Value("010.0.0.1"))
    }
}

private final class RecordingGRE: GRETransport {
    var sent: [GREPacket] = []
    func send(_ packet: GREPacket) throws { sent.append(packet) }
    func receive() throws -> GREPacket { throw PPTPError("unused blocking receive") }
}
