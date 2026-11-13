import XCTest
@testable import PPTPCore

final class LCPConfigurationTests: XCTestCase {
    private let pap: [UInt8] = [3, 4, 0xc0, 0x23]
    private let mschap: [UInt8] = [3, 5, 0xc2, 0x23, 0x81]

    func testContinuesAfterNakAndAgreesBothDirections() throws {
        let negotiation = LCPConfiguration(policy: .requireMSCHAPv2)
        _ = try negotiation.start(identifier: 7, magic: 0x11223344)
        let peerPAP = LCPPacket(code: 1, identifier: 40, data: pap)
        XCTAssertEqual(try negotiation.receive(peerPAP), [LCPPacket(code: 3, identifier: 40, data: mschap)])
        XCTAssertFalse(negotiation.readyForAuthentication)
        let nak = LCPPacket(code: 3, identifier: 7, data: [1, 4, 5, 0xdc, 2, 6, 0, 0, 0, 0])
        let revised = try XCTUnwrap(negotiation.receive(nak).first)
        XCTAssertEqual(revised.identifier, 8)
        XCTAssertEqual(revised.data, [1, 4, 5, 0xdc, 5, 6, 0x11, 0x22, 0x33, 0x44, 2, 6, 0, 0, 0, 0])
        let peerMSCHAP = LCPPacket(code: 1, identifier: 41, data: [1, 4, 5, 0xdc] + mschap)
        XCTAssertEqual(try negotiation.receive(peerMSCHAP), [LCPPacket(code: 2, identifier: 41, data: peerMSCHAP.data)])
        XCTAssertFalse(negotiation.readyForAuthentication)
        XCTAssertTrue(try negotiation.receive(LCPPacket(code: 2, identifier: 8, data: revised.data)).isEmpty)
        XCTAssertTrue(negotiation.readyForAuthentication)
        XCTAssertEqual(negotiation.authentication, "MS-CHAPv2")
        XCTAssertEqual(negotiation.localMRU, 1500)
        XCTAssertEqual(negotiation.peerMRU, 1500)
    }

    func testPAPIsNeverAcceptedByMSCHAPPolicy() throws {
        let negotiation = LCPConfiguration(policy: .requireMSCHAPv2)
        let request = try negotiation.start(identifier: 1, magic: 1)
        _ = try negotiation.receive(LCPPacket(code: 2, identifier: 1, data: request.data))
        for id: UInt8 in 10...15 {
            let output = try negotiation.receive(LCPPacket(code: 1, identifier: id, data: pap))
            XCTAssertEqual(output, [LCPPacket(code: 3, identifier: id, data: mschap)])
            XCTAssertFalse(negotiation.readyForAuthentication)
            XCTAssertNil(negotiation.authentication)
        }
    }

    func testPAPRequiresAnExplicitPolicyAndBothAcks() throws {
        let negotiation = LCPConfiguration(policy: .requirePAP)
        let own = try negotiation.start(identifier: 1, magic: 1)
        let peer = LCPPacket(code: 1, identifier: 80, data: pap)
        XCTAssertEqual(try negotiation.receive(peer), [LCPPacket(code: 2, identifier: 80, data: pap)])
        XCTAssertFalse(negotiation.readyForAuthentication)
        _ = try negotiation.receive(LCPPacket(code: 2, identifier: 1, data: own.data))
        XCTAssertTrue(negotiation.readyForAuthentication)
        XCTAssertEqual(negotiation.authentication, "PAP")
    }

    func testMissingAuthenticationIsNakedInsteadOfSkipped() throws {
        let negotiation = LCPConfiguration(policy: .requireMSCHAPv2)
        _ = try negotiation.start(identifier: 1, magic: 1)
        let peer = LCPPacket(code: 1, identifier: 20, data: [1, 4, 5, 0xdc])
        XCTAssertEqual(try negotiation.receive(peer), [LCPPacket(code: 3, identifier: 20, data: mschap)])
        XCTAssertFalse(negotiation.peerAcknowledged)
    }

    func testAckMustMatchIdentifierOptionsAndOrder() throws {
        let negotiation = LCPConfiguration(policy: .requireMSCHAPv2)
        let own = try negotiation.start(identifier: 7, magic: 1)
        _ = try negotiation.receive(LCPPacket(code: 2, identifier: 8, data: own.data))
        _ = try negotiation.receive(LCPPacket(code: 2, identifier: 7, data: Array(own.data.dropFirst(4))))
        _ = try negotiation.receive(LCPPacket(code: 2, identifier: 7, data: Array(own.data.suffix(6)) + Array(own.data.prefix(4))))
        XCTAssertFalse(negotiation.localAcknowledged)
        _ = try negotiation.receive(LCPPacket(code: 2, identifier: 7, data: own.data))
        XCTAssertTrue(negotiation.localAcknowledged)
    }

    func testUnknownPeerOptionsAreRejectedBeforeNegotiableValues() throws {
        let negotiation = LCPConfiguration(policy: .requireMSCHAPv2)
        _ = try negotiation.start(identifier: 1, magic: 1)
        let peer = LCPPacket(code: 1, identifier: 21, data: pap + [13, 3, 6, 99, 4, 1, 2])
        XCTAssertEqual(try negotiation.receive(peer), [LCPPacket(code: 4, identifier: 21, data: [13, 3, 6, 99, 4, 1, 2])])
        XCTAssertFalse(negotiation.peerAcknowledged)
    }

    func testRejectRemovesOnlyAnExactOrderedSubset() throws {
        let negotiation = LCPConfiguration(policy: .requireMSCHAPv2)
        let own = try negotiation.start(identifier: 255, magic: 0x11223344)
        let changedMagic = LCPPacket(code: 4, identifier: 255, data: [5, 6, 0, 0, 0, 1])
        XCTAssertTrue(try negotiation.receive(changedMagic).isEmpty)
        XCTAssertTrue(try negotiation.receive(LCPPacket(code: 4, identifier: 255, data: [])).isEmpty)
        let reversed = Array(own.data.suffix(6)) + Array(own.data.prefix(4))
        XCTAssertTrue(try negotiation.receive(LCPPacket(code: 4, identifier: 255, data: reversed)).isEmpty)
        let revised = try XCTUnwrap(negotiation.receive(LCPPacket(code: 4, identifier: 255, data: Array(own.data.prefix(4)))).first)
        XCTAssertEqual(revised.identifier, 0)
        XCTAssertEqual(revised.data, [5, 6, 0x11, 0x22, 0x33, 0x44])
        _ = try negotiation.receive(LCPPacket(code: 2, identifier: 0, data: revised.data))
        XCTAssertEqual(negotiation.localMRU, 1500)
    }

    func testMalformedOptionsDuplicatesAndMutualAuthenticationAreNotEchoed() throws {
        let negotiation = LCPConfiguration(policy: .requireMSCHAPv2)
        _ = try negotiation.start(identifier: 1, magic: 1)
        for bytes: [UInt8] in [[1], [1, 0], [1, 5, 0], pap + pap, [3, 4, 0xc2, 0x23]] {
            XCTAssertThrowsError(try negotiation.receive(LCPPacket(code: 1, identifier: 3, data: bytes)))
        }
        XCTAssertThrowsError(try negotiation.receive(LCPPacket(code: 3, identifier: 1, data: pap)))
        XCTAssertFalse(negotiation.readyForAuthentication)
    }

    func testNakDoesNotImportUnknownOptionsOrInvalidBooleanSuggestions() throws {
        let negotiation = LCPConfiguration(policy: .requireMSCHAPv2)
        let own = try negotiation.start(identifier: 1, magic: 1)
        XCTAssertTrue(try negotiation.receive(LCPPacket(code: 3, identifier: 1, data: [7, 2])).isEmpty)
        let revised = try XCTUnwrap(negotiation.receive(LCPPacket(code: 3, identifier: 1, data: [99, 4, 1, 2])).first)
        XCTAssertEqual(revised.data, own.data)
        XCTAssertThrowsError(try negotiation.receive(LCPPacket(code: 3, identifier: 2, data: [1, 4, 0, 1])))
    }

    func testMagicCollisionAndNakChooseDistinctMagic() throws {
        let negotiation = LCPConfiguration(policy: .requireMSCHAPv2, newMagic: { 2 })
        _ = try negotiation.start(identifier: 1, magic: 1)
        let peer = LCPPacket(code: 1, identifier: 55, data: mschap + [5, 6, 0, 0, 0, 1])
        XCTAssertEqual(try negotiation.receive(peer), [LCPPacket(code: 3, identifier: 55, data: [5, 6, 0, 0, 0, 2])])
        let revised = try XCTUnwrap(negotiation.receive(LCPPacket(code: 3, identifier: 1, data: [5, 6, 0, 0, 0, 1])).first)
        XCTAssertTrue(revised.data.suffix(6).elementsEqual([5, 6, 0, 0, 0, 2]))
        _ = try negotiation.receive(LCPPacket(code: 2, identifier: revised.identifier, data: revised.data))
        XCTAssertEqual(negotiation.localMagic, 2)
    }

    func testProposalAndPeerExchangeLimits() throws {
        let proposals = LCPConfiguration(policy: .requireMSCHAPv2)
        var current = try proposals.start(identifier: 1, magic: 1)
        for _ in 0..<9 {
            current = try XCTUnwrap(proposals.receive(LCPPacket(code: 3, identifier: current.identifier,
                                                               data: [2, 6, 0, 0, 0, 0])).first)
        }
        XCTAssertThrowsError(try proposals.receive(LCPPacket(code: 3, identifier: current.identifier, data: [2, 6, 0, 0, 0, 0])))
        let peer = LCPConfiguration(policy: .requireMSCHAPv2)
        _ = try peer.start(identifier: 1, magic: 1)
        for _ in 0..<64 { _ = try peer.receive(LCPPacket(code: 1, identifier: 2, data: pap)) }
        XCTAssertThrowsError(try peer.receive(LCPPacket(code: 1, identifier: 2, data: pap)))
    }

    func testConfigurationSummaryDecodesNakWithoutDumpingUnknownData() throws {
        let packet = LCPPacket(code: 3, identifier: 7, data: [1, 4, 5, 0xdc, 2, 6, 0, 0, 0, 0] + pap)
        XCTAssertEqual(try packet.configurationSummary(), "MRU=1500, ACCM=0x00000000, authentication=PAP")
        let unknown = LCPPacket(code: 4, identifier: 7, data: [99, 4, 0xaa, 0xbb])
        XCTAssertEqual(try unknown.configurationSummary(), "option 99 (4 bytes)")
        XCTAssertThrowsError(try LCPOption(type: 99, value: [UInt8](repeating: 0, count: 254)).encoded())
    }
}
