import Foundation
import XCTest
import PPTPCore
import PPTPRuntime
@testable import PPTPAppSupport

final class AppTests: XCTestCase, @unchecked Sendable {
    func testProfileAndExportNeverContainPasswordOrLoginInWireConfig() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = ProfileStore(directory: directory)
        let profile = AppProfile(username: UUID().uuidString,
                                 configuration: ClientConfiguration(server: "203.0.113.10", routes: ["192.0.2.0/24"]))
        try store.save(profile)
        XCTAssertEqual(try store.load(), profile)
        let data = try store.exporting(profile)
        XCTAssertFalse(String(decoding: data, as: UTF8.self).contains(profile.username))
        XCTAssertFalse(String(decoding: data, as: UTF8.self).contains("password"))
        XCTAssertEqual(try ClientConfiguration.load(data), profile.configuration)
        let imported = try store.importing(data, into: AppProfile())
        XCTAssertEqual(imported.configuration, profile.configuration)
        XCTAssertEqual(imported.username, "")
        let attributes = try FileManager.default.attributesOfItem(atPath: directory.appendingPathComponent("profile.json").path)
        XCTAssertEqual((attributes[.posixPermissions] as? NSNumber)?.intValue, 0o600)
    }

    func testTrustPolicyRejectsDifferentUserAndIncompatibleProtocol() {
        let trust = HelperTrust(ownerUID: 501, clientRequirement: "identifier test", helperRequirement: "identifier helper")
        XCTAssertTrue(trust.allows(uid: 501))
        XCTAssertFalse(trust.allows(uid: 0))
        XCTAssertFalse(trust.allows(uid: 502))
        XCTAssertFalse(HelperTrust(ownerUID: 501, clientRequirement: "", helperRequirement: "", protocolVersion: 1).allows(uid: 501))
    }

    func testOneSessionAndOwnerBoundCancellationWaitForCleanup() throws {
        let started = expectation(description: "started")
        let stopped = expectation(description: "cleanup completed")
        let controller = SessionController { _, _, token, events in
            events(SessionUpdate(.connected, "ready", authenticated: true))
            started.fulfill()
            while !token.isCancelled { Thread.sleep(forTimeInterval: 0.005) }
        }
        let owner = UUID()
        let config = try JSONEncoder().encode(ClientConfiguration(server: "203.0.113.10", routes: ["192.0.2.0/24"]))
        try controller.start(owner: owner, configuration: config, username: UUID().uuidString,
                             password: Data(UUID().uuidString.utf8), events: { _ in })
        wait(for: [started], timeout: 2)
        XCTAssertFalse(controller.isIdle)
        XCTAssertThrowsError(try controller.start(owner: UUID(), configuration: config, username: "x", password: Data([1]), events: { _ in }))
        XCTAssertFalse(controller.stop(owner: UUID()))
        XCTAssertTrue(controller.stop(owner: owner, completion: { stopped.fulfill() }))
        wait(for: [stopped], timeout: 2)
        XCTAssertTrue(controller.isIdle)
        XCTAssertEqual(controller.snapshot.phase, .disconnected)
    }

    func testFailedAuthenticationIsTerminalWithoutAutomaticRetry() throws {
        let done = expectation(description: "failure")
        let controller = SessionController { _, _, _, _ in throw PPTPError("authentication rejected") }
        let config = try JSONEncoder().encode(ClientConfiguration(server: "203.0.113.10", routes: ["192.0.2.0/24"]))
        try controller.start(owner: UUID(), configuration: config, username: UUID().uuidString,
                             password: Data(UUID().uuidString.utf8)) { event in
            if event.phase == .failed { done.fulfill() }
        }
        wait(for: [done], timeout: 2)
        XCTAssertEqual(controller.snapshot.phase, .failed)
        XCTAssertTrue(controller.isIdle)
    }
}
