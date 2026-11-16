import Foundation
import XCTest
import PPTPCore
import PPTPRuntime
@testable import PPTPAppSupport

final class ModelTests: XCTestCase, @unchecked Sendable {
    @MainActor private func makeModel() -> (AppModel, FakeBridge, FakePasswords, URL) {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let bridge = FakeBridge()
        let passwords = FakePasswords()
        let model = AppModel(store: ProfileStore(directory: directory), passwords: passwords, factory: { events, unavailable in
            bridge.setCallbacks(events: events, unavailable: unavailable); return bridge
        })
        model.profile.configuration = ClientConfiguration(server: "203.0.113.10", routes: ["192.0.2.0/24"])
        model.profile.username = UUID().uuidString
        return (model, bridge, passwords, directory)
    }
    @MainActor private func ready(_ model: AppModel) async {
        model.prepareHelper(requirement: "test-requirement")
        for _ in 0..<100 where !model.helperAvailable { await Task.yield() }
        XCTAssertTrue(model.helperAvailable)
    }

    @MainActor func testKeychainOnlySavesAfterServerAcceptsAuthentication() async throws {
        let (model, bridge, passwords, directory) = makeModel()
        defer { try? FileManager.default.removeItem(at: directory) }
        await ready(model)
        let secret = UUID().uuidString
        model.password = secret
        model.connect()
        XCTAssertEqual(bridge.startCount, 1)
        XCTAssertEqual(passwords.saveCount, 0)
        XCTAssertEqual(model.password, "")
        XCTAssertFalse(model.canEdit)
        model.receive(SessionUpdate(.ipcp, "", authenticated: true))
        XCTAssertEqual(passwords.saveCount, 1)
        XCTAssertEqual(try passwords.read(account: model.profile.id.uuidString), Data(secret.utf8))
        XCTAssertFalse(model.log.joined().contains(secret))
        model.receive(SessionUpdate(.connected, "ready", authenticated: true))
        XCTAssertEqual(passwords.saveCount, 1)
        model.disconnect()
        for _ in 0..<20 { await Task.yield() }
        XCTAssertTrue(model.canEdit)
        model.connect() // Uses the stored password, without console input.
        XCTAssertEqual(bridge.startCount, 2)
    }

    @MainActor func testFailureDoesNotSavePasswordOrRetry() async {
        let (model, bridge, passwords, directory) = makeModel()
        defer { try? FileManager.default.removeItem(at: directory) }
        await ready(model)
        model.password = UUID().uuidString
        model.connect()
        model.receive(SessionUpdate(.failed, "authentication rejected"))
        for _ in 0..<20 { await Task.yield() }
        XCTAssertEqual(bridge.startCount, 1)
        XCTAssertEqual(passwords.saveCount, 0)
        XCTAssertTrue(model.canEdit)
    }

    @MainActor func testCancellationAndLateUpdatesCannotReturnToConnected() async {
        let (model, _, passwords, directory) = makeModel()
        defer { try? FileManager.default.removeItem(at: directory) }
        await ready(model)
        model.password = UUID().uuidString
        model.connect()
        model.disconnect()
        model.receive(SessionUpdate(.connected, "late", authenticated: true))
        XCTAssertEqual(model.snapshot.phase, .stopping)
        XCTAssertEqual(passwords.saveCount, 0)
        for _ in 0..<20 { await Task.yield() }
        XCTAssertEqual(model.snapshot.phase, .disconnected)
    }

    @MainActor func testStaleConnectionCallbacksDoNotDisableNewConnection() async {
        let (model, bridge, _, directory) = makeModel()
        defer { try? FileManager.default.removeItem(at: directory) }
        await ready(model)
        let old = bridge.callbacks()
        await ready(model)
        old.0?(SessionUpdate(.failed, "old connection")); old.1?()
        for _ in 0..<20 { await Task.yield() }
        XCTAssertTrue(model.helperAvailable)
        XCTAssertEqual(model.snapshot.phase, .disconnected)
    }

    @MainActor func testMalformedImportPreservesExistingProfile() {
        let (model, _, _, directory) = makeModel()
        defer { try? FileManager.default.removeItem(at: directory) }
        let before = model.profile
        model.importConfiguration(Data("{}".utf8))
        XCTAssertEqual(model.profile, before)
        XCTAssertNotNil(model.errorMessage)
    }

    func testCancelledRunnerNeverStartsNetworkOrRequiresRoot() {
        let token = CancellationToken(); token.cancel()
        let credentials = try! SessionCredentials(username: UUID().uuidString, password: Data(UUID().uuidString.utf8))
        XCTAssertThrowsError(try VPNRunner.run(profile: ClientConfiguration(server: "203.0.113.10", routes: ["192.0.2.0/24"]),
                                               credentials: credentials, cancelled: { token.isCancelled }, update: { _ in XCTFail("no I/O after preflight cancellation") })) { error in
            XCTAssertTrue(error is SessionRunError)
        }
    }

    func testRealKeychainRoundTripUsesOnlyNewTemporaryItem() throws {
        let service = "local.pptpclient.tests." + UUID().uuidString
        let store = KeychainPasswordStore(service: service)
        let account = UUID().uuidString
        let secret = Data(UUID().uuidString.utf8)
        do { try store.save(secret, account: account) }
        catch let error as PasswordStoreError where error.code == -25308 || error.code == -25293 {
            throw XCTSkip("Test keychain is locked or interaction is disabled")
        }
        defer { try? store.remove(account: account) }
        XCTAssertEqual(try store.read(account: account), secret)
        try store.remove(account: account)
        XCTAssertNil(try store.read(account: account))
    }
}

private final class FakePasswords: PasswordStoring, @unchecked Sendable {
    private let lock = NSLock()
    private var items: [String: Data] = [:]
    private var writes = 0
    var saveCount: Int { lock.lock(); defer { lock.unlock() }; return writes }
    func read(account: String) throws -> Data? { lock.lock(); defer { lock.unlock() }; return items[account] }
    func save(_ password: Data, account: String) throws { lock.lock(); items[account] = password; writes += 1; lock.unlock() }
    func remove(account: String) throws { lock.lock(); items.removeValue(forKey: account); lock.unlock() }
}

private final class FakeBridge: HelperCommunicating, @unchecked Sendable {
    private let lock = NSLock()
    private var events: (@Sendable (SessionUpdate) -> Void)?
    private var unavailable: (@Sendable () -> Void)?
    private var starts = 0
    var startCount: Int { lock.lock(); defer { lock.unlock() }; return starts }
    func setCallbacks(events: @escaping @Sendable (SessionUpdate) -> Void, unavailable: @escaping @Sendable () -> Void) {
        lock.lock(); self.events = events; self.unavailable = unavailable; lock.unlock()
    }
    func callbacks() -> ((@Sendable (SessionUpdate) -> Void)?, (@Sendable () -> Void)?) {
        lock.lock(); defer { lock.unlock() }; return (events, unavailable)
    }
    func open(requirement: String, completion: @escaping @Sendable (Bool) -> Void) { completion(true) }
    func start(configuration: Data, username: String, password: Data, completion: @escaping @Sendable (Bool, String) -> Void) {
        lock.lock(); starts += 1; lock.unlock(); completion(true, "")
    }
    func stop(completion: @escaping @Sendable (Bool) -> Void) { completion(true) }
    func uninstall(completion: @escaping @Sendable (Bool, String) -> Void) { completion(true, "") }
    func invalidate() {}
}
