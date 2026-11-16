import Dispatch
import Foundation
import PPTPCore
import PPTPRuntime

public final class SessionController: @unchecked Sendable {
    public typealias Worker = @Sendable (ClientConfiguration, SessionCredentials, CancellationToken,
                                        @escaping @Sendable (SessionUpdate) -> Void) throws -> Void
    private struct Active {
        let id: UUID
        let owner: UUID
        let token: CancellationToken
        var waiters: [@Sendable () -> Void] = []
    }
    private let lock = NSLock()
    private let queue = DispatchQueue(label: "local.pptpclient.session")
    private let worker: Worker
    private var active: Active?
    private var accepting = true
    private var current = SessionUpdate(.disconnected, "Отключено")
    public init(worker: @escaping Worker = { profile, credentials, token, events in
        try VPNRunner.run(profile: profile, credentials: credentials, cancelled: { token.isCancelled }, update: events)
    }) { self.worker = worker }

    public var snapshot: SessionUpdate { lock.lock(); defer { lock.unlock() }; return current }
    public var isIdle: Bool { lock.lock(); defer { lock.unlock() }; return active == nil }

    public func start(owner: UUID, configuration: Data, username: String, password: Data,
                      events: @escaping @Sendable (SessionUpdate) -> Void) throws {
        guard configuration.count <= 65536 else { throw PPTPError("configuration is too large") }
        let profile = try ClientConfiguration.load(configuration)
        let credentials = try SessionCredentials(username: username, password: password)
        lock.lock()
        guard active == nil, accepting else { lock.unlock(); credentials.erase(); throw PPTPError("VPN is already running or helper is stopping") }
        let job = Active(id: UUID(), owner: owner, token: CancellationToken())
        active = job
        current = SessionUpdate(.connecting, "Подключение")
        lock.unlock()
        queue.async { [self] in
            var failure: String?
            do {
                try worker(profile, credentials, job.token) { [weak self] event in
                    guard event.phase != .disconnected else { return } // Publish terminal state only after cleanup.
                    self?.publish(event, id: job.id, events: events)
                }
            } catch SessionRunError.cancelled {
                failure = nil
            } catch {
                if !job.token.isCancelled { failure = String(describing: error) }
            }
            credentials.erase()
            lock.lock()
            guard active?.id == job.id else { lock.unlock(); return }
            let waiters = active?.waiters ?? []
            active = nil
            let final = failure.map { SessionUpdate(.failed, $0) } ?? SessionUpdate(.disconnected, "Отключено")
            current = final
            lock.unlock()
            events(final)
            waiters.forEach { $0() }
        }
    }

    @discardableResult public func stop(owner: UUID, completion: @escaping @Sendable () -> Void = {}) -> Bool {
        lock.lock()
        guard let job = active else { lock.unlock(); completion(); return true }
        guard job.owner == owner else { lock.unlock(); return false }
        active?.waiters.append(completion)
        current = SessionUpdate(.stopping, "Отключение")
        job.token.cancel()
        lock.unlock()
        return true
    }
    public func stopAll() {
        lock.lock(); accepting = false; active?.token.cancel(); lock.unlock()
    }
    public func beginUninstall() -> Bool {
        lock.lock(); defer { lock.unlock() }
        guard active == nil else { return false }
        accepting = false
        return true
    }
    private func publish(_ event: SessionUpdate, id: UUID, events: @Sendable (SessionUpdate) -> Void) {
        lock.lock()
        guard active?.id == id else { lock.unlock(); return }
        if active?.token.isCancelled == true, event.phase != .stopping { lock.unlock(); return }
        current = event
        lock.unlock()
        events(event)
    }
}
