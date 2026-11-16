import Foundation
import PPTPRuntime

public protocol HelperCommunicating: Sendable {
    func open(requirement: String, completion: @escaping @Sendable (Bool) -> Void)
    func start(configuration: Data, username: String, password: Data, completion: @escaping @Sendable (Bool, String) -> Void)
    func stop(completion: @escaping @Sendable (Bool) -> Void)
    func uninstall(completion: @escaping @Sendable (Bool, String) -> Void)
    func invalidate()
}

public final class HelperConnection: NSObject, HelperClientProtocol, HelperCommunicating, @unchecked Sendable {
    private let lock = NSLock()
    private var connection: NSXPCConnection?
    private var pollTimer: DispatchSourceTimer?
    private let event: @Sendable (SessionUpdate) -> Void
    private let unavailable: @Sendable () -> Void
    public init(event: @escaping @Sendable (SessionUpdate) -> Void, unavailable: @escaping @Sendable () -> Void) {
        self.event = event; self.unavailable = unavailable
    }
    public func open(requirement: String, completion: @escaping @Sendable (Bool) -> Void) {
        guard !requirement.isEmpty else { completion(false); return }
        let connection = NSXPCConnection(machServiceName: AppIdentity.helper, options: .privileged)
        connection.setCodeSigningRequirement(requirement)
        connection.remoteObjectInterface = NSXPCInterface(with: HelperServiceProtocol.self)
        connection.exportedInterface = NSXPCInterface(with: HelperClientProtocol.self)
        connection.exportedObject = self
        connection.invalidationHandler = { [weak self] in self?.becameUnavailable() }
        connection.interruptionHandler = { [weak self] in self?.becameUnavailable() }
        lock.lock(); self.connection = connection; lock.unlock()
        connection.resume()
        let remote = connection.remoteObjectProxyWithErrorHandler { _ in completion(false) } as? HelperServiceProtocol
        remote?.hello { [weak self] version, snapshot in
            guard version == AppIdentity.protocolVersion else { completion(false); return }
            self?.receiveUpdate(snapshot)
            self?.startPolling()
            completion(true)
        }
    }
    public func start(configuration: Data, username: String, password: Data, completion: @escaping @Sendable (Bool, String) -> Void) {
        guard let remote = proxy(error: { completion(false, "Служебный компонент недоступен") }) else {
            completion(false, "Служебный компонент не установлен"); return
        }
        remote.start(configuration: configuration, username: username, password: password, reply: completion)
    }
    public func stop(completion: @escaping @Sendable (Bool) -> Void) {
        guard let remote = proxy(error: { completion(false) }) else { completion(false); return }
        remote.stop(reply: completion)
    }
    public func uninstall(completion: @escaping @Sendable (Bool, String) -> Void) {
        guard let remote = proxy(error: { completion(false, "Служебный компонент недоступен") }) else { completion(false, ""); return }
        remote.uninstall(reply: completion)
    }
    public func receiveUpdate(_ data: Data) {
        do { event(try SessionCoding.decode(data)) }
        catch { event(SessionUpdate(.failed, "Некорректный ответ служебного компонента")) }
    }
    public func invalidate() {
        lock.lock(); let old = connection; connection = nil; pollTimer?.cancel(); pollTimer = nil; lock.unlock()
        old?.invalidate()
    }
    private func startPolling() {
        let timer = DispatchSource.makeTimerSource(queue: DispatchQueue.global(qos: .utility))
        timer.schedule(deadline: .now() + 1, repeating: 1)
        timer.setEventHandler { [weak self] in
            guard let self, let remote = self.proxy(error: { [weak self] in self?.becameUnavailable() }) else { return }
            remote.status { [weak self] data in self?.receiveUpdate(data) }
        }
        lock.lock(); pollTimer?.cancel(); pollTimer = timer; lock.unlock()
        timer.resume()
    }
    private func becameUnavailable() {
        lock.lock(); pollTimer?.cancel(); pollTimer = nil; lock.unlock()
        unavailable()
    }
    private func proxy(error: @escaping @Sendable () -> Void) -> HelperServiceProtocol? {
        lock.lock(); let connection = connection; lock.unlock()
        return connection?.remoteObjectProxyWithErrorHandler { _ in error() } as? HelperServiceProtocol
    }
    deinit { pollTimer?.cancel(); connection?.invalidate() }
}
