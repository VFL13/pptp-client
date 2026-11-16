import Darwin
import Foundation
import PPTPAppSupport
import PPTPRuntime

final class Service: NSObject, HelperServiceProtocol, @unchecked Sendable {
    let owner = UUID()
    weak var connection: NSXPCConnection?
    let sessions: SessionController
    init(connection: NSXPCConnection, sessions: SessionController) { self.connection = connection; self.sessions = sessions }
    func hello(reply: @escaping @Sendable (Int, Data) -> Void) { reply(AppIdentity.protocolVersion, SessionCoding.encode(sessions.snapshot)) }
    func status(reply: @escaping @Sendable (Data) -> Void) { reply(SessionCoding.encode(sessions.snapshot)) }
    func start(configuration: Data, username: String, password: Data, reply: @escaping @Sendable (Bool, String) -> Void) {
        do {
            try sessions.start(owner: owner, configuration: configuration, username: username, password: password) { [weak self] event in
                guard let self, let connection = self.connection else { return }
                let remote = connection.remoteObjectProxyWithErrorHandler { [weak self] _ in self?.lostConnection() } as? HelperClientProtocol
                remote?.receiveUpdate(SessionCoding.encode(event))
            }
            reply(true, "")
        } catch { reply(false, String(describing: error)) }
    }
    func stop(reply: @escaping @Sendable (Bool) -> Void) {
        if !sessions.stop(owner: owner, completion: { reply(true) }) { reply(false) }
    }
    func lostConnection() { sessions.stop(owner: owner) }
    func uninstall(reply: @escaping @Sendable (Bool, String) -> Void) {
        guard sessions.beginUninstall() else { reply(false, "Сначала отключите VPN"); return }
        do {
            for path in [AppIdentity.daemonPath, AppIdentity.trustPath, AppIdentity.helperPath] {
                if FileManager.default.fileExists(atPath: path) { try FileManager.default.removeItem(atPath: path) }
            }
            reply(true, "")
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) {
                let process = Process()
                process.executableURL = URL(fileURLWithPath: "/bin/launchctl")
                process.arguments = ["bootout", "system/" + AppIdentity.helper]
                do { try process.run() } catch { exit(0) }
            }
        } catch { reply(false, "Не удалось удалить служебный компонент; переустановите пакет и повторите") }
    }
}

final class ListenerDelegate: NSObject, NSXPCListenerDelegate, @unchecked Sendable {
    let sessions = SessionController()
    let trust: HelperTrust
    private let lock = NSLock()
    private var connections: [UUID: NSXPCConnection] = [:]
    init(trust: HelperTrust) { self.trust = trust }
    var hasConnections: Bool { lock.lock(); defer { lock.unlock() }; return !connections.isEmpty }
    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        guard trust.allows(uid: connection.effectiveUserIdentifier) else { return false }
        let service = Service(connection: connection, sessions: sessions)
        connection.exportedInterface = NSXPCInterface(with: HelperServiceProtocol.self)
        connection.exportedObject = service
        connection.remoteObjectInterface = NSXPCInterface(with: HelperClientProtocol.self)
        let owner = service.owner
        let sessions = self.sessions
        connection.invalidationHandler = { [weak self] in
            sessions.stop(owner: owner)
            guard let self else { return }
            self.lock.lock(); self.connections.removeValue(forKey: owner); self.lock.unlock()
        }
        connection.interruptionHandler = { sessions.stop(owner: owner) }
        lock.lock(); connections[service.owner] = connection; lock.unlock()
        connection.resume()
        return true
    }
}

do {
    guard geteuid() == 0 else { throw NSError(domain: "PPTPHelper", code: 1) }
    for path in ["/Library", "/Library/Application Support", "/Library/Application Support/PPTPClient", AppIdentity.trustPath] {
        let attributes = try FileManager.default.attributesOfItem(atPath: path)
        let expectedType: FileAttributeType = path == AppIdentity.trustPath ? .typeRegular : .typeDirectory
        guard (attributes[.ownerAccountID] as? NSNumber)?.uint32Value == 0,
              let permissions = attributes[.posixPermissions] as? NSNumber, permissions.intValue & 0o022 == 0,
              attributes[.type] as? FileAttributeType == expectedType else { throw NSError(domain: "PPTPHelper", code: 2) }
    }
    let trust = try PropertyListDecoder().decode(HelperTrust.self, from: Data(contentsOf: URL(fileURLWithPath: AppIdentity.trustPath)))
    guard trust.ownerUID > 0, trust.protocolVersion == AppIdentity.protocolVersion,
          !trust.clientRequirement.isEmpty else { throw NSError(domain: "PPTPHelper", code: 3) }
    let delegate = ListenerDelegate(trust: trust)
    let listener = NSXPCListener(machServiceName: AppIdentity.helper)
    listener.setConnectionCodeSigningRequirement(trust.clientRequirement)
    listener.delegate = delegate
    signal(SIGTERM, SIG_IGN)
    let termination = DispatchSource.makeSignalSource(signal: SIGTERM, queue: .main)
    termination.setEventHandler {
        delegate.sessions.stopAll()
        DispatchQueue.global().async {
            let end = ProcessInfo.processInfo.systemUptime + 20
            while !delegate.sessions.isIdle, ProcessInfo.processInfo.systemUptime < end { usleep(100_000) }
            exit(0)
        }
    }
    termination.resume()
    let idle = DispatchSource.makeTimerSource(queue: .main)
    idle.schedule(deadline: .now() + 30, repeating: 10)
    idle.setEventHandler { if !delegate.hasConnections, delegate.sessions.isIdle { exit(0) } }
    idle.resume()
    listener.resume()
    dispatchMain()
} catch {
    FileHandle.standardError.write(Data("PPTP helper requires a valid installed trust policy and root launchd context.\n".utf8))
    exit(1)
}
