import CMacSupport
import Foundation
import PPTPCore

public enum SessionPhase: String, Codable, Sendable {
    case disconnected, connecting, lcp, authenticating, ipcp, configuring, connected, stopping, failed
    public var isActive: Bool { ![.disconnected, .failed].contains(self) }
}

public struct SessionUpdate: Codable, Equatable, Sendable {
    public var phase: SessionPhase
    public var message: String
    public var interface: String?
    public var address: String?
    public var authenticated: Bool
    public init(_ phase: SessionPhase, _ message: String = "", interface: String? = nil, address: String? = nil, authenticated: Bool = false) {
        self.phase = phase; self.message = message; self.interface = interface
        self.address = address; self.authenticated = authenticated
    }
}

public final class CancellationToken: @unchecked Sendable {
    private let lock = NSLock()
    private var cancelled = false
    public init() {}
    public var isCancelled: Bool { lock.lock(); defer { lock.unlock() }; return cancelled }
    public func cancel() { lock.lock(); cancelled = true; lock.unlock() }
}

public final class SessionCredentials: @unchecked Sendable {
    private let lock = NSLock()
    private var username: [UInt8]
    private var password: [UInt8]
    public init(username: String, password: Data) throws {
        guard !username.isEmpty, username.utf8.count <= 255, !password.isEmpty, password.count <= 255 else {
            throw PPTPError("invalid PAP credential length")
        }
        self.username = Array(username.utf8); self.password = Array(password)
    }
    public func authenticate(_ client: PPPClient, now: TimeInterval) throws -> [PPPAction] {
        lock.lock(); defer { eraseLocked(); lock.unlock() }
        return try client.authenticate(username: username, password: password, now: now)
    }
    public func erase() { lock.lock(); eraseLocked(); lock.unlock() }
    private func eraseLocked() {
        username.withUnsafeMutableBytes { pptp_clear($0.baseAddress, $0.count) }
        password.withUnsafeMutableBytes { pptp_clear($0.baseAddress, $0.count) }
        username.removeAll(); password.removeAll()
    }
    deinit { erase() }
}
