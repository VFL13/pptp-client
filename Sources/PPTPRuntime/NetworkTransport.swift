import Dispatch
import Foundation
import Network
import PPTPCore

// Network.framework callbacks run on a dedicated queue; access to their result
// is synchronized explicitly, including callbacks arriving after cancellation.
private final class CallbackResult<Value>: @unchecked Sendable {
    private let lock = NSLock()
    private var value: Result<Value, Error>?
    let ready = DispatchSemaphore(value: 0)

    public func complete(_ result: Result<Value, Error>) {
        lock.lock()
        guard value == nil else { lock.unlock(); return }
        value = result
        lock.unlock()
        ready.signal()
    }

    public func wait(until deadline: DispatchTime, cancelled: () -> Bool = { false }) throws -> Value {
        while ready.wait(timeout: min(deadline, .now() + 0.1)) != .success {
            if cancelled() { throw SessionRunError.cancelled }
            if DispatchTime.now() >= deadline { throw PPTPError("PPTP operation timed out") }
        }
        lock.lock()
        defer { lock.unlock() }
        guard let value else { throw PPTPError("missing network result") }
        return try value.get()
    }
}

// Mutable operation deadlines belong to the caller thread. Network callbacks
// touch only the synchronized byte buffer and Network.framework connection.
public final class NetworkTransport: ControlTransport, @unchecked Sendable {
    private let connection: NWConnection
    private var deadline: DispatchTime
    private let cancelled: @Sendable () -> Bool
    private let input = NetworkInput()

    public convenience init(host: String, port: UInt16, timeout: Double) throws {
        try self.init(host: host, port: port, deadline: .now() + timeout)
    }

    public init(host: String, port: UInt16, deadline: DispatchTime, cancelled: @escaping @Sendable () -> Bool = { false }) throws {
        guard let endpointPort = NWEndpoint.Port(rawValue: port) else {
            throw PPTPError("invalid TCP port")
        }
        self.deadline = deadline
        self.cancelled = cancelled
        // DNS resolution, TCP connection, writes and reads share one deadline.
        connection = NWConnection(host: NWEndpoint.Host(host), port: endpointPort, using: .tcp)
        let result = CallbackResult<Void>()
        let input = self.input
        connection.stateUpdateHandler = { state in
            switch state {
            case .ready: result.complete(.success(()))
            case .failed(let error):
                input.fail(error)
                result.complete(.failure(error))
            case .cancelled: result.complete(.failure(PPTPError("connection cancelled")))
            default: break
            }
        }
        connection.start(queue: DispatchQueue(label: "pptp.control.transport"))
        do {
            try result.wait(until: deadline, cancelled: cancelled)
            receiveMore()
        } catch {
            connection.cancel()
            throw error
        }
    }

    deinit { connection.cancel() }

    public func setDeadline(_ value: DispatchTime) { deadline = value }

    public func write(_ bytes: [UInt8]) throws {
        let result = CallbackResult<Void>()
        connection.send(content: Data(bytes), completion: .contentProcessed { error in
            if let error { result.complete(.failure(error)) }
            else { result.complete(.success(())) }
        })
        try result.wait(until: deadline, cancelled: cancelled)
    }

    public func readExactly(_ count: Int) throws -> [UInt8] {
        try input.read(count, deadline: deadline, cancelled: cancelled)
    }

    public func readAvailableMessage() throws -> ControlMessage? { try input.message() }

    private func receiveMore() {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 4096) { [weak self] data, _, complete, error in
            guard let self else { return }
            if let data, !data.isEmpty {
                if !self.input.append(data) { self.connection.cancel(); return }
            }
            if let error { self.input.fail(error); return }
            if complete { self.input.fail(PPTPError("server closed TCP connection")); return }
            self.receiveMore()
        }
    }
}

private final class NetworkInput: @unchecked Sendable {
    private let condition = NSCondition()
    private var bytes: [UInt8] = []
    private var error: Error?

    public func append(_ data: Data) -> Bool {
        condition.lock()
        defer { condition.broadcast(); condition.unlock() }
        guard bytes.count + data.count <= 65536 else {
            error = PPTPError("PPTP control receive buffer limit exceeded")
            return false
        }
        bytes += data
        return true
    }
    public func fail(_ value: Error) {
        condition.lock()
        error = value
        condition.broadcast()
        condition.unlock()
    }
    public func read(_ count: Int, deadline: DispatchTime, cancelled: () -> Bool) throws -> [UInt8] {
        condition.lock()
        defer { condition.unlock() }
        while bytes.count < count {
            if cancelled() { throw SessionRunError.cancelled }
            if let error { throw error }
            let now = DispatchTime.now().uptimeNanoseconds
            guard now < deadline.uptimeNanoseconds else { throw PPTPError("PPTP operation timed out") }
            let remaining = Double(deadline.uptimeNanoseconds - now) / 1e9
            _ = condition.wait(until: Date(timeIntervalSinceNow: min(1, remaining)))
        }
        let result = Array(bytes.prefix(count))
        bytes.removeFirst(count)
        return result
    }
    public func message() throws -> ControlMessage? {
        condition.lock()
        defer { condition.unlock() }
        guard bytes.count >= 12 else {
            if let error { throw error }
            return nil
        }
        let length = try ControlMessage.frameLength(header: Array(bytes.prefix(12)))
        guard bytes.count >= length else {
            if let error { throw error }
            return nil
        }
        let frame = Array(bytes.prefix(length))
        bytes.removeFirst(length)
        return try ControlMessage.decode(frame)
    }
}
