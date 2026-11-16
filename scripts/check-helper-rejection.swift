// Compile and run as a regular user after installing PPTPClient.
// This deliberately untrusted executable must not receive a helper reply.
import Darwin
import Foundation

@objc protocol ProbeService {
    func hello(reply: @escaping @Sendable (Int, Data) -> Void)
}

final class ProbeResult: @unchecked Sendable {
    private let lock = NSLock()
    private var receivedReply = false
    let completed = DispatchSemaphore(value: 0)
    func accepted() { lock.lock(); receivedReply = true; lock.unlock(); completed.signal() }
    func rejected() { completed.signal() }
    var wasAccepted: Bool { lock.lock(); defer { lock.unlock() }; return receivedReply }
}

guard geteuid() != 0 else { fatalError("Run this check as a regular user") }
let connection = NSXPCConnection(machServiceName: "local.pptpclient.helper", options: .privileged)
let result = ProbeResult()
connection.remoteObjectInterface = NSXPCInterface(with: ProbeService.self)
connection.invalidationHandler = { result.rejected() }
connection.resume()
let proxy = connection.remoteObjectProxyWithErrorHandler { _ in result.rejected() } as? ProbeService
proxy?.hello { _, _ in result.accepted() }
let finished = result.completed.wait(timeout: .now() + 5) == .success
connection.invalidate()
guard finished else { print("INCONCLUSIVE: no XPC response"); exit(2) }
guard !result.wasAccepted else { print("FAIL: untrusted client received a helper reply"); exit(1) }
print("Untrusted XPC client rejected. Run only while the installed app can reach its helper.")
