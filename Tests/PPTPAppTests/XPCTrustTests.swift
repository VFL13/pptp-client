import Foundation
import XCTest
import PPTPAppSupport

private final class RejectDelegate: NSObject, NSXPCListenerDelegate, @unchecked Sendable {
    let reached: XCTestExpectation
    init(reached: XCTestExpectation) { self.reached = reached }
    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        reached.fulfill()
        return false
    }
}

final class XPCTrustTests: XCTestCase, @unchecked Sendable {
    func testWrongSignatureIsRejectedBeforeServiceDelegate() {
        let reached = expectation(description: "untrusted client never reaches service")
        reached.isInverted = true
        let rejected = expectation(description: "XPC rejects untrusted client")
        rejected.assertForOverFulfill = false
        let delegate = RejectDelegate(reached: reached)
        let listener = NSXPCListener.anonymous()
        listener.setConnectionCodeSigningRequirement("identifier \"local.pptpclient.never-trusted-test\"")
        listener.delegate = delegate
        listener.resume()
        let client = NSXPCConnection(listenerEndpoint: listener.endpoint)
        client.remoteObjectInterface = NSXPCInterface(with: HelperServiceProtocol.self)
        client.invalidationHandler = { rejected.fulfill() }
        client.resume()
        let remote = client.remoteObjectProxyWithErrorHandler { _ in rejected.fulfill() } as? HelperServiceProtocol
        remote?.hello { _, _ in XCTFail("untrusted client received a reply") }
        wait(for: [rejected, reached], timeout: 2)
        client.invalidate()
        listener.invalidate()
        withExtendedLifetime(delegate) {}
    }
}
