import Foundation
import PPTPRuntime

public enum AppIdentity {
    public static let app = "local.pptpclient"
    public static let helper = "local.pptpclient.helper"
    public static let protocolVersion = 2
    public static let helperPath = "/Library/PrivilegedHelperTools/local.pptpclient.helper"
    public static let daemonPath = "/Library/LaunchDaemons/local.pptpclient.helper.plist"
    public static let trustPath = "/Library/Application Support/PPTPClient/trust.plist"
}

@objc public protocol HelperClientProtocol {
    func receiveUpdate(_ data: Data)
}

@objc public protocol HelperServiceProtocol {
    func hello(reply: @escaping @Sendable (Int, Data) -> Void)
    func start(configuration: Data, username: String, password: Data, reply: @escaping @Sendable (Bool, String) -> Void)
    func stop(reply: @escaping @Sendable (Bool) -> Void)
    func status(reply: @escaping @Sendable (Data) -> Void)
    func uninstall(reply: @escaping @Sendable (Bool, String) -> Void)
}

public struct HelperTrust: Codable, Sendable {
    public var ownerUID: UInt32
    public var clientRequirement: String
    public var helperRequirement: String
    public var protocolVersion: Int
    public init(ownerUID: UInt32, clientRequirement: String, helperRequirement: String, protocolVersion: Int = 2) {
        self.ownerUID = ownerUID; self.clientRequirement = clientRequirement
        self.helperRequirement = helperRequirement; self.protocolVersion = protocolVersion
    }
    public func allows(uid: UInt32) -> Bool { ownerUID > 0 && uid == ownerUID && protocolVersion == AppIdentity.protocolVersion }
}

public enum SessionCoding {
    public static func encode(_ update: SessionUpdate) -> Data { (try? JSONEncoder().encode(update)) ?? Data() }
    public static func decode(_ data: Data) throws -> SessionUpdate {
        guard data.count <= 65536 else { throw CocoaError(.coderReadCorrupt) }
        return try JSONDecoder().decode(SessionUpdate.self, from: data)
    }
}
