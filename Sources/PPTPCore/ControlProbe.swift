import Foundation

public protocol ControlTransport: AnyObject {
    func write(_ bytes: [UInt8]) throws
    func readExactly(_ count: Int) throws -> [UInt8]
    func readAvailableMessage() throws -> ControlMessage?
}

public extension ControlTransport {
    func readAvailableMessage() throws -> ControlMessage? { nil }
}

public struct ProbeReport: Sendable {
    public let server: ServerInfo
    public let cleanShutdown: Bool
    public let shutdownWarning: String?
}

/// Opens and closes only the control channel. Does not create a PPP call.
public enum ControlProbe {
    public static func run(over transport: any ControlTransport) throws -> ProbeReport {
        let channel = ControlChannel(transport: transport)
        let server = try channel.start()
        do {
            try channel.stop()
            return ProbeReport(server: server, cleanShutdown: true, shutdownWarning: nil)
        } catch {
            // An established control channel and a clean shutdown are distinct results.
            return ProbeReport(server: server, cleanShutdown: false, shutdownWarning: String(describing: error))
        }
    }

}
