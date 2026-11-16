import CMacSupport
import Darwin
import Dispatch
import Foundation
import PPTPCore

final class TunnelInterface {
    let descriptor: Int32
    let name: String
    private var closed = false

    init(configuration: PPPNetworkConfiguration, mtu: Int) throws {
        var buffer = [CChar](repeating: 0, count: 64)
        let fd = pptp_open_utun(&buffer, buffer.count)
        guard fd >= 0 else { throw PPTPError("could not create utun interface: errno \(errno)") }
        descriptor = fd
        name = String(decoding: buffer.prefix(while: { $0 != 0 }).map { UInt8(bitPattern: $0) }, as: UTF8.self)
        do {
            guard name.hasPrefix("utun"), name.dropFirst(4).allSatisfy(\.isNumber) else { throw PPTPError("unexpected tunnel interface name") }
            try LocalCommand.run("/sbin/ifconfig", [name, "inet", configuration.localAddress.description,
                configuration.peerAddress.description, "netmask", "255.255.255.255", "mtu", String(mtu), "up"])
        } catch {
            close(fd)
            closed = true
            throw error
        }
    }

    deinit { closeInterface() }
    func closeInterface() {
        if !closed { close(descriptor); closed = true }
    }

    func readIPv4() throws -> [UInt8]? {
        var bytes = [UInt8](repeating: 0, count: 65539)
        let count = bytes.withUnsafeMutableBytes { read(descriptor, $0.baseAddress, $0.count) }
        if count < 0 {
            if errno == EAGAIN || errno == EINTR { return nil }
            throw PPTPError("reading tunnel interface failed")
        }
        guard count >= 4 else { throw PPTPError("truncated utun packet") }
        guard bytes.prefix(4).elementsEqual([0, 0, 0, UInt8(AF_INET)]) else { return nil }
        return Array(bytes[4..<count])
    }

    func writeIPv4(_ packet: [UInt8]) throws {
        let bytes = [UInt8(0), 0, 0, UInt8(AF_INET)] + packet
        let deadline = DispatchTime.now() + 2
        while true {
            let count = bytes.withUnsafeBytes { write(descriptor, $0.baseAddress, $0.count) }
            if count == bytes.count { return }
            guard count < 0, errno == EAGAIN || errno == EINTR else { throw PPTPError("writing tunnel interface failed") }
            guard DispatchTime.now() < deadline else { throw PPTPError("tunnel interface write timed out") }
            var item = pollfd(fd: descriptor, events: Int16(POLLOUT), revents: 0)
            if poll(&item, 1, 50) < 0, errno != EINTR { throw PPTPError("waiting for tunnel interface failed") }
        }
    }
}
