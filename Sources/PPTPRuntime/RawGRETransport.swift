import Darwin
import Dispatch
import Foundation
import PPTPCore

public final class RawGRETransport: GRETransport {
    public let descriptor: Int32
    private let peerBytes: [UInt8]
    private var deadline: DispatchTime

    public init(ip: String, deadline: DispatchTime) throws {
        var peer = sockaddr_in()
        peer.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        peer.sin_family = sa_family_t(AF_INET)
        guard inet_pton(AF_INET, ip, &peer.sin_addr) == 1 else {
            throw PPTPError("GRE requires a literal IPv4 address")
        }
        peerBytes = withUnsafeBytes(of: peer.sin_addr.s_addr) { Array($0) }
        self.deadline = deadline
        let fd = socket(AF_INET, SOCK_RAW, IPPROTO_GRE)
        guard fd >= 0 else { throw Self.systemError("opening GRE socket (administrator privileges required)") }
        do {
            let flags = fcntl(fd, F_GETFL)
            guard flags >= 0, fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0 else {
                throw Self.systemError("making GRE socket nonblocking")
            }
            let connected = withUnsafePointer(to: &peer) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }
            guard connected == 0 else { throw Self.systemError("connecting GRE socket") }
        } catch {
            close(fd)
            throw error
        }
        descriptor = fd
    }

    deinit { close(descriptor) }

    public func setDeadline(_ value: DispatchTime) { deadline = value }

    public func receiveAvailable() throws -> GREPacket? {
        var bytes = [UInt8](repeating: 0, count: 65535)
        let count = bytes.withUnsafeMutableBytes { recv(descriptor, $0.baseAddress, $0.count, 0) }
        if count < 0 {
            if errno == EAGAIN || errno == EINTR { return nil }
            throw Self.systemError("receiving GRE packet")
        }
        return try GREPacket.decodeIPv4(Array(bytes.prefix(count)), expectedSource: peerBytes)
    }

    public func send(_ packet: GREPacket) throws {
        let bytes = try packet.encoded()
        while true {
            try wait(for: Int16(POLLOUT))
            let count = bytes.withUnsafeBytes { Darwin.send(descriptor, $0.baseAddress, $0.count, 0) }
            if count < 0 {
                if errno == EINTR || errno == EAGAIN { continue }
                throw Self.systemError("sending GRE packet")
            }
            guard count == bytes.count else { throw PPTPError("partial GRE datagram send") }
            return
        }
    }

    public func receive() throws -> GREPacket {
        var bytes = [UInt8](repeating: 0, count: 65535)
        while true {
            try wait(for: Int16(POLLIN))
            let count = bytes.withUnsafeMutableBytes { recv(descriptor, $0.baseAddress, $0.count, 0) }
            if count < 0 {
                if errno == EINTR || errno == EAGAIN { continue }
                throw Self.systemError("receiving GRE packet")
            }
            return try GREPacket.decodeIPv4(Array(bytes.prefix(count)), expectedSource: peerBytes)
        }
    }

    private func wait(for events: Int16) throws {
        while true {
            let now = DispatchTime.now().uptimeNanoseconds
            let end = deadline.uptimeNanoseconds
            guard now < end else { throw PPTPError("GRE probe timed out") }
            let milliseconds = Int32(min((end - now + 999_999) / 1_000_000, UInt64(Int32.max)))
            var item = pollfd(fd: descriptor, events: events, revents: 0)
            let result = poll(&item, 1, milliseconds)
            if result < 0 {
                if errno == EINTR { continue }
                throw Self.systemError("waiting for GRE socket")
            }
            if result == 0 { throw PPTPError("GRE probe timed out") }
            guard item.revents & Int16(POLLERR | POLLHUP | POLLNVAL) == 0 else {
                throw PPTPError("GRE socket reported an error")
            }
            if item.revents & events != 0 { return }
        }
    }

    private static func systemError(_ operation: String) -> PPTPError {
        let code = errno
        return PPTPError("\(operation): errno \(code) (\(String(cString: strerror(code))))")
    }
}
