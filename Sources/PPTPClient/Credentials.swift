import CMacSupport
import Darwin
import Foundation
import PPTPCore

final class Credentials {
    private var username: [UInt8]
    private var password: [UInt8]

    private init(username: [UInt8], password: [UInt8]) {
        self.username = username
        self.password = password
    }
    deinit { erase() }

    static func prompt() throws -> Credentials {
        guard isatty(STDIN_FILENO) == 1 else { throw PPTPError("connect requires an interactive terminal; credentials via pipes or arguments are not supported") }
        FileHandle.standardOutput.write(Data("VPN login: ".utf8))
        guard let login = readLine(), !login.isEmpty, login.utf8.count <= 255 else { throw PPTPError("invalid VPN login length") }
        var storage = [CChar](repeating: 0, count: 4096)
        defer { storage.withUnsafeMutableBytes { pptp_clear($0.baseAddress, $0.count) } }
        guard pptp_read_password(&storage, storage.count) == 0 else { throw PPTPError("password input cancelled or unavailable") }
        let bytes = storage.prefix(while: { $0 != 0 }).map { UInt8(bitPattern: $0) }
        guard !bytes.isEmpty, bytes.count <= 255 else { throw PPTPError("PAP password must contain between 1 and 255 UTF-8 bytes") }
        return Credentials(username: Array(login.utf8), password: bytes)
    }

    func authenticate(_ client: PPPClient, now: TimeInterval) throws -> [PPPAction] {
        defer { erase() }
        return try client.authenticate(username: username, password: password, now: now)
    }

    private func erase() {
        username.withUnsafeMutableBytes { pptp_clear($0.baseAddress, $0.count) }
        password.withUnsafeMutableBytes { pptp_clear($0.baseAddress, $0.count) }
        username.removeAll()
        password.removeAll()
    }
}
