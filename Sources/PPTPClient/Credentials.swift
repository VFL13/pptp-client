import CMacSupport
import Darwin
import Foundation
import PPTPCore
import PPTPRuntime

enum Credentials {
    static func prompt() throws -> SessionCredentials {
        guard isatty(STDIN_FILENO) == 1 else { throw PPTPError("connect requires an interactive terminal") }
        FileHandle.standardOutput.write(Data("VPN login: ".utf8))
        guard let login = readLine(), !login.isEmpty else { throw PPTPError("VPN login is required") }
        var storage = [CChar](repeating: 0, count: 4096)
        defer { storage.withUnsafeMutableBytes { pptp_clear($0.baseAddress, $0.count) } }
        guard pptp_read_password(&storage, storage.count) == 0 else { throw PPTPError("password input cancelled") }
        var bytes = storage.prefix(while: { $0 != 0 }).map { UInt8(bitPattern: $0) }
        defer { bytes.withUnsafeMutableBytes { pptp_clear($0.baseAddress, $0.count) } }
        return try SessionCredentials(username: login, password: Data(bytes))
    }
}
