import CMacSupport
import Darwin
import Dispatch
import Foundation
import PPTPCore
import PPTPRuntime

func loadProfile(_ args: [String], allowCheck: Bool) throws -> (ClientConfiguration, Bool) {
    var path: String?
    var checkOnly = false
    var index = 0
    while index < args.count {
        switch args[index] {
        case "--config":
            guard path == nil, index + 1 < args.count else { throw PPTPError("provide one --config JSON path") }
            path = args[index + 1]
            index += 2
        case "--check-only" where allowCheck && !checkOnly:
            checkOnly = true
            index += 1
        default: throw PPTPError("unsupported connect option; use --config PATH and optionally --check-only")
        }
    }
    guard let path else { throw PPTPError("--config PATH is required") }
    let url = URL(fileURLWithPath: path)
    let size = try url.resourceValues(forKeys: [.fileSizeKey]).fileSize ?? 0
    guard size <= 65536 else { throw PPTPError("configuration file is too large") }
    return (try ClientConfiguration.load(Data(contentsOf: url)), checkOnly)
}

func checkConfiguration(_ args: [String]) throws {
    let (profile, _) = try loadProfile(args, allowCheck: false)
    print("Configuration: valid")
    print("Server: \(profile.server):\(profile.port ?? 1723)")
    print("Authentication: PAP; encryption: NONE")
    print("Routes: \(try profile.routes.map { try IPv4CIDR($0).description }.joined(separator: ", "))")
    print("DNS domains: \((profile.dnsDomains ?? []).joined(separator: ", "))")
}

func connectVPN(_ args: [String]) throws {
    let (profile, checkOnly) = try loadProfile(args, allowCheck: true)
    guard geteuid() == 0 else { throw PPTPError("connect requires administrator privileges (sudo)") }
    print("Mode: PPTP / PAP / NO ENCRYPTION")
    let credentials = try Credentials.prompt()
    guard pptp_install_signals() == 0 else { throw PPTPError("could not install signal handlers") }
    defer { pptp_restore_signals() }
    do {
        try VPNRunner.run(profile: profile, credentials: credentials, checkOnly: checkOnly,
                          cancelled: { pptp_cancelled() != 0 }) { event in
            print("PPP state: \(event.phase.rawValue) \(event.message)")
            if let address = event.address { print("PPP IPv4: \(address)") }
            if let name = event.interface { print("VPN connected on \(name).") }
        }
    } catch SessionRunError.cancelled { print("PPTP disconnected.") }
}
