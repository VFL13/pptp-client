import Darwin
import Foundation
import PPTPCore
import PPTPRuntime

let usage = """
PPTPClient — experimental IPv4 PPTP client for macOS

  pptp-client doctor
  pptp-client probe HOST [--port 1723] [--timeout 10]
  pptp-client gre-probe IPV4 [--port 1723] [--timeout 10]
  pptp-client config-check --config PATH
  pptp-client connect --config PATH [--check-only]

doctor checks local prerequisites and attempts to open, then close, a GRE
raw socket. It sends no packets and changes no network settings.
probe opens and closes a PPTP control channel. It does not authenticate,
create a PPP call, test GRE traffic, or establish a VPN.
gre-probe requires administrator privileges, creates a PPTP call and sends
one PPP LCP request over GRE. It does not authenticate or change routes/DNS.
The timeout includes setup and GRE exchange; shutdown has up to 2 extra seconds.
connect supports PAP with encryption=none only. Credentials are prompted in
the local terminal. Only explicit configuration routes use the VPN.
--check-only authenticates and negotiates IPv4 without modifying network settings.
"""

func doctor() {
    print("macOS: \(ProcessInfo.processInfo.operatingSystemVersionString)")
    #if arch(arm64)
    print("Architecture: arm64 (Apple Silicon)")
    #else
    print("Architecture: x86_64")
    #endif
    print("System pppd present: \(FileManager.default.isExecutableFile(atPath: "/usr/sbin/pppd"))")
    print("Presence of pppd does not establish that PPP/MPPE can be used on this OS.")
    let descriptor = socket(AF_INET, SOCK_RAW, IPPROTO_GRE)
    guard descriptor >= 0 else {
        let code = errno
        print("GRE socket: unavailable in this process (errno \(code): \(String(cString: strerror(code))))")
        if code == EPERM || code == EACCES {
            print("Opening a raw socket requires suitable privileges. GRE support remains unverified.")
        }
        exit(2)
    }
    close(descriptor)
    print("GRE socket: opened and closed successfully; GRE delivery remains unverified.")
}

func probe(_ args: [String]) throws {
    let options = try ProbeOptions(args)
    let transport = try NetworkTransport(host: options.host, port: options.port, timeout: options.timeout)
    let report = try ControlProbe.run(over: transport)
    print("PPTP control channel: established")
    print("Server host: \(report.server.host)")
    print("Server vendor: \(report.server.vendor)")
    if let warning = report.shutdownWarning {
        print("Control shutdown: unconfirmed (\(warning))")
    } else {
        print("Control shutdown: confirmed")
    }
    print("VPN is NOT connected. Authentication, GRE delivery and PPP/MPPE were not tested.")
    if !report.cleanShutdown { exit(2) }
}

do {
    let args = Array(CommandLine.arguments.dropFirst())
    switch args.first {
    case "doctor" where args.count == 1: doctor()
    case "probe": try probe(Array(args.dropFirst()))
    case "gre-probe":
        if !(try greProbe(Array(args.dropFirst()))) { exit(2) }
    case "config-check": try checkConfiguration(Array(args.dropFirst()))
    case "connect": try connectVPN(Array(args.dropFirst()))
    case nil, "--help", "-h": print(usage)
    default: throw PPTPError(usage)
    }
} catch {
    FileHandle.standardError.write(Data("Error: \(error)\n".utf8))
    exit(1)
}
