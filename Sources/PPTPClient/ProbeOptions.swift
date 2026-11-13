import Foundation
import PPTPCore

struct ProbeOptions {
    let host: String
    var port: UInt16 = 1723
    var timeout = 10.0

    init(_ args: [String]) throws {
        guard let host = args.first, !host.isEmpty, !host.hasPrefix("-"),
              !host.contains("://"), !host.contains("/"),
              !host.unicodeScalars.contains(where: { CharacterSet.whitespacesAndNewlines.contains($0) }) else {
            throw PPTPError("provide a server hostname or IP address, without a URL scheme")
        }
        self.host = host
        var seen: Set<String> = []
        var index = 1
        while index < args.count {
            let option = args[index]
            guard index + 1 < args.count, seen.insert(option).inserted else {
                throw PPTPError("missing value or duplicate option: \(option)")
            }
            let value = args[index + 1]
            switch option {
            case "--port":
                guard let parsed = UInt16(value), parsed > 0 else { throw PPTPError("invalid TCP port") }
                port = parsed
            case "--timeout":
                guard let parsed = Double(value), parsed.isFinite, parsed > 0, parsed <= 120 else {
                    throw PPTPError("timeout must be between 0 and 120 seconds, excluding 0")
                }
                timeout = parsed
            default: throw PPTPError("unknown option: \(option)")
            }
            index += 2
        }
    }
}
