import Foundation

public struct ClientConfiguration: Decodable, Sendable {
    public let server: String
    public let port: UInt16?
    public let authentication: String
    public let encryption: String
    public let routes: [String]
    public let dnsServers: [String]?
    public let dnsDomains: [String]?

    public static func load(_ data: Data) throws -> ClientConfiguration {
        guard let object = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw PPTPError("configuration must be a JSON object")
        }
        let allowed: Set<String> = ["server", "port", "authentication", "encryption", "routes", "dnsServers", "dnsDomains"]
        guard Set(object.keys).isSubset(of: allowed) else { throw PPTPError("configuration contains unsupported keys; credentials must not be stored here") }
        let config = try JSONDecoder().decode(ClientConfiguration.self, from: data)
        try config.validate()
        return config
    }

    public func validate() throws {
        let server = try IPv4Value(server)
        guard server.isUnicast, (port ?? 1723) > 0 else { throw PPTPError("invalid PPTP server or port") }
        guard authentication == "pap", encryption == "none" else {
            throw PPTPError("this build supports only explicit authentication=pap and encryption=none")
        }
        guard !routes.isEmpty, routes.count <= 128 else { throw PPTPError("configure between 1 and 128 routes") }
        let parsed = try routes.map(IPv4CIDR.init)
        guard Set(parsed.map(\.description)).count == parsed.count else { throw PPTPError("duplicate configured routes") }
        guard !parsed.contains(where: { $0.contains(server) }) else {
            throw PPTPError("a configured route includes the public PPTP server; recursive tunneling is prohibited")
        }
        guard (dnsServers ?? []).count <= 4, (dnsDomains ?? []).count <= 32 else { throw PPTPError("too many DNS servers or domains") }
        for dns in dnsServers ?? [] {
            guard try IPv4Value(dns).isUnicast else { throw PPTPError("invalid DNS server address") }
        }
        for domain in dnsDomains ?? [] {
            guard domain.utf8.count <= 253, !domain.isEmpty,
                  domain.split(separator: ".", omittingEmptySubsequences: false).allSatisfy({ label in
                      !label.isEmpty && label.utf8.count <= 63 && label.first != "-" && label.last != "-"
                      && label.utf8.allSatisfy { (65...90).contains($0) || (97...122).contains($0) || (48...57).contains($0) || $0 == 45 }
                  }) else { throw PPTPError("DNS domains must be explicit ASCII domain names") }
        }
    }
}
