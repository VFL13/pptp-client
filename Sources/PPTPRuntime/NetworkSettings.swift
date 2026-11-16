import Foundation
import PPTPCore
import SystemConfiguration

final class NetworkSettings {
    private let interface: String
    private var routes: [IPv4CIDR] = []
    private var dnsStore: SCDynamicStore?
    private var dnsKey: String?

    init(interface: String) { self.interface = interface }

    func apply(profile: ClientConfiguration, network: PPPNetworkConfiguration) throws {
        var wanted = try profile.routes.map(IPv4CIDR.init)
        let configuredDNS = profile.dnsServers ?? []
        let dns = try configuredDNS.isEmpty ? network.dnsServers : configuredDNS.map(IPv4Value.init)
        if !(profile.dnsDomains ?? []).isEmpty {
            guard !dns.isEmpty else { throw PPTPError("DNS domains configured but no DNS server was supplied or assigned") }
            let server = try IPv4Value(profile.server)
            for address in dns where !wanted.contains(where: { $0.contains(address) }) {
                guard address != server else { throw PPTPError("DNS route would include the public VPN server") }
                wanted.append(try IPv4CIDR("\(address)/32"))
            }
        }
        for route in wanted {
            // ifconfig already installs the point-to-point peer's host route.
            if route.prefix == 32, route.network == network.peerAddress { continue }
            try LocalCommand.run("/sbin/route", ["-n", "add", "-net", route.description, "-interface", interface])
            routes.append(route)
        }
        if let domains = profile.dnsDomains, !domains.isEmpty {
            guard let store = SCDynamicStoreCreate(nil, "PPTPClient" as CFString, nil, nil) else { throw PPTPError("could not open DNS settings session") }
            let key = "State:/Network/Service/PPTPClient-\(UUID().uuidString)/DNS"
            let value: [String: Any] = ["ServerAddresses": dns.map(\.description), "SupplementalMatchDomains": domains,
                "SupplementalMatchOrders": domains.map { _ in 10 }, "InterfaceName": interface]
            guard SCDynamicStoreAddTemporaryValue(store, key as CFString, value as CFDictionary) else { throw PPTPError("could not apply temporary DNS settings") }
            dnsStore = store
            dnsKey = key
        }
    }

    /// The caller closes utun afterward, which also removes its interface routes.
    func remove() -> [String] {
        var warnings: [String] = []
        if let dnsStore, let dnsKey, !SCDynamicStoreRemoveValue(dnsStore, dnsKey as CFString) {
            warnings.append("could not explicitly remove temporary DNS settings")
        }
        dnsStore = nil
        dnsKey = nil
        for route in routes.reversed() {
            do { try LocalCommand.run("/sbin/route", ["-n", "delete", "-net", route.description, "-interface", interface]) }
            catch { warnings.append("could not explicitly remove route \(route); closing utun will remove interface routes") }
        }
        routes.removeAll()
        return warnings
    }
}
