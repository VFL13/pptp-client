import Foundation
import PPTPCore

public struct AppProfile: Codable, Equatable, Sendable {
    public var id: UUID
    public var username: String
    public var rememberPassword: Bool
    public var configuration: ClientConfiguration
    public init(id: UUID = UUID(), username: String = "", rememberPassword: Bool = true,
                configuration: ClientConfiguration = ClientConfiguration()) {
        self.id = id; self.username = username; self.rememberPassword = rememberPassword; self.configuration = configuration
    }
}

public struct ProfileStore: Sendable {
    public let directory: URL
    public init(directory: URL? = nil) {
        self.directory = directory ?? FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("PPTPClient", isDirectory: true)
    }
    public func load() throws -> AppProfile? {
        let file = directory.appendingPathComponent("profile.json")
        guard FileManager.default.fileExists(atPath: file.path) else { return nil }
        let size = try file.resourceValues(forKeys: [.fileSizeKey]).fileSize ?? 0
        guard size <= 65536 else { throw PPTPError("profile is too large") }
        let data = try Data(contentsOf: file)
        guard data.count <= 65536 else { throw PPTPError("profile is too large") }
        return try JSONDecoder().decode(AppProfile.self, from: data)
    }
    public func save(_ profile: AppProfile) throws {
        try profile.configuration.validate()
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true,
                                               attributes: [.posixPermissions: 0o700])
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: directory.path)
        let encoder = JSONEncoder(); encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        let target = directory.appendingPathComponent("profile.json")
        try encoder.encode(profile).write(to: target, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: target.path)
    }
    public func importing(_ data: Data, into profile: AppProfile) throws -> AppProfile {
        guard data.count <= 65536 else { throw PPTPError("configuration is too large") }
        var changed = profile
        changed.configuration = try ClientConfiguration.load(data)
        return changed
    }
    public func exporting(_ profile: AppProfile) throws -> Data {
        try profile.configuration.validate()
        let encoder = JSONEncoder(); encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        return try encoder.encode(profile.configuration)
    }
}
