import Foundation
import Security

public protocol PasswordStoring: Sendable {
    func read(account: String) throws -> Data?
    func save(_ password: Data, account: String) throws
    func remove(account: String) throws
}

public struct KeychainPasswordStore: PasswordStoring {
    private let service: String
    public init(service: String = "local.pptpclient") { self.service = service }
    private func query(_ account: String) -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service,
         kSecAttrAccount as String: account, kSecAttrSynchronizable as String: false]
    }
    public func read(account: String) throws -> Data? {
        var query = query(account)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let code = SecItemCopyMatching(query as CFDictionary, &result)
        if code == errSecItemNotFound { return nil }
        guard code == errSecSuccess else { throw PasswordStoreError(code: code) }
        return result as? Data
    }
    public func save(_ password: Data, account: String) throws {
        let base = query(account)
        let attributes: [String: Any] = [kSecValueData as String: password,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly]
        var code = SecItemUpdate(base as CFDictionary, attributes as CFDictionary)
        if code == errSecItemNotFound {
            code = SecItemAdd(base.merging(attributes) { _, new in new } as CFDictionary, nil)
        }
        guard code == errSecSuccess else { throw PasswordStoreError(code: code) }
    }
    public func remove(account: String) throws {
        let code = SecItemDelete(query(account) as CFDictionary)
        guard code == errSecSuccess || code == errSecItemNotFound else { throw PasswordStoreError(code: code) }
    }
}

public struct PasswordStoreError: Error, CustomStringConvertible {
    public let code: OSStatus
    public var description: String { "Keychain error \(code)" }
}
