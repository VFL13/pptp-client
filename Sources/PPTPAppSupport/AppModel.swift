import Combine
import Foundation
import PPTPCore
import PPTPRuntime

@MainActor public final class AppModel: ObservableObject {
    public typealias Factory = @Sendable (@escaping @Sendable (SessionUpdate) -> Void, @escaping @Sendable () -> Void) -> any HelperCommunicating
    @Published public var profile: AppProfile
    @Published public var password = ""
    @Published public var dnsServersText = ""
    @Published public var dnsDomainsText = ""
    @Published public private(set) var snapshot = SessionUpdate(.disconnected, "Отключено")
    @Published public private(set) var helperAvailable = false
    @Published public private(set) var checkingHelper = false
    @Published public var errorMessage: String?
    @Published public private(set) var log: [String] = []
    private let store: ProfileStore
    private let passwords: any PasswordStoring
    private let factory: Factory
    private var helper: (any HelperCommunicating)?
    private var generation = UUID()
    private var pendingPassword: Data?
    private var pendingAccount: String?
    private var closing = false
    public var canEdit: Bool { !snapshot.phase.isActive }
    public var canConnect: Bool { helperAvailable && canEdit }
    public var needsImport: Bool { profile.configuration.server.isEmpty }
    public var statusTitle: String {
        switch snapshot.phase {
        case .disconnected: return "Отключено"
        case .connecting: return "Подключение"
        case .lcp: return "Согласование PPP"
        case .authenticating: return "Проверка пароля"
        case .ipcp: return "Получение адреса"
        case .configuring: return "Настройка маршрутов"
        case .connected: return "Подключено"
        case .stopping: return "Отключение"
        case .failed: return "Не удалось подключиться"
        }
    }

    public init(store: ProfileStore = ProfileStore(), passwords: any PasswordStoring = KeychainPasswordStore(),
                factory: @escaping Factory = { HelperConnection(event: $0, unavailable: $1) }) {
        self.store = store; self.passwords = passwords; self.factory = factory
        do { profile = try store.load() ?? AppProfile() }
        catch { profile = AppProfile(); errorMessage = "Не удалось прочитать профиль. Импортируйте конфигурацию заново." }
        syncDNS()
    }

    public func prepareHelper(requirement: String) {
        guard canEdit, !closing else { return }
        generation = UUID()
        let current = generation
        helper?.invalidate()
        checkingHelper = true; helperAvailable = false
        let transport = factory({ [weak self] event in
            Task { @MainActor in guard let self, self.generation == current, !self.closing else { return }; self.receive(event) }
        }, { [weak self] in
            Task { @MainActor in
                guard let self, self.generation == current, !self.closing else { return }
                self.helperAvailable = false; self.checkingHelper = false
                if self.snapshot.phase.isActive { self.receive(SessionUpdate(.failed, "Связь со служебным компонентом потеряна")) }
            }
        })
        helper = transport
        transport.open(requirement: requirement) { [weak self] available in
            Task { @MainActor in
                guard let self, self.generation == current, !self.closing else { return }
                self.helperAvailable = available; self.checkingHelper = false
            }
        }
        Task { @MainActor [weak self] in
            try? await Task.sleep(for: .seconds(3))
            guard let self, self.generation == current, self.checkingHelper else { return }
            self.checkingHelper = false; self.helperAvailable = false
        }
    }

    public func saveProfile() {
        do { try persist() }
        catch { errorMessage = "Проверьте настройки: \(error)" }
    }
    public func importConfiguration(_ data: Data) {
        guard canEdit else { return }
        do { profile = try store.importing(data, into: profile); syncDNS(); try store.save(profile) }
        catch { errorMessage = "Не удалось импортировать JSON: \(error)" }
    }
    public func exportConfiguration() throws -> Data { try persist(); return try store.exporting(profile) }
    public func addRoute(_ text: String) throws {
        guard canEdit else { return }
        let route = try IPv4CIDR(text.trimmingCharacters(in: .whitespacesAndNewlines)).description
        guard !profile.configuration.routes.contains(route) else { throw PPTPError("эта подсеть уже добавлена") }
        profile.configuration.routes.append(route)
    }
    public func forgetPassword() {
        do { try passwords.remove(account: profile.id.uuidString); password = ""; clearPending() }
        catch { errorMessage = "Не удалось удалить пароль из Связки ключей" }
    }

    public func connect() {
        guard canConnect, let helper else { return }
        do {
            try persist()
            let secret: Data
            if !password.isEmpty { secret = Data(password.utf8) }
            else if profile.rememberPassword, let saved = try passwords.read(account: profile.id.uuidString) { secret = saved }
            else { throw PPTPError("Введите пароль VPN") }
            guard !profile.username.isEmpty, profile.username.utf8.count <= 255,
                  !secret.isEmpty, secret.count <= 255 else { throw PPTPError("Проверьте логин и пароль VPN") }
            if profile.rememberPassword { pendingPassword = secret; pendingAccount = profile.id.uuidString }
            password = ""
            receive(SessionUpdate(.connecting, "Подключение"))
            helper.start(configuration: try store.exporting(profile), username: profile.username, password: secret) { [weak self] accepted, message in
                Task { @MainActor in
                    guard let self, !self.closing else { return }
                    if !accepted { self.receive(SessionUpdate(.failed, message)) }
                }
            }
        } catch { errorMessage = "\(error)"; clearPending() }
    }
    public func disconnect() {
        guard snapshot.phase.isActive else { return }
        snapshot = SessionUpdate(.stopping, "Отключение")
        helper?.stop { [weak self] success in
            Task { @MainActor in
                guard let self, !self.closing else { return }
                self.receive(success ? SessionUpdate(.disconnected, "Отключено") : SessionUpdate(.failed, "Не удалось подтвердить остановку служебного компонента"))
            }
        }
    }
    public func uninstallHelper() {
        guard canEdit else { return }
        helper?.uninstall { [weak self] success, message in
            Task { @MainActor in
                guard let self else { return }
                if success { self.helperAvailable = false; self.helper?.invalidate() }
                else { self.errorMessage = message }
            }
        }
    }
    public func shutdown(completion: @escaping @MainActor @Sendable () -> Void) {
        closing = true; clearPending(); password = ""
        guard let helper else { completion(); return }
        helper.stop { _ in Task { @MainActor in helper.invalidate(); completion() } }
    }
    public func receive(_ update: SessionUpdate) {
        if snapshot.phase == .stopping, update.phase.isActive, update.phase != .stopping { return }
        if snapshot == update { return }
        if update.authenticated, let pendingPassword, let pendingAccount {
            do { try passwords.save(pendingPassword, account: pendingAccount) }
            catch { errorMessage = "VPN принят сервером, но пароль не удалось сохранить в Связке ключей" }
            clearPending()
        }
        if update.phase == .failed || update.phase == .disconnected { clearPending() }
        snapshot = update
        let time = Date().formatted(date: .omitted, time: .standard)
        log.append("\(time)  \(update.phase.rawValue)  \(update.message)")
        if log.count > 200 { log.removeFirst(log.count - 200) }
    }
    private func persist() throws {
        profile.configuration.dnsServers = tokens(dnsServersText)
        profile.configuration.dnsDomains = tokens(dnsDomainsText)
        try store.save(profile)
        if !profile.rememberPassword { try passwords.remove(account: profile.id.uuidString) }
    }
    private func syncDNS() {
        dnsServersText = (profile.configuration.dnsServers ?? []).joined(separator: ", ")
        dnsDomainsText = (profile.configuration.dnsDomains ?? []).joined(separator: ", ")
    }
    private func tokens(_ string: String) -> [String] { string.split { $0 == "," || $0.isWhitespace }.map(String.init) }
    private func clearPending() {
        if let count = pendingPassword?.count { pendingPassword?.resetBytes(in: 0..<count) }
        pendingPassword = nil; pendingAccount = nil
    }
}
