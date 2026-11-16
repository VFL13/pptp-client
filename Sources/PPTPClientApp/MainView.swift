import AppKit
import SwiftUI
import UniformTypeIdentifiers
import PPTPAppSupport

struct MainView: View {
    @ObservedObject var model: AppModel
    @State private var newRoute = ""
    @State private var removeHelper = false
    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 14) {
                Image(systemName: "network").font(.system(size: 30)).foregroundStyle(.white)
                    .frame(width: 58, height: 58).background(.blue.gradient, in: RoundedRectangle(cornerRadius: 16))
                VStack(alignment: .leading, spacing: 4) {
                    Text("PPTPClient").font(.title2.bold())
                    Text("Ваши рабочие сети на Mac").font(.subheadline).foregroundStyle(.secondary)
                }
                Spacer()
                Label(model.statusTitle, systemImage: model.snapshot.phase == .connected ? "checkmark.circle.fill" : "circle")
                    .font(.callout).foregroundStyle(model.snapshot.phase == .connected ? .green : .secondary)
            }.padding(22)
            Divider()
            if !model.helperAvailable {
                HStack {
                    Image(systemName: "gear.badge.checkmark")
                    Text(model.checkingHelper ? "Проверка служебного компонента…" : "Установите служебный компонент из PPTPClient.pkg")
                    Spacer()
                    Button("Установщик…", action: openInstaller)
                    Button { refreshHelper() } label: { Image(systemName: "arrow.clockwise") }
                }.font(.callout).padding(12).background(.blue.opacity(0.07))
            }
            TabView {
                connection.tabItem { Label("Подключение", systemImage: "network") }
                routes.tabItem { Label("Сети", systemImage: "point.3.connected.trianglepath.dotted") }
                dns.tabItem { Label("DNS", systemImage: "globe") }
                diagnostics.tabItem { Label("Диагностика", systemImage: "text.alignleft") }
            }.padding(14)
            Divider()
            HStack {
                Button("Импорт JSON…", action: importJSON).disabled(!model.canEdit)
                Button("Экспорт JSON…", action: exportJSON).disabled(!model.canEdit)
                Spacer()
                if model.snapshot.phase.isActive {
                    if model.snapshot.phase != .connected { ProgressView().controlSize(.small) }
                    Button("Отключить") { model.disconnect() }.disabled(model.snapshot.phase == .stopping)
                } else {
                    Button("Подключить") { model.connect() }.buttonStyle(.borderedProminent).disabled(!model.canConnect)
                }
            }.padding(16)
        }
        .frame(minWidth: 610, minHeight: 580)
        .alert("PPTPClient", isPresented: Binding(get: { model.errorMessage != nil }, set: { if !$0 { model.errorMessage = nil } })) {
            Button("OK") { model.errorMessage = nil }
        } message: { Text(model.errorMessage ?? "") }
        .confirmationDialog("Удалить служебный компонент?", isPresented: $removeHelper) {
            Button("Удалить компонент", role: .destructive) { model.uninstallHelper() }
        } message: { Text("Приложение и профиль останутся. Для нового подключения потребуется повторная установка пакета.") }
    }

    private var connection: some View {
        Form {
            if model.needsImport {
                Section { Text("Импортируйте существующий JSON-конфиг или укажите сервер и сети вручную.").foregroundStyle(.secondary) }
            }
            Section("Сервер") {
                TextField("IPv4-адрес", text: $model.profile.configuration.server, prompt: Text("203.0.113.10"))
                TextField("TCP-порт", value: Binding(get: { Int(model.profile.configuration.port ?? 1723) }, set: { model.profile.configuration.port = UInt16(exactly: $0) ?? 0 }), format: .number.grouping(.never))
            }.disabled(!model.canEdit)
            Section("Учётная запись") {
                TextField("Логин", text: $model.profile.username)
                SecureField("Пароль", text: $model.password, prompt: Text("Введите пароль или используйте Keychain"))
                Toggle("Запомнить пароль в Связке ключей", isOn: $model.profile.rememberPassword)
                Button("Забыть сохранённый пароль") { model.forgetPassword() }.font(.callout)
            }.disabled(!model.canEdit)
            Section {
                Text("PPTP · PAP · без шифрования").font(.caption).foregroundStyle(.secondary)
                if let address = model.snapshot.address { LabeledContent("Адрес VPN", value: address) }
                if let name = model.snapshot.interface { LabeledContent("Интерфейс", value: name) }
                if !model.snapshot.message.isEmpty { Text(model.snapshot.message).foregroundStyle(model.snapshot.phase == .failed ? .red : .secondary) }
            }
        }.formStyle(.grouped)
    }
    private var routes: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Только эти сети используют VPN. Остальной трафик идёт обычным путём.").font(.callout).foregroundStyle(.secondary)
            List {
                ForEach(model.profile.configuration.routes, id: \.self) { route in
                    HStack {
                        Text(route).font(.system(.body, design: .monospaced))
                        Spacer()
                        Button { model.profile.configuration.routes.removeAll { $0 == route } } label: { Image(systemName: "trash") }.buttonStyle(.borderless)
                    }
                }
            }.clipShape(RoundedRectangle(cornerRadius: 8))
            HStack {
                TextField("Подсеть CIDR, например 192.0.2.0/24", text: $newRoute).onSubmit(addRoute)
                Button("Добавить", action: addRoute)
                Button("Сохранить") { model.saveProfile() }
            }
        }.padding(10).disabled(!model.canEdit)
    }
    private var dns: some View {
        Form {
            Section("Внутренние имена") {
                TextField("Домены через запятую", text: $model.dnsDomainsText, prompt: Text("corp.example"))
                TextField("DNS-серверы через запятую", text: $model.dnsServersText, prompt: Text("Назначенные VPN-сервером, если поле пустое"))
            }
            Section {
                Text("Если домены не заданы, DNS macOS не меняется. Указанные домены будут использовать DNS через VPN.").foregroundStyle(.secondary)
                Button("Сохранить настройки") { model.saveProfile() }
            }
        }.formStyle(.grouped).disabled(!model.canEdit)
    }
    private var diagnostics: some View {
        VStack(alignment: .leading, spacing: 12) {
            ScrollView { Text(model.log.isEmpty ? "Здесь появятся состояния подключения." : model.log.joined(separator: "\n"))
                .font(.system(.caption, design: .monospaced)).frame(maxWidth: .infinity, alignment: .leading).textSelection(.enabled) }
            HStack {
                Button("Сохранить журнал…") {
                    let panel = NSSavePanel(); panel.nameFieldStringValue = "pptp-diagnostics.txt"
                    if panel.runModal() == .OK, let url = panel.url {
                        do { try Data(model.log.joined(separator: "\n").utf8).write(to: url, options: .atomic) }
                        catch { model.errorMessage = "Не удалось сохранить журнал" }
                    }
                }
                Spacer()
                Button("Удалить служебный компонент…", role: .destructive) { removeHelper = true }.disabled(!model.helperAvailable || !model.canEdit)
            }
        }.padding(10)
    }
    private func addRoute() {
        do { try model.addRoute(newRoute); newRoute = "" }
        catch { model.errorMessage = "Не удалось добавить подсеть: \(error)" }
    }
    private func importJSON() {
        let panel = NSOpenPanel(); panel.allowedContentTypes = [.json]; panel.allowsMultipleSelection = false
        if panel.runModal() == .OK, let url = panel.url {
            do { model.importConfiguration(try Data(contentsOf: url)) }
            catch { model.errorMessage = "Не удалось открыть JSON" }
        }
    }
    private func exportJSON() {
        let panel = NSSavePanel(); panel.allowedContentTypes = [.json]; panel.nameFieldStringValue = "vpn-config.json"
        if panel.runModal() == .OK, let url = panel.url {
            do { try model.exportConfiguration().write(to: url, options: .atomic) }
            catch { model.errorMessage = "Не удалось экспортировать конфигурацию: \(error)" }
        }
    }
    private func refreshHelper() { model.prepareHelper(requirement: Bundle.main.object(forInfoDictionaryKey: "PPTPHelperRequirement") as? String ?? "") }
    private func openInstaller() {
        let sibling = Bundle.main.bundleURL.deletingLastPathComponent().appendingPathComponent("PPTPClient.pkg")
        if FileManager.default.fileExists(atPath: sibling.path) { NSWorkspace.shared.open(sibling); return }
        let panel = NSOpenPanel(); panel.allowedContentTypes = [UTType(filenameExtension: "pkg") ?? .package]
        if panel.runModal() == .OK, let url = panel.url { NSWorkspace.shared.open(url) }
    }
}
