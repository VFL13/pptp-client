import AppKit
import SwiftUI
import PPTPAppSupport

@MainActor final class AppDelegate: NSObject, NSApplicationDelegate {
    var model: AppModel?
    private var terminating = false
    func applicationDidFinishLaunching(_ notification: Notification) {
        NSWorkspace.shared.notificationCenter.addObserver(self, selector: #selector(willSleep), name: NSWorkspace.willSleepNotification, object: nil)
        NSWorkspace.shared.notificationCenter.addObserver(self, selector: #selector(didWake), name: NSWorkspace.didWakeNotification, object: nil)
    }
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { false }
    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        if terminating { return .terminateNow }
        terminating = true
        guard let model else { return .terminateNow }
        model.shutdown { NSApp.reply(toApplicationShouldTerminate: true) }
        Task { @MainActor in
            try? await Task.sleep(for: .seconds(15))
            NSApp.reply(toApplicationShouldTerminate: true)
        }
        return .terminateLater
    }
    @objc private func willSleep() { model?.disconnect() }
    @objc private func didWake() {
        model?.prepareHelper(requirement: Bundle.main.object(forInfoDictionaryKey: "PPTPHelperRequirement") as? String ?? "")
    }
}

@main struct PPTPClientApplication: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate
    @StateObject private var model = AppModel()
    var body: some Scene {
        Window("PPTPClient", id: "main") {
            MainView(model: model)
                .task {
                    delegate.model = model
                    model.prepareHelper(requirement: Bundle.main.object(forInfoDictionaryKey: "PPTPHelperRequirement") as? String ?? "")
                }
        }
        .defaultSize(width: 640, height: 610)
        MenuBarExtra("PPTPClient", systemImage: model.snapshot.phase == .connected ? "network" : "circle.dotted") {
            MenuView(model: model)
        }
    }
}

private struct MenuView: View {
    @ObservedObject var model: AppModel
    @Environment(\.openWindow) private var openWindow
    var body: some View {
        Text(model.statusTitle)
        if let address = model.snapshot.address { Text(address) }
        Divider()
        Button("Открыть PPTPClient") { openWindow(id: "main"); NSApp.activate(ignoringOtherApps: true) }
        if model.snapshot.phase.isActive {
            Button("Отключить") { model.disconnect() }.disabled(model.snapshot.phase == .stopping)
        } else {
            Button("Подключить") {
                if model.password.isEmpty, !model.profile.rememberPassword { openWindow(id: "main"); NSApp.activate(ignoringOtherApps: true) }
                else { model.connect() }
            }.disabled(!model.canConnect)
        }
        Divider()
        Button("Выйти из PPTPClient") { NSApp.terminate(nil) }
    }
}
