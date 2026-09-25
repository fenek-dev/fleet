import SwiftUI

/// Menu bar extra (design §7.5): fleet health, alert count, lock state.
struct MenuBarView: View {
    @Environment(CoreBridge.self) private var core
    @Environment(AppLock.self) private var lock
    @Environment(AIModel.self) private var ai
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        Text("\(core.onlineCount) of \(core.servers.count) servers online")
        Text(core.alerts.isEmpty ? "No open alerts" : "\(core.alerts.count) open alerts · \(core.criticalCount) critical")
        Divider()
        Button(lock.isLocked ? "Unlock Fleet" : "Lock Fleet") {
            if lock.isLocked { Task { await lock.unlock() } } else { lock.lock() }
        }
        Button(ai.paused ? "Resume AI agents" : "Pause AI agents") { ai.setPaused(!ai.paused) }
        Divider()
        Button("Open Fleet") {
            openWindow(id: "main")
            NSApp.activate()
        }
        Button("Quit Fleet") { NSApp.terminate(nil) }
            .keyboardShortcut("q")
    }
}

struct MenuBarLabel: View {
    @Environment(CoreBridge.self) private var core

    var body: some View {
        let count = core.alerts.count
        if count > 0 {
            Label("\(count)", systemImage: "server.rack")
                .labelStyle(.titleAndIcon)
        } else {
            Image(systemName: "server.rack")
        }
    }
}
