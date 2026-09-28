import SwiftUI

/// ⌘K palette (skeleton): jump to servers and screens, lock/unlock.
/// Operations arrive with the bulk engine.
struct PaletteAction: Identifiable {
    let id: String
    let title: String
    let subtitle: String
    let symbol: String
    let run: @MainActor () -> Void
}

struct CommandPalette: View {
    @Environment(CoreBridge.self) private var core
    @Environment(AppLock.self) private var lock
    @Binding var isPresented: Bool
    @Binding var selection: NavItem?
    @State private var query = ""
    @State private var highlighted = 0
    @FocusState private var focused: Bool

    private var actions: [PaletteAction] {
        var all: [PaletteAction] = [
            .init(id: "nav.fleet", title: "Fleet", subtitle: "Go to", symbol: "server.rack") {
                selection = .fleet
            },
            .init(id: "nav.alerts", title: "Alerts", subtitle: "Go to", symbol: "bell") {
                selection = .alerts
            },
            .init(id: "lock", title: lock.isLocked ? "Unlock Fleet" : "Lock Fleet",
                  subtitle: "App", symbol: lock.isLocked ? "lock.open" : "lock") {
                if lock.isLocked { Task { await lock.unlock() } } else { lock.lock() }
            },
        ]
        for s in core.servers {
            all.append(.init(id: "srv.\(s.id)", title: s.name, subtitle: s.host,
                             symbol: "server.rack") { selection = .server(s.id) })
        }
        let q = query.trimmingCharacters(in: .whitespaces).lowercased()
        guard !q.isEmpty else { return all }
        return all.filter {
            $0.title.lowercased().contains(q) || $0.subtitle.lowercased().contains(q)
        }
    }

    var body: some View {
        let list = actions
        VStack(spacing: 0) {
            HStack(spacing: 8) {
                Image(systemName: "magnifyingglass").foregroundStyle(Color.textMuted)
                TextField("Search servers or run…", text: $query)
                    .textFieldStyle(.plain)
                    .font(.system(size: 15))
                    .focused($focused)
                    .accessibilityIdentifier("palette.query")
                    .onSubmit { run(list) }
            }
            .padding(14)
            Divider().overlay(Color.divider)
            ScrollView {
                VStack(spacing: 2) {
                    ForEach(Array(list.prefix(12).enumerated()), id: \.element.id) { i, a in
                        HStack(spacing: 10) {
                            Image(systemName: a.symbol).frame(width: 18)
                            Text(a.title).foregroundStyle(Color.text)
                            Spacer()
                            Text(a.subtitle).font(.secondary).foregroundStyle(Color.textMuted)
                        }
                        .font(.base)
                        .padding(.horizontal, 12)
                        .frame(height: 34)
                        .background(i == highlighted ? Color.selected : .clear,
                                    in: RoundedRectangle(cornerRadius: 8))
                        .contentShape(Rectangle())
                        .accessibilityElement(children: .combine)
                        .accessibilityAddTraits(.isButton)
                        .accessibilityIdentifier("palette.item.\(a.id)")
                        .onTapGesture { highlighted = i; run(list) }
                    }
                }
                .padding(6)
            }
            .frame(maxHeight: 360)
        }
        .frame(width: 560)
        .background(Color.card, in: RoundedRectangle(cornerRadius: 12))
        .overlay(RoundedRectangle(cornerRadius: 12).stroke(Color.border))
        .shadow(radius: 30)
        .onAppear { focused = true }
        .onChange(of: query) { highlighted = 0 }
        .onKeyPress(.downArrow) { highlighted = min(highlighted + 1, max(list.count - 1, 0)); return .handled }
        .onKeyPress(.upArrow) { highlighted = max(highlighted - 1, 0); return .handled }
        .onKeyPress(.escape) { isPresented = false; return .handled }
    }

    private func run(_ list: [PaletteAction]) {
        guard list.indices.contains(highlighted) else { return }
        list[highlighted].run()
        isPresented = false
    }
}
