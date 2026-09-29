import SwiftUI

/// Servers carrying one tag (sidebar "Tags").
struct TagView: View {
    @Environment(CoreBridge.self) private var core
    let tag: String
    @Binding var selection: NavItem?

    var body: some View {
        let servers = core.servers.filter { $0.tags.contains(tag) }
        VStack(spacing: 0) {
            ScreenHeader(tag, subtitle: "\(servers.count) server\(servers.count == 1 ? "" : "s") tagged") {
                Chip(text: tag)
            }
            if servers.isEmpty {
                ContentUnavailableView("No server has this tag", systemImage: "tag")
                    .accessibilityIdentifier("tag.empty")
            } else {
                ScrollView {
                    VStack(spacing: 0) {
                        ForEach(Array(servers.enumerated()), id: \.element.id) { i, s in
                            if i > 0 { Divider().overlay(Color.divider) }
                            Button { selection = .server(s.id) } label: {
                                HStack(spacing: 14) {
                                    VStack(alignment: .leading, spacing: 2) {
                                        Text(s.name).foregroundStyle(Color.text).font(.base.weight(.medium))
                                        Text("\(s.host):\(s.port)").font(.mono(11)).foregroundStyle(Color.textMuted)
                                    }
                                    Spacer()
                                    ForEach(s.tags.filter { $0 != tag }, id: \.self) { Chip(text: $0) }
                                    StatusPill(label: s.state.label, tone: s.state.tone)
                                }
                                .padding(.horizontal, 16)
                                .frame(height: Metrics.tableRowHeight + 8)
                                .contentShape(Rectangle())
                            }
                            .buttonStyle(.plain)
                            .accessibilityIdentifier("tag.server.\(s.name)")
                        }
                    }
                    .background(Color.card, in: RoundedRectangle(cornerRadius: 12))
                    .overlay(RoundedRectangle(cornerRadius: 12).stroke(Color.border))
                    .padding(24)
                }
            }
        }
        .background(Color.window)
        .navigationTitle(tag)
    }
}
