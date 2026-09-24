# Fleet UI design (dark theme only)

The live canvas is at https://claude.ai/artifact/PuJiRrfLgeZdx4fc8ivHJk. The `ui-reference/*.dc.html` files are the canvas source for each screen. They need the canvas runtime to render, so use them as a reference for exact values, not as runnable pages.

## Tokens

| Token | Value | Use |
|---|---|---|
| window | `#121315` | App background |
| sidebar | `#141518` | Sidebar |
| header | `#151619` | Toolbars and headers |
| card | `#1a1b1e` | Cards and tables |
| card-subtle | `#1f2024` | Table headers, footers |
| control | `#25262b` | Buttons, inputs, active segmented button |
| track | `#0f1012` | Segmented control background |
| selected | `#26272c` | Active navigation item, chips |
| border | `#2a2b30` | Card borders |
| border-control | `#34363c` | Control borders |
| divider | `#232429` | Row dividers |
| text | `#ededee` | Primary text |
| text-secondary | `#a3a7ae` | Secondary text |
| text-muted | `#8d9199` | Captions, metadata |
| accent | `#2563eb` | Primary buttons, charts; white text on it |
| accent-text | accent mixed 45% toward white (`#87a9f4`) | Links and accent-colored text on dark surfaces |
| ok | bg `#15291d`, text `#6fd49a`, dot `#3fb772` | Healthy |
| warn | bg `#33230f`, text `#f0a257`, dot `#e8832a` | Warnings |
| critical | bg `#3a1a17`, text `#ff8a7d`, dot `#ef5a4a` | Critical |
| info | bg `#182338`, text `#8fb3ff` | Pending, running, selected |
| terminal | bg `#0d0e10`, bar `#16171a`, prompt `#8ab4f8` | Terminal |

## Type

- **Geist** (400/500/600) for the UI; **Geist Mono** for IPs, paths, logs, the terminal and PIDs.
- **Sizes:** 13 px base (matching macOS), 12 px secondary, 11 px captions. Titles: 17 px (toolbar), 22 px (server name), 20 px (settings section).
- Tabular numerals for every metric.

## Layout

- **Window:** 1440×900 reference. Sidebar 240 px; toolbar 60 px; content padding 24–28 px.
- **Radii:** cards 12 px, controls 8 px, pills 11 px.
- **Tables:** row height 42 px; column header 36 px on card-subtle.
- **Status:** always a pill with a dot plus a text label. Color is never the only signal.

## Screens

1. **Fleet overview:** summary cards, "while you were away" digest, server table with CPU sparklines.
2. **Server overview:** 24-hour metric charts, top processes, timeline, containers, profile and score.
3. **Terminal and files:** tabbed terminal backed by tmux, broadcast and record toggles, SFTP browser, transfers.
4. **Security:** hardening score ring, bans, vulnerabilities, login history, needs-attention list, change alerts.
5. **Firewall:** auto-revert confirmation banner, rules table with the added rule highlighted, container ports, ruleset history.
6. **Bulk run:** operation or shell, targets, canary-then-batches rollout, dry run, live progress per server.
7. **Provisioning wizard:** 5-step stepper, profile and role choice, access settings, plan preview with expected score.
8. **Settings, Devices:** Macs with Secure Enclave keys, roster status, recovery drill, pausing AI agents, encrypted sync.

## SwiftUI notes

- Use `NavigationSplitView` with the sidebar as shown. The command palette (⌘K) is an overlay.
- Force dark appearance (`.preferredColorScheme(.dark)`) and define the tokens as a `Color` extension.
- Charts: Swift Charts `AreaMark` + `LineMark` with accent at about 9% fill opacity.
- Terminal: SwiftTerm, themed with the terminal tokens.
