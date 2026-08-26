import SwiftUI
import UIKit

enum AppPage: String, CaseIterable, Identifiable {
    case downloads, flowShare, browser, settings, activity, schedule, license, about
    var id: String { rawValue }
    var title: String {
        switch self { case .flowShare: "FlowShare"; default: rawValue.capitalized }
    }
    var icon: String {
        switch self {
        case .downloads: "arrow.down.to.line"
        case .flowShare: "shareplay"
        case .browser: "globe"
        case .settings: "gearshape"
        case .activity: "clock.arrow.circlepath"
        case .schedule: "alarm"
        case .license: "checkmark.seal"
        case .about: "info.circle"
        }
    }
}

struct MainShellView: View {
    @EnvironmentObject private var store: AppStore
    @State private var page: AppPage = .downloads
    @State private var drawerOpen = false
    private let tabs: [AppPage] = [.downloads, .flowShare, .browser, .settings]

    var body: some View {
        ZStack(alignment: .leading) {
            VStack(spacing: 0) {
                Group {
                    switch page {
                    case .downloads: DownloadsView(openMenu: showDrawer)
                    case .flowShare: FlowShareView(openMenu: showDrawer)
                    case .browser: BrowserHomeView(openMenu: showDrawer)
                    case .settings: SettingsView(openMenu: showDrawer)
                    case .activity: ActivityView(openMenu: showDrawer)
                    case .schedule: ScheduleView(openMenu: showDrawer)
                    case .license: LicenseView(openMenu: showDrawer)
                    case .about: AboutView(openMenu: showDrawer)
                    }
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
                bottomBar
            }
            .disabled(drawerOpen)

            if drawerOpen {
                Color.black.opacity(0.52).ignoresSafeArea().onTapGesture { hideDrawer() }.transition(.opacity)
                DrawerView(selection: $page, close: hideDrawer)
                    .frame(width: min(310, UIScreen.main.bounds.width * 0.84))
                    .transition(.move(edge: .leading))
            }
        }
        .animation(.easeInOut(duration: 0.2), value: drawerOpen)
        .sheet(isPresented: Binding(
            get: { store.incomingURL != nil },
            set: { if !$0 { store.incomingURL = nil } }
        )) {
            if let url = store.incomingURL { AddDownloadView(prefilledURL: url) }
        }
    }

    private var bottomBar: some View {
        HStack(spacing: 3) {
            ForEach(tabs) { item in
                Button {
                    page = item
                } label: {
                    VStack(spacing: 3) {
                        Image(systemName: item.icon).font(.system(size: 20, weight: .semibold))
                        Text(item.title).font(.system(size: 10, weight: page == item ? .bold : .semibold)).lineLimit(1)
                    }
                    .foregroundStyle(page == item ? FlowPalette.content : FlowPalette.secondary)
                    .frame(maxWidth: .infinity, minHeight: 54)
                    .background(page == item ? FlowPalette.selected : .clear)
                    .clipShape(RoundedRectangle(cornerRadius: 14))
                }
            }
        }
        .padding(3).background(FlowPalette.surface.opacity(0.97))
        .clipShape(RoundedRectangle(cornerRadius: 19)).overlay(RoundedRectangle(cornerRadius: 19).stroke(FlowPalette.outline.opacity(0.7)))
        .shadow(color: .black.opacity(0.16), radius: 10, y: 5)
        .padding(.horizontal, 12).padding(.top, 2).padding(.bottom, 4)
        .background(FlowPalette.background)
    }

    private func showDrawer() { drawerOpen = true }
    private func hideDrawer() { drawerOpen = false }
}

struct DrawerView: View {
    @EnvironmentObject private var store: AppStore
    @Binding var selection: AppPage
    let close: () -> Void

    var body: some View {
        VStack(spacing: 4) {
            HStack(spacing: 10) {
                FlowGetLogo(size: 40)
                VStack(alignment: .leading) { Text("FlowGet").font(.headline); Text("License not synced").font(.caption).foregroundStyle(.secondary) }
                Spacer()
                Button { store.settings.theme = store.settings.theme == .dark ? .light : .dark } label: {
                    Image(systemName: store.settings.theme == .dark ? "sun.max" : "moon")
                }
            }.padding(.vertical, 14)

            ForEach(AppPage.allCases) { page in
                Button {
                    selection = page; close()
                } label: {
                    Label(page.title, systemImage: page.icon)
                        .frame(maxWidth: .infinity, minHeight: 44, alignment: .leading)
                        .padding(.horizontal, 14)
                        .background(selection == page ? FlowPalette.selected : .clear)
                        .clipShape(RoundedRectangle(cornerRadius: 14))
                }.foregroundStyle(selection == page ? FlowPalette.content : FlowPalette.secondary)
            }
            Spacer()
            Button(role: .destructive) { store.logout() } label: {
                Label("Log out", systemImage: "rectangle.portrait.and.arrow.right").frame(maxWidth: .infinity, alignment: .leading)
            }.padding(14)
            FlowCard(content: VStack(alignment: .leading, spacing: 8) {
                Text("Storage").font(.headline)
                Text(DownloadManager.downloadFolder.path).font(.caption).foregroundStyle(.secondary).lineLimit(2)
                ProgressView(value: 0.5).tint(FlowPalette.action)
            }.padding(14))
            Text("FlowGet \(AppConfig.version)").font(.caption2).foregroundStyle(.tertiary).padding(.vertical, 12)
        }
        .padding(.horizontal, 16)
        .background(FlowPalette.surface.ignoresSafeArea())
        .clipShape(.rect(topTrailingRadius: 24, bottomTrailingRadius: 24))
        .shadow(radius: 14)
    }
}
