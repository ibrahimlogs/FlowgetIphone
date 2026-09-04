import Foundation
import SwiftUI

enum AppPage: String, CaseIterable, Identifiable {
    case downloads, flowShare, browser, settings, activity, schedule, license, about

    var id: String { rawValue }
    var title: String {
        switch self {
        case .flowShare: "FlowShare"
        default: rawValue.capitalized
        }
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
    @State private var dragOffset: CGFloat = 0
    private let tabs: [AppPage] = [.downloads, .flowShare, .browser, .settings]

    var body: some View {
        GeometryReader { proxy in
            ZStack(alignment: .leading) {
                currentPage
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                    .safeAreaInset(edge: .bottom, spacing: 0) { bottomBar }
                    .disabled(drawerOpen)
                    .accessibilityHidden(drawerOpen)

                if drawerOpen {
                    Color.black.opacity(0.68)
                        .ignoresSafeArea()
                        .onTapGesture { hideDrawer() }
                        .transition(.opacity)

                    DrawerView(selection: $page, close: hideDrawer)
                        .frame(width: min(300, proxy.size.width * 0.84))
                        .offset(x: min(0, dragOffset))
                        .transition(.move(edge: .leading))
                        .gesture(
                            DragGesture(minimumDistance: 12)
                                .onChanged { dragOffset = min(0, $0.translation.width) }
                                .onEnded {
                                    if $0.translation.width < -70 { hideDrawer() }
                                    else { withAnimation(FlowMotion.standard) { dragOffset = 0 } }
                                }
                        )
                }
            }
            .contentShape(Rectangle())
            .simultaneousGesture(
                DragGesture(minimumDistance: 18)
                    .onEnded { value in
                        if !drawerOpen, value.startLocation.x < 22, value.translation.width > 75 {
                            showDrawer()
                        }
                    }
            )
        }
        .animation(FlowMotion.standard, value: drawerOpen)
        .sheet(isPresented: Binding(
            get: { store.incomingURL != nil },
            set: { if !$0 { store.incomingURL = nil } }
        )) {
            if let url = store.incomingURL { AddDownloadView(prefilledURL: url) }
        }
    }

    @ViewBuilder private var currentPage: some View {
        switch page {
        case .downloads: DownloadsView(openMenu: showDrawer)
        case .flowShare: FlowShareView(flowShare: store.flowShare, openMenu: showDrawer)
        case .browser: BrowserHomeView(openMenu: showDrawer)
        case .settings: SettingsView(onBack: { withAnimation(FlowMotion.standard) { page = .downloads } })
        case .activity: ActivityView(openMenu: showDrawer)
        case .schedule: ScheduleView(openMenu: showDrawer)
        case .license: LicenseView(openMenu: showDrawer)
        case .about: AboutView(openMenu: showDrawer)
        }
    }

    private var bottomBar: some View {
        HStack(spacing: 3) {
            ForEach(tabs) { item in
                Button {
                    withAnimation(FlowMotion.standard) { page = item }
                } label: {
                    VStack(spacing: 3) {
                        Image(systemName: item.icon)
                            .font(.system(size: page == item ? 22 : 20, weight: .semibold))
                        Text(item.title)
                            .font(page == item ? .flowLabel.weight(.bold) : .flowLabel)
                            .lineLimit(1)
                            .minimumScaleFactor(0.85)
                    }
                    .foregroundStyle(page == item ? FlowPalette.content : FlowPalette.tertiary)
                    .frame(maxWidth: .infinity, minHeight: 56)
                    .background(page == item ? FlowPalette.selected : .clear)
                    .clipShape(RoundedRectangle(cornerRadius: 15, style: .continuous))
                }
                .buttonStyle(FlowPressButtonStyle())
                .accessibilityAddTraits(page == item ? .isSelected : [])
            }
        }
        .padding(3)
        .frame(height: 62)
        .background(.ultraThinMaterial)
        .background(FlowPalette.surface.opacity(0.92))
        .clipShape(RoundedRectangle(cornerRadius: 18, style: .continuous))
        .overlay {
            RoundedRectangle(cornerRadius: 18, style: .continuous)
                .stroke(FlowPalette.outline.opacity(0.65), lineWidth: 0.75)
        }
        .shadow(color: .black.opacity(0.16), radius: 10, y: 5)
        .padding(.horizontal, 12)
        .padding(.vertical, 4)
        .background(FlowPalette.background)
    }

    private func showDrawer() {
        dragOffset = 0
        drawerOpen = true
    }

    private func hideDrawer() {
        drawerOpen = false
        dragOffset = 0
    }
}

struct DrawerView: View {
    @EnvironmentObject private var store: AppStore
    @Binding var selection: AppPage
    let close: () -> Void

    var body: some View {
        VStack(spacing: 0) {
            header
            Spacer().frame(height: 10)
            VStack(spacing: 2) {
                ForEach(AppPage.allCases) { page in
                    Button {
                        selection = page
                        close()
                    } label: {
                        HStack(spacing: 16) {
                            Image(systemName: page.icon)
                                .font(.system(size: 20, weight: .medium))
                                .frame(width: 22)
                            Text(page.title).font(selection == page ? .flowTitle : .flowBodySmall.weight(.medium))
                            Spacer()
                        }
                        .foregroundStyle(selection == page ? FlowPalette.content : FlowPalette.secondary)
                        .padding(.horizontal, 14)
                        .frame(height: 46)
                        .background(selection == page ? FlowPalette.selected : .clear)
                        .clipShape(RoundedRectangle(cornerRadius: FlowRadius.medium, style: .continuous))
                    }
                    .buttonStyle(.plain)
                }
            }
            Spacer(minLength: 10)
            Button(role: .destructive) { store.logout() } label: {
                HStack(spacing: 16) {
                    Image(systemName: "rectangle.portrait.and.arrow.right").frame(width: 22)
                    Text("Log out").font(.flowBodySmall.weight(.medium))
                    Spacer()
                }
                .foregroundStyle(FlowPalette.secondary)
                .padding(.horizontal, 14)
                .frame(height: 46)
            }
            .buttonStyle(.plain)
            storageCard
            Text("FlowGet \(AppConfig.version)")
                .font(.flowLabelSmall)
                .foregroundStyle(FlowPalette.tertiary)
                .padding(.vertical, 14)
        }
        .padding(.horizontal, 16)
        .background(FlowPalette.elevated.ignoresSafeArea())
        .clipShape(.rect(bottomTrailingRadius: 24, topTrailingRadius: 24))
        .shadow(color: .black.opacity(0.2), radius: 16, x: 5)
    }

    private var header: some View {
        HStack(spacing: 8) {
            Button {
                selection = .about
                close()
            } label: {
                HStack(spacing: 8) {
                    FlowGetLogo(size: 44)
                    VStack(alignment: .leading, spacing: 2) {
                        Text("FlowGet").font(.flowTitle)
                        Text(store.account == nil ? "License not synced" : store.license.title)
                            .font(.flowLabel)
                            .foregroundStyle(FlowPalette.secondary)
                    }
                }
            }
            .buttonStyle(.plain)
            Spacer()
            Button {
                store.settings.theme = store.settings.theme == .dark ? .light : .dark
            } label: {
                Image(systemName: store.settings.theme == .dark ? "sun.max" : "moon")
                    .font(.system(size: 20, weight: .medium))
                    .frame(width: 42, height: 42)
            }
            .buttonStyle(.plain)
            .accessibilityLabel("Switch appearance")
        }
        .frame(height: 72)
    }

    private var storageCard: some View {
        FlowCard(content: VStack(alignment: .leading, spacing: 10) {
            Text("Storage").font(.flowTitleSmall)
            HStack {
                Text(storage.free).font(.flowLabel)
                Spacer()
                Text("/ \(storage.total)").font(.flowLabel).foregroundStyle(FlowPalette.secondary)
            }
            FlowProgressBar(value: storage.usedFraction)
        }.padding(.horizontal, 16).padding(.vertical, 14))
    }

    private var storage: (free: String, total: String, usedFraction: Double) {
        let values = try? FileManager.default.attributesOfFileSystem(forPath: NSHomeDirectory())
        let free = (values?[.systemFreeSize] as? NSNumber)?.int64Value ?? 0
        let total = (values?[.systemSize] as? NSNumber)?.int64Value ?? 0
        let used = max(0, total - free)
        return (
            ByteCountFormatter.string(fromByteCount: free, countStyle: .file) + " free",
            ByteCountFormatter.string(fromByteCount: total, countStyle: .file),
            total > 0 ? Double(used) / Double(total) : 0
        )
    }
}
