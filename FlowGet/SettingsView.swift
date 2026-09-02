import SwiftUI
import UserNotifications

struct SettingsView: View {
    @EnvironmentObject private var store: AppStore
    @State private var showConcurrent = false
    @State private var showSpeed = false
    @State private var showDirectoryInfo = false
    @State private var confirmWiFiOnly = false
    let onBack: () -> Void

    var body: some View {
        VStack(spacing: 0) {
            FlowTopBar(title: "Settings", onMenu: onBack, leadingIcon: "chevron.left", trailing: AnyView(
                Menu {
                    Button("Reset download settings", systemImage: "arrow.counterclockwise") { resetDownloadSettings() }
                } label: {
                    Image(systemName: "ellipsis").font(.system(size: 21, weight: .semibold)).rotationEffect(.degrees(90)).frame(width: 42, height: 42)
                }
            ))
            ScrollView {
                VStack(alignment: .leading, spacing: 10) {
                    section("Download") {
                        VStack(spacing: 0) {
                            navigationRow("Download directory", store.settings.downloadDirectory, "folder") { showDirectoryInfo = true }
                            divider
                            navigationRow("Max active downloads", "\(store.settings.maxConcurrent) active downloads", "slider.horizontal.3") { showConcurrent = true }
                            divider
                            navigationRow("Global speed limit", speedLabel, "speedometer") { showSpeed = true }
                            divider
                            settingToggle("Wi-Fi only", "Download only on Wi-Fi", "wifi", value: Binding(
                                get: { store.settings.wifiOnly },
                                set: { value in
                                    if value { confirmWiFiOnly = true }
                                    else { store.settings.wifiOnly = false }
                                }
                            ))
                            divider
                            settingToggle("Auto retry", "Retry failed downloads", "arrow.clockwise", value: $store.settings.autoRetry)
                            divider
                            settingToggle("Use mobile data", "Download on mobile data", "cellularbars", value: $store.settings.useMobileData)
                        }
                    }

                    section("Notifications") {
                        settingToggle("Download notifications", "Show progress in Notification Center", "bell", value: $store.settings.notifications)
                    }

                    section("Privacy & media") {
                        VStack(spacing: 0) {
                            settingToggle("Block ads & trackers", "Reduce advertising and cross-site tracking", "shield", value: $store.settings.contentBlocking)
                            divider
                            navigationRow("Content blocking", store.settings.aggressiveBlocking ? "Aggressive" : "Standard", "slider.horizontal.3") {
                                store.settings.aggressiveBlocking.toggle()
                            }
                            divider
                            settingToggle("Block pop-ups", "Prevent unwanted windows and redirects", "nosign", value: $store.settings.popupBlocking)
                            divider
                            settingToggle("Background playback", "Keep webpage media playing outside the browser", "play.circle", value: $store.settings.backgroundPlayback)
                            divider
                            settingToggle("Picture-in-picture", "Continue supported video in a floating window", "pip", value: $store.settings.pictureInPicture)
                        }
                    }

                    section("Appearance") {
                        VStack(alignment: .leading, spacing: 10) {
                            Text("Choose how FlowGet looks on this device.")
                                .font(.flowBodySmall).foregroundStyle(FlowPalette.secondary)
                            FlowTabs(labels: ThemeMode.allCases.map(\.title), selection: themeSelection)
                        }
                        .padding(14)
                    }

                    section("About") {
                        VStack(spacing: 0) {
                            infoRow("Version", AppConfig.version, "info.circle")
                            divider
                            infoRow("Platform", "iOS 17+ • Native Swift", "iphone")
                        }
                    }
                }
                .padding(.horizontal, 16)
                .padding(.top, 14)
                .padding(.bottom, 28)
            }
            .scrollIndicators(.hidden)
        }
        .flowPage()
        .confirmationDialog("Max active downloads", isPresented: $showConcurrent, titleVisibility: .visible) {
            ForEach(1...5, id: \.self) { count in
                Button("\(count) active download\(count == 1 ? "" : "s")") { store.settings.maxConcurrent = count }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("Choose how many downloads FlowGet can run at the same time.")
        }
        .confirmationDialog("Global speed limit", isPresented: $showSpeed, titleVisibility: .visible) {
            Button("No limit") { store.settings.globalSpeedLimitBytes = 0 }
            Button("512 KB/s") { store.settings.globalSpeedLimitBytes = 512 * 1024 }
            Button("1 MB/s") { store.settings.globalSpeedLimitBytes = 1024 * 1024 }
            Button("5 MB/s") { store.settings.globalSpeedLimitBytes = 5 * 1024 * 1024 }
            Button("Cancel", role: .cancel) {}
        }
        .alert("FlowGet download folder", isPresented: $showDirectoryInfo) {
            Button("OK", role: .cancel) {}
        } message: {
            Text("iOS securely stores downloads in Files › On My iPhone › FlowGet. Use each completed download's menu to open or share it.")
        }
        .alert("Enable Wi-Fi Only?", isPresented: $confirmWiFiOnly) {
            Button("Cancel", role: .cancel) {}
            Button("Enable") { store.settings.wifiOnly = true }
        } message: {
            Text("FlowGet will pause new downloads when Wi-Fi is unavailable instead of using cellular data.")
        }
        .onChange(of: store.settings.notifications) { _, enabled in
            if enabled {
                UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound, .badge]) { _, _ in }
            }
        }
    }

    private var divider: some View {
        Divider().overlay(FlowPalette.outline).padding(.leading, 70)
    }

    private var speedLabel: String {
        store.settings.globalSpeedLimitBytes == 0 ? "No limit" : "\(store.settings.globalSpeedLimitBytes.fileSize)/s"
    }

    private var themeSelection: Binding<Int> {
        Binding(
            get: { ThemeMode.allCases.firstIndex(of: store.settings.theme) ?? 0 },
            set: { store.settings.theme = ThemeMode.allCases[$0] }
        )
    }

    private func section<Content: View>(_ title: String, @ViewBuilder content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(title).font(.flowTitleLarge).padding(.top, 8)
            FlowCard(content: content(), elevated: true)
        }
    }

    private func navigationRow(_ title: String, _ detail: String, _ icon: String, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            HStack(spacing: 14) {
                FlowIcon(name: icon)
                VStack(alignment: .leading, spacing: 3) {
                    Text(title).font(.flowTitle)
                    Text(detail).font(.flowBodySmall).foregroundStyle(FlowPalette.secondary).lineLimit(2)
                }
                Spacer(minLength: 8)
                Image(systemName: "chevron.right").font(.system(size: 14, weight: .bold)).foregroundStyle(FlowPalette.tertiary)
            }
            .padding(.horizontal, 14).frame(minHeight: 72)
        }
        .buttonStyle(.plain)
    }

    private func settingToggle(_ title: String, _ detail: String, _ icon: String, value: Binding<Bool>) -> some View {
        HStack(spacing: 14) {
            FlowIcon(name: icon)
            VStack(alignment: .leading, spacing: 3) {
                Text(title).font(.flowTitle)
                Text(detail).font(.flowBodySmall).foregroundStyle(FlowPalette.secondary).fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 8)
            Toggle("", isOn: value).labelsHidden().toggleStyle(FlowSwitchToggleStyle())
        }
        .padding(.horizontal, 14).frame(minHeight: 72)
    }

    private func infoRow(_ title: String, _ detail: String, _ icon: String) -> some View {
        HStack(spacing: 14) {
            FlowIcon(name: icon)
            Text(title).font(.flowTitle)
            Spacer()
            Text(detail).font(.flowBodySmall.weight(.medium)).foregroundStyle(FlowPalette.secondary).multilineTextAlignment(.trailing)
        }
        .padding(.horizontal, 14).frame(minHeight: 70)
    }

    private func resetDownloadSettings() {
        store.settings.maxConcurrent = 3
        store.settings.globalSpeedLimitBytes = 0
        store.settings.wifiOnly = false
        store.settings.autoRetry = true
        store.settings.useMobileData = true
    }
}
