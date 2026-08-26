import SwiftUI

struct SettingsView: View {
    @EnvironmentObject private var store: AppStore
    @State private var showConcurrent = false
    @State private var showSpeed = false
    let openMenu: () -> Void

    var body: some View {
        VStack(spacing: 0) {
            FlowTopBar(title: "Settings", onMenu: openMenu)
            ScrollView {
                VStack(alignment: .leading, spacing: 20) {
                    FlowSectionTitle(title: "Download")
                    FlowCard(content: VStack(spacing: 0) {
                        row("Download directory", store.settings.downloadDirectory, "folder") {}
                        divider
                        row("Max active downloads", "\(store.settings.maxConcurrent)", "slider.horizontal.3") { showConcurrent = true }
                        divider
                        row("Global speed limit", store.settings.globalSpeedLimitBytes == 0 ? "No limit" : "\(store.settings.globalSpeedLimitBytes.fileSize)/s", "speedometer") { showSpeed = true }
                        divider
                        toggle("Wi-Fi only", "Download only on Wi-Fi", "wifi", value: $store.settings.wifiOnly)
                        divider
                        toggle("Auto retry", "Retry failed downloads", "arrow.clockwise", value: $store.settings.autoRetry)
                        divider
                        toggle("Use mobile data", "Download on mobile data", "cellularbars", value: $store.settings.useMobileData)
                    })
                    FlowSectionTitle(title: "Notifications")
                    FlowCard(content: toggle("Download notifications", "Show download progress", "bell", value: $store.settings.notifications))
                    FlowSectionTitle(title: "Browser privacy")
                    FlowCard(content: VStack(spacing: 0) {
                        toggle("Content blocking", "Block common trackers and ads", "hand.raised", value: $store.settings.contentBlocking)
                        divider
                        toggle("Aggressive blocking", "Use stricter filtering rules", "shield.lefthalf.filled", value: $store.settings.aggressiveBlocking)
                        divider
                        toggle("Block pop-ups", "Prevent unwanted new windows", "rectangle.on.rectangle.slash", value: $store.settings.popupBlocking)
                        divider
                        toggle("Picture in Picture", "Allow supported web video", "pip", value: $store.settings.pictureInPicture)
                    })
                    FlowSectionTitle(title: "Appearance")
                    FlowCard(content: VStack(alignment: .leading, spacing: 14) {
                        Text("Choose how FlowGet looks on this device.").foregroundStyle(.secondary)
                        Picker("Theme", selection: $store.settings.theme) { ForEach(ThemeMode.allCases) { Text($0.title).tag($0) } }.pickerStyle(.segmented)
                    }.padding(16))
                    FlowSectionTitle(title: "About")
                    FlowCard(content: VStack(spacing: 0) {
                        info("Version", AppConfig.version, "info.circle")
                        divider
                        info("Platform", "iOS 17+ • Native Swift", "iphone")
                    })
                }.padding(.horizontal, 18).padding(.bottom, 24)
            }
        }
        .flowPage()
        .confirmationDialog("Max active downloads", isPresented: $showConcurrent) {
            ForEach(1...10, id: \.self) { count in Button("\(count)") { store.settings.maxConcurrent = count } }
        }
        .confirmationDialog("Global speed limit", isPresented: $showSpeed) {
            Button("No limit") { store.settings.globalSpeedLimitBytes = 0 }
            Button("512 KB/s") { store.settings.globalSpeedLimitBytes = 512 * 1024 }
            Button("1 MB/s") { store.settings.globalSpeedLimitBytes = 1024 * 1024 }
            Button("5 MB/s") { store.settings.globalSpeedLimitBytes = 5 * 1024 * 1024 }
        }
    }

    private var divider: some View { Divider().padding(.leading, 70) }
    private func row(_ title: String, _ detail: String, _ icon: String, action: @escaping () -> Void) -> some View {
        Button(action: action) { HStack(spacing: 14) { FlowIcon(name: icon); VStack(alignment: .leading) { Text(title).font(.headline); Text(detail).font(.subheadline).foregroundStyle(.secondary).lineLimit(2) }; Spacer(); Image(systemName: "chevron.right").foregroundStyle(.secondary) }.padding(14) }.foregroundStyle(FlowPalette.content)
    }
    private func toggle(_ title: String, _ detail: String, _ icon: String, value: Binding<Bool>) -> some View {
        HStack(spacing: 14) { FlowIcon(name: icon); VStack(alignment: .leading) { Text(title).font(.headline); Text(detail).font(.subheadline).foregroundStyle(.secondary) }; Spacer(); Toggle("", isOn: value).labelsHidden() }.padding(14)
    }
    private func info(_ title: String, _ detail: String, _ icon: String) -> some View {
        HStack(spacing: 14) { FlowIcon(name: icon); Text(title); Spacer(); Text(detail).font(.subheadline.bold()).multilineTextAlignment(.trailing) }.padding(14)
    }
}
