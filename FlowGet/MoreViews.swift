import SwiftUI

struct ActivityView: View {
    @EnvironmentObject private var store: AppStore
    @State private var filter = 0
    let openMenu: () -> Void
    var body: some View {
        VStack(spacing: 0) {
            FlowTopBar(title: "Activity", onMenu: openMenu, trailing: AnyView(Menu { Button("Clear history", role: .destructive) { store.activity.removeAll() } } label: { Image(systemName: "ellipsis").font(.title2) }))
            Picker("Activity", selection: $filter) { Text("All").tag(0); Text("Transfers").tag(1); Text("System").tag(2) }.pickerStyle(.segmented).padding(.horizontal, 18)
            if visible.isEmpty {
                VStack(spacing: 14) { Spacer(); Image(systemName: "clock.arrow.circlepath").font(.system(size: 60)).foregroundStyle(.tertiary); Text("No activity yet").font(.title2.bold()); Text("Downloads and transfers will appear here.").foregroundStyle(.secondary); Spacer() }
            } else {
                ScrollView { LazyVStack(spacing: 12) { ForEach(visible) { item in FlowCard(content: HStack(spacing: 14) { FlowIcon(name: item.kind == .download ? "arrow.down" : item.kind == .transfer ? "arrow.left.arrow.right" : "gearshape"); VStack(alignment: .leading) { Text(item.title).font(.headline); Text(item.detail).font(.subheadline).foregroundStyle(.secondary); Text(item.date.formatted(date: .abbreviated, time: .shortened)).font(.caption).foregroundStyle(.tertiary) }; Spacer(); Image(systemName: item.succeeded ? "checkmark.circle.fill" : "xmark.circle.fill").foregroundStyle(item.succeeded ? FlowPalette.success : FlowPalette.danger) }.padding(14)) } }.padding(18) }
            }
        }.flowPage()
    }
    private var visible: [ActivityItem] { store.activity.filter { filter == 0 || (filter == 1 && $0.kind == .transfer) || (filter == 2 && $0.kind == .system) } }
}

struct ScheduleView: View {
    @EnvironmentObject private var store: AppStore
    @State private var showEditor = false
    @State private var title = "Scheduled downloads"
    @State private var time = Date()
    @State private var wifiOnly = true
    let openMenu: () -> Void
    var body: some View {
        VStack(spacing: 0) {
            FlowTopBar(title: "Schedule", onMenu: openMenu, trailing: AnyView(Button { showEditor = true } label: { Image(systemName: "plus").font(.title2.bold()) }))
            ScrollView { VStack(alignment: .leading, spacing: 18) {
                FlowCard(content: HStack(spacing: 14) { FlowIcon(name: "alarm", emphasized: true); VStack(alignment: .leading) { Text("Smart scheduling").font(.headline); Text("Run queued downloads at the best time.").font(.subheadline).foregroundStyle(.secondary) }; Spacer(); Text("\(store.schedules.filter { $0.enabled }.count) enabled").font(.caption.bold()).padding(8).background(FlowPalette.inset).clipShape(Capsule()) }.padding(16))
                FlowSectionTitle(title: "Upcoming")
                if store.schedules.isEmpty { FlowCard(content: Text("No schedules yet. Tap + to add one.").foregroundStyle(.secondary).padding(22)) }
                ForEach($store.schedules) { $schedule in
                    FlowCard(content: HStack(spacing: 14) { FlowIcon(name: "alarm"); VStack(alignment: .leading) { Text(schedule.title).font(.headline); Text(String(format: "%d:%02d • %@", schedule.hour, schedule.minute, schedule.wifiOnly ? "Wi-Fi only" : "Any network")).font(.caption).foregroundStyle(.secondary) }; Spacer(); Toggle("", isOn: $schedule.enabled).labelsHidden(); Button(role: .destructive) { store.schedules.removeAll { $0.id == schedule.id } } label: { Image(systemName: "trash") } }.padding(14))
                }
            }.padding(18) }
        }.flowPage().sheet(isPresented: $showEditor) {
            NavigationStack { Form { TextField("Name", text: $title); DatePicker("Start time", selection: $time, displayedComponents: .hourAndMinute); Toggle("Wi-Fi only", isOn: $wifiOnly) }.navigationTitle("Add schedule").toolbar { ToolbarItem(placement: .cancellationAction) { Button("Cancel") { showEditor = false } }; ToolbarItem(placement: .confirmationAction) { Button("Save") { let parts = Calendar.current.dateComponents([.hour, .minute], from: time); store.schedules.append(DownloadSchedule(title: title, hour: parts.hour ?? 22, minute: parts.minute ?? 0, wifiOnly: wifiOnly)); showEditor = false } } } }
        }
    }
}

struct LicenseView: View {
    let openMenu: () -> Void
    var body: some View {
        VStack(spacing: 0) { FlowTopBar(title: "License", onMenu: openMenu); ScrollView { VStack(alignment: .leading, spacing: 18) {
            FlowCard(content: VStack(spacing: 14) { Image(systemName: "checkmark.seal").font(.system(size: 52)); Text("License status").font(.title2.bold()); Text("Not synced").foregroundStyle(.secondary); Text("Licensing activates after the FlowGet backend registers the iOS native client and device-attestation contract.").font(.subheadline).multilineTextAlignment(.center).foregroundStyle(.secondary) }.frame(maxWidth: .infinity).padding(24))
            FlowSectionTitle(title: "Included")
            FlowCard(content: VStack(spacing: 0) { feature("Priority download performance", "speedometer"); Divider().padding(.leading, 68); feature("FlowShare device synchronization", "arrow.triangle.2.circlepath"); Divider().padding(.leading, 68); feature("Secure transfer controls", "lock.shield") })
        }.padding(18) } }.flowPage()
    }
    private func feature(_ title: String, _ icon: String) -> some View { HStack(spacing: 14) { FlowIcon(name: icon); Text(title).font(.headline); Spacer(); Image(systemName: "checkmark.circle.fill").foregroundStyle(FlowPalette.success) }.padding(14) }
}

struct AboutView: View {
    @Environment(\.openURL) private var openURL
    let openMenu: () -> Void
    var body: some View {
        VStack(spacing: 0) { FlowTopBar(title: "About", onMenu: openMenu); ScrollView { VStack(spacing: 18) {
            VStack(spacing: 12) { FlowGetLogo(size: 72); Text("FlowGet").font(.largeTitle.bold()); Text("Fast downloads. Smart transfer.").foregroundStyle(.secondary); Text("Version \(AppConfig.version)").font(.caption.bold()).padding(8).background(FlowPalette.inset).clipShape(Capsule()) }.padding(.vertical, 20)
            FlowCard(content: VStack(spacing: 0) { link("FlowGet website", "globe", AppConfig.authBaseURL); Divider().padding(.leading, 68); link("Help and support", "questionmark.circle", AppConfig.contactURL); Divider().padding(.leading, 68); link("Privacy policy", "hand.raised", AppConfig.privacyURL) })
            FlowCard(content: HStack(spacing: 14) { FlowIcon(name: "swift"); VStack(alignment: .leading) { Text("Core app").font(.headline); Text("Native Swift / SwiftUI").font(.subheadline).foregroundStyle(.secondary) }; Spacer() }.padding(14))
            Text("Designed for fast, calm, and reliable transfers.").font(.caption).foregroundStyle(.tertiary).padding(18)
        }.padding(18) } }.flowPage()
    }
    private func link(_ title: String, _ icon: String, _ url: URL) -> some View { Button { openURL(url) } label: { HStack(spacing: 14) { FlowIcon(name: icon); Text(title).font(.headline); Spacer(); Image(systemName: "arrow.right").foregroundStyle(.secondary) }.padding(14) }.foregroundStyle(FlowPalette.content) }
}
