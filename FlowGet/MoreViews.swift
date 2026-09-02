import Foundation
import SwiftUI

struct ActivityView: View {
    @EnvironmentObject private var store: AppStore
    @State private var filter = 0
    @State private var showAdd = false
    @State private var showClear = false
    let openMenu: () -> Void

    var body: some View {
        VStack(spacing: 0) {
            FlowTopBar(title: "Activity", onMenu: openMenu, trailing: AnyView(
                Menu {
                    Button("Clear activity history", systemImage: "trash", role: .destructive) { showClear = true }
                    Button("Refresh", systemImage: "arrow.clockwise") {}
                } label: {
                    Image(systemName: "ellipsis").font(.system(size: 21, weight: .semibold)).rotationEffect(.degrees(90)).frame(width: 42, height: 42)
                }
            ))
            FlowTabs(labels: ["All", "Transfers", "System"], selection: $filter)
                .padding(.horizontal, 16).padding(.bottom, 10)
            if visible.isEmpty {
                VStack {
                    Spacer()
                    FlowEmptyState(image: "ActivityEmpty", title: "No activity recorded yet", message: "Your download history and file transfer activity will appear here.")
                    Spacer()
                }
            } else {
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 10) {
                        ForEach(groupedDates) { group in
                            Text(group.title).font(.flowBodySmall.weight(.semibold)).padding(.top, 8)
                            FlowCard(content: VStack(spacing: 0) {
                                ForEach(Array(group.items.enumerated()), id: \.element.id) { index, item in
                                    activityRow(item, last: index == group.items.count - 1)
                                }
                            }, elevated: true)
                        }
                    }.padding(.horizontal, 16).padding(.bottom, 86)
                }.scrollIndicators(.hidden)
            }
        }
        .overlay(alignment: .bottomTrailing) {
            Button { showAdd = true } label: {
                Image(systemName: "plus").font(.system(size: 22, weight: .bold)).foregroundStyle(FlowPalette.onAction)
                    .frame(width: 56, height: 56).background(FlowPalette.action).clipShape(Circle()).shadow(color: .black.opacity(0.18), radius: 7, y: 4)
            }.buttonStyle(FlowPressButtonStyle()).padding(20)
        }
        .flowPage()
        .sheet(isPresented: $showAdd) { AddDownloadView().presentationDragIndicator(.visible) }
        .alert("Clear Activity History?", isPresented: $showClear) {
            Button("Cancel", role: .cancel) {}
            Button("Clear History", role: .destructive) { store.activity.removeAll() }
        } message: { Text("This removes all activity records from this view.") }
    }

    private var visible: [ActivityItem] {
        store.activity.filter { filter == 0 || (filter == 1 && $0.kind == .transfer) || (filter == 2 && $0.kind == .system) }
    }

    private var groupedDates: [ActivityDateGroup] {
        let grouped = Dictionary(grouping: visible) { Calendar.current.startOfDay(for: $0.date) }
        return grouped.keys.sorted(by: >).map { date in
            let title = Calendar.current.isDateInToday(date) ? "Today" : date.formatted(date: .abbreviated, time: .omitted)
            return ActivityDateGroup(day: date, title: title, items: grouped[date, default: []].sorted { $0.date > $1.date })
        }
    }

    private func activityRow(_ item: ActivityItem, last: Bool) -> some View {
        HStack(alignment: .top, spacing: 12) {
            VStack(spacing: 0) {
                Image(systemName: item.succeeded ? "checkmark" : "xmark")
                    .font(.system(size: 13, weight: .bold)).foregroundStyle(item.succeeded ? FlowPalette.success : FlowPalette.danger)
                    .frame(width: 28, height: 28)
                    .background((item.succeeded ? FlowPalette.success : FlowPalette.danger).opacity(0.1)).clipShape(Circle())
                    .overlay(Circle().stroke(item.succeeded ? FlowPalette.success : FlowPalette.danger, lineWidth: 1.2))
                if !last { Rectangle().fill(FlowPalette.outline).frame(width: 1, height: 34) }
            }.padding(.top, 14)
            VStack(alignment: .leading, spacing: 4) {
                Text(item.title).font(.flowBodySmall.weight(.bold)).lineLimit(1)
                Text(item.detail).font(.flowLabel).foregroundStyle(FlowPalette.secondary).lineLimit(1)
            }.padding(.top, 14)
            Spacer()
            Text(item.date.formatted(date: .omitted, time: .shortened)).font(.flowLabel).foregroundStyle(FlowPalette.secondary).padding(.top, 16)
        }
        .padding(.horizontal, 14).frame(height: 76)
    }
}

private struct ActivityDateGroup: Identifiable {
    let day: Date
    let title: String
    let items: [ActivityItem]
    var id: Date { day }
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
            FlowTopBar(title: "Schedule", onMenu: openMenu)
            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    FlowCard(content: HStack(spacing: 14) {
                        FlowIcon(name: "alarm", emphasized: true, size: 52)
                        VStack(alignment: .leading, spacing: 5) {
                            Text("Smart scheduling").font(.flowTitle)
                            Text("Run queued downloads at the best time.").font(.flowCaption).foregroundStyle(FlowPalette.secondary)
                        }
                        Spacer()
                        FlowStatusBadge(title: "\(store.schedules.filter { $0.enabled }.count) enabled")
                    }.padding(18), elevated: true)

                    FlowSectionTitle(title: "Upcoming", count: store.schedules.count)
                    if store.schedules.isEmpty {
                        FlowCard(content: Text("No schedules yet. Tap + to add one.").font(.flowBodySmall).foregroundStyle(FlowPalette.secondary).padding(22))
                    }
                    ForEach($store.schedules) { $schedule in scheduleCard($schedule) }
                    FlowSectionTitle(title: "Quiet hours")
                    FlowCard(content: HStack(spacing: 12) {
                        FlowIcon(name: "moon")
                        VStack(alignment: .leading, spacing: 3) {
                            Text("Download window").font(.flowTitleSmall)
                            Text("Any time").font(.flowCaption).foregroundStyle(FlowPalette.secondary)
                        }
                        Spacer(); Image(systemName: "chevron.right").foregroundStyle(FlowPalette.tertiary)
                    }.padding(16))
                }.padding(.horizontal, 16).padding(.top, 12).padding(.bottom, 28)
            }.scrollIndicators(.hidden)
        }
        .overlay(alignment: .bottomTrailing) {
            Button { showEditor = true } label: {
                Image(systemName: "calendar.badge.plus").font(.system(size: 21, weight: .semibold)).foregroundStyle(FlowPalette.onAction)
                    .frame(width: 56, height: 56).background(FlowPalette.action).clipShape(Circle()).shadow(color: .black.opacity(0.18), radius: 7, y: 4)
            }.buttonStyle(FlowPressButtonStyle()).padding(20)
        }
        .flowPage()
        .sheet(isPresented: $showEditor) { editorSheet.presentationDetents([.medium]).presentationDragIndicator(.visible) }
    }

    private func scheduleCard(_ schedule: Binding<DownloadSchedule>) -> some View {
        let value = schedule.wrappedValue
        return FlowCard(content: HStack(spacing: 14) {
            VStack(spacing: 4) {
                Image(systemName: "alarm").font(.system(size: 18, weight: .medium))
                Text(String(format: "%d:%02d", value.hour, value.minute)).font(.flowLabel)
            }.frame(width: 58, height: 58).background(value.enabled ? FlowPalette.selected : FlowPalette.inset).clipShape(RoundedRectangle(cornerRadius: 14))
            VStack(alignment: .leading, spacing: 4) {
                Text(value.title).font(.flowTitleSmall)
                Text("\(value.wifiOnly ? "Wi-Fi only" : "Any network") • Every day").font(.flowCaption).foregroundStyle(FlowPalette.secondary)
            }
            Spacer()
            Button(role: .destructive) { store.schedules.removeAll { $0.id == value.id } } label: { Image(systemName: "trash") }.buttonStyle(.plain)
            Toggle("", isOn: schedule.enabled).labelsHidden().toggleStyle(FlowSwitchToggleStyle())
        }.padding(16), elevated: value.enabled)
    }

    private var editorSheet: some View {
        NavigationStack {
            Form {
                TextField("Name", text: $title)
                DatePicker("Start time", selection: $time, displayedComponents: .hourAndMinute)
                Toggle("Wi-Fi only", isOn: $wifiOnly)
            }
            .navigationTitle("Add schedule").navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { showEditor = false } }
                ToolbarItem(placement: .confirmationAction) { Button("Save", action: saveSchedule) }
            }
        }
    }

    private func saveSchedule() {
        let parts = Calendar.current.dateComponents([.hour, .minute], from: time)
        store.schedules.append(DownloadSchedule(title: title, hour: parts.hour ?? 22, minute: parts.minute ?? 0, wifiOnly: wifiOnly))
        showEditor = false
    }
}

struct LicenseView: View {
    @EnvironmentObject private var store: AppStore
    let openMenu: () -> Void

    var body: some View {
        VStack(spacing: 0) {
            FlowTopBar(title: "License", onMenu: openMenu)
            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    VStack(alignment: .leading, spacing: 18) {
                        HStack(spacing: 12) {
                            Image(systemName: "checkmark.seal").font(.system(size: 30, weight: .medium))
                            VStack(alignment: .leading, spacing: 2) {
                                Text("License not synced").font(.flowTitleLarge)
                                Text(store.account?.email ?? "Signed out").font(.flowCaption).opacity(0.72)
                            }
                            Spacer(); FlowStatusBadge(title: "Free", color: FlowPalette.onAction)
                        }
                        Text("FlowGet will verify Mobile access when the native iOS licensing contract is available.").font(.flowBodySmall).opacity(0.78)
                    }
                    .foregroundStyle(FlowPalette.onAction).padding(22).background(FlowPalette.action).clipShape(RoundedRectangle(cornerRadius: 24))

                    FlowSectionTitle(title: "License details")
                    FlowCard(content: VStack(spacing: 0) {
                        info("Plan", "No active paid plan", "checkmark.seal")
                        Divider().padding(.leading, 70)
                        info("Device", "This iPhone", "iphone")
                        Divider().padding(.leading, 70)
                        info("Access expiry", "Not applicable", "calendar")
                    }, elevated: true)
                    FlowOutlineButton(title: "Refresh licensing", icon: "arrow.clockwise") {}
                }.padding(.horizontal, 16).padding(.top, 12).padding(.bottom, 28)
            }.scrollIndicators(.hidden)
        }.flowPage()
    }

    private func info(_ title: String, _ value: String, _ icon: String) -> some View {
        HStack(spacing: 14) { FlowIcon(name: icon); Text(title).font(.flowTitleSmall); Spacer(); Text(value).font(.flowCaption).foregroundStyle(FlowPalette.secondary).multilineTextAlignment(.trailing) }
            .padding(14)
    }
}

struct AboutView: View {
    @Environment(\.openURL) private var openURL
    let openMenu: () -> Void

    var body: some View {
        VStack(spacing: 0) {
            FlowTopBar(title: "About", onMenu: openMenu)
            ScrollView {
                VStack(spacing: 14) {
                    VStack(spacing: 10) {
                        FlowGetLogo(size: 64).padding(20).background(FlowPalette.inset).clipShape(Circle())
                        Text("FlowGet").font(.flowHeadline)
                        Text("Fast downloads. Smart transfer.").font(.flowBodySmall).foregroundStyle(FlowPalette.secondary)
                        FlowStatusBadge(title: "Version \(AppConfig.version)", color: FlowPalette.secondary)
                    }.padding(.vertical, 18)
                    FlowCard(content: VStack(spacing: 0) {
                        link("FlowGet website", "globe", AppConfig.authBaseURL)
                        Divider().padding(.leading, 70)
                        link("Help and support", "questionmark.circle", AppConfig.contactURL)
                        Divider().padding(.leading, 70)
                        link("Privacy policy", "hand.raised", AppConfig.privacyURL)
                    }, elevated: true)
                    FlowCard(content: HStack(spacing: 14) {
                        FlowIcon(name: "shield")
                        VStack(alignment: .leading, spacing: 3) {
                            Text("Core engine").font(.flowTitleSmall)
                            Text("Native Swift / SwiftUI").font(.flowCaption).foregroundStyle(FlowPalette.secondary)
                        }; Spacer()
                    }.padding(14), elevated: true)
                    Text("Designed for fast, calm, and reliable transfers.").font(.flowCaption).foregroundStyle(FlowPalette.tertiary).padding(18)
                }.padding(.horizontal, 16)
            }.scrollIndicators(.hidden)
        }.flowPage()
    }

    private func link(_ title: String, _ icon: String, _ url: URL) -> some View {
        Button { openURL(url) } label: {
            HStack(spacing: 14) { FlowIcon(name: icon); Text(title).font(.flowTitleSmall); Spacer(); Image(systemName: "arrow.right").foregroundStyle(FlowPalette.tertiary) }.padding(14)
        }.buttonStyle(.plain)
    }
}
