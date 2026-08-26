import SwiftUI
import UniformTypeIdentifiers

struct DownloadsView: View {
    @EnvironmentObject private var store: AppStore
    @State private var filter = 0
    @State private var search = ""
    @State private var showSearch = false
    @State private var showAdd = false
    @State private var itemsVersion = 0

    let openMenu: () -> Void
    private var manager: DownloadManager { store.downloads }

    var body: some View {
        ZStack(alignment: .bottomTrailing) {
            VStack(spacing: 0) {
                FlowTopBar(title: "Downloads", onMenu: openMenu, trailing: AnyView(
                    Button { withAnimation { showSearch.toggle() } } label: { Image(systemName: "magnifyingglass").font(.title2.bold()) }
                ))
                if showSearch {
                    HStack { Image(systemName: "magnifyingglass"); TextField("Search files", text: $search); Button { search = "" } label: { Image(systemName: "xmark.circle.fill") } }
                        .padding(.horizontal, 14).frame(height: 46).background(FlowPalette.surface)
                        .clipShape(RoundedRectangle(cornerRadius: 14)).overlay(RoundedRectangle(cornerRadius: 14).stroke(FlowPalette.outline))
                        .padding(.horizontal, 18).padding(.bottom, 10)
                }
                Picker("Filter", selection: $filter) {
                    Text("All \(manager.items.count)").tag(0)
                    Text("Active \(manager.items.filter { !$0.status.isTerminal }.count)").tag(1)
                    Text("Completed \(manager.items.filter { $0.status == .completed }.count)").tag(2)
                }
                .pickerStyle(.segmented).padding(.horizontal, 18).padding(.bottom, 12)

                if visibleItems.isEmpty {
                    VStack(spacing: 14) {
                        Spacer()
                        Image(systemName: "arrow.down.doc").font(.system(size: 58)).foregroundStyle(.tertiary)
                        Text("No downloads yet").font(.title2.bold())
                        Text("Share a link to FlowGet or add a URL to get started.").multilineTextAlignment(.center).foregroundStyle(.secondary)
                        Spacer()
                    }.padding(40)
                } else {
                    ScrollView {
                        LazyVStack(alignment: .leading, spacing: 12) {
                            ForEach(sectioned, id: \.0) { title, values in
                                if !values.isEmpty {
                                    HStack { Text(title).font(.title3.bold()); Text("\(values.count)").font(.caption.bold()).padding(7).background(FlowPalette.inset).clipShape(Circle()) }
                                        .padding(.top, 8)
                                    ForEach(values) { item in DownloadRow(item: item, manager: manager) }
                                }
                            }
                        }.padding(.horizontal, 18).padding(.bottom, 90)
                    }
                }
            }
            Button { showAdd = true } label: {
                Image(systemName: "plus").font(.title.bold()).foregroundStyle(FlowPalette.onAction)
                    .frame(width: 64, height: 64).background(FlowPalette.action).clipShape(Circle()).shadow(radius: 8, y: 5)
            }.padding(22)
        }
        .flowPage()
        .sheet(isPresented: $showAdd) { AddDownloadView() }
        .onReceive(store.downloads.$items) { _ in itemsVersion &+= 1 }
    }

    private var visibleItems: [DownloadItem] {
        manager.items.filter { item in
            (search.isEmpty || item.title.localizedCaseInsensitiveContains(search)) &&
            (filter == 0 || (filter == 1 && !item.status.isTerminal) || (filter == 2 && item.status == .completed))
        }
    }
    private var sectioned: [(String, [DownloadItem])] {
        [("Active", visibleItems.filter { !$0.status.isTerminal }), ("Completed", visibleItems.filter { $0.status == .completed }),
         ("Other", visibleItems.filter { $0.status.isTerminal && $0.status != .completed })]
    }
}

private struct DownloadRow: View {
    let item: DownloadItem
    @ObservedObject var manager: DownloadManager
    var body: some View {
        FlowCard(content: HStack(spacing: 14) {
            FlowIcon(name: icon)
            VStack(alignment: .leading, spacing: 6) {
                Text(item.title).font(.headline).lineLimit(1)
                Text(detail).font(.subheadline).foregroundStyle(.secondary).lineLimit(1)
                if item.status == .downloading { ProgressView(value: item.progress).tint(FlowPalette.action) }
                Text(item.addedAt.formatted(date: .abbreviated, time: .shortened)).font(.caption).foregroundStyle(.secondary)
            }
            Spacer()
            Menu {
                if item.status == .downloading { Button("Pause", systemImage: "pause") { manager.pause(item.id) } }
                else if item.status != .completed { Button("Resume", systemImage: "play") { manager.start(item.id) } }
                if let local = manager.localURL(for: item) { ShareLink(item: local) { Label("Share file", systemImage: "square.and.arrow.up") } }
                Button("Delete", systemImage: "trash", role: .destructive) { manager.remove(item.id) }
            } label: {
                if item.status == .completed { Image(systemName: "checkmark.circle.fill").font(.title2).foregroundStyle(FlowPalette.success) }
                else { Image(systemName: "ellipsis").font(.title2) }
            }
        }.padding(14))
    }
    private var icon: String { item.mimeType?.hasPrefix("video") == true ? "film" : item.mimeType?.hasPrefix("image") == true ? "photo" : "doc" }
    private var detail: String {
        var values: [String] = []
        if let total = item.totalBytes { values.append(total.fileSize) }
        values.append(item.status.label)
        if item.speedBytesPerSecond > 0 { values.append("\(item.speedBytesPerSecond.fileSize)/s") }
        return values.joined(separator: " • ")
    }
}

struct AddDownloadView: View {
    @EnvironmentObject private var store: AppStore
    @Environment(\.dismiss) private var dismiss
    @State private var mode = 0
    @State private var input = ""
    @State private var wifiOnly = false
    @State private var autoStart = true
    @State private var showImporter = false
    @State private var error: String?
    var prefilledURL: URL?

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 18) {
                    Picker("Source", selection: $mode) { Text("URL").tag(0); Text("Torrent").tag(1); Text("Magnet").tag(2) }
                        .pickerStyle(.segmented)
                    if mode == 1 {
                        FlowCard(content: Button { showImporter = true } label: {
                            VStack(spacing: 12) { Image(systemName: "doc.badge.plus").font(.largeTitle); Text("Choose .torrent file").font(.headline); Text("Torrent transfer activates when the iOS native core is linked.").font(.caption).foregroundStyle(.secondary) }
                                .frame(maxWidth: .infinity).padding(28)
                        })
                    } else {
                        HStack { Image(systemName: mode == 0 ? "link" : "bolt.horizontal"); TextField(mode == 0 ? "Enter link" : "Paste magnet link", text: $input).textInputAutocapitalization(.never).keyboardType(.URL) }
                            .padding(16).background(FlowPalette.surface).clipShape(RoundedRectangle(cornerRadius: 14)).overlay(RoundedRectangle(cornerRadius: 14).stroke(FlowPalette.outline))
                    }

                    FlowCard(content: VStack(spacing: 0) {
                        settingRow("Save to", subtitle: store.settings.downloadDirectory, icon: "folder", toggle: nil)
                        Divider().padding(.leading, 68)
                        settingRow("Wi-Fi only", subtitle: "Download only on Wi-Fi", icon: "wifi", toggle: $wifiOnly)
                        Divider().padding(.leading, 68)
                        settingRow("Auto start", subtitle: "Start download immediately", icon: "play.circle", toggle: $autoStart)
                    })
                    if let error { Text(error).font(.footnote).foregroundStyle(FlowPalette.danger).frame(maxWidth: .infinity, alignment: .leading) }
                    FlowPrimaryButton(title: "Download", icon: "arrow.down", disabled: mode == 1 || input.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty) { submit() }
                }.padding(18)
            }
            .flowPage().navigationTitle("Add Download").navigationBarTitleDisplayMode(.inline)
            .toolbar { ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } } }
            .onAppear { if let prefilledURL { input = prefilledURL.absoluteString } }
            .fileImporter(isPresented: $showImporter, allowedContentTypes: [UTType(filenameExtension: "torrent") ?? .data]) { _ in
                error = "The selected torrent is ready for native-core integration on macOS."
            }
        }
    }

    @ViewBuilder private func settingRow(_ title: String, subtitle: String, icon: String, toggle: Binding<Bool>?) -> some View {
        HStack(spacing: 14) { FlowIcon(name: icon); VStack(alignment: .leading) { Text(title).font(.headline); Text(subtitle).font(.caption).foregroundStyle(.secondary) }; Spacer(); if let toggle { Toggle("", isOn: toggle).labelsHidden() } }
            .padding(14)
    }
    private func submit() {
        guard mode == 0, let url = URLInput.downloadURL(from: input) else { error = mode == 2 ? "Torrent magnet support requires the native iOS core." : "Enter a valid HTTP or HTTPS link."; return }
        store.downloads.add(url: url, wifiOnly: wifiOnly, autoStart: autoStart)
        store.incomingURL = nil
        dismiss()
    }
}
