import Foundation
import SwiftUI
import UniformTypeIdentifiers

struct DownloadsView: View {
    @EnvironmentObject private var store: AppStore
    @State private var filter = 0
    @State private var search = ""
    @State private var showSearch = false
    @State private var showAdd = false
    @State private var showDesktopNotice = false
    @State private var showClearConfirmation = false
    @State private var itemsVersion = 0

    let openMenu: () -> Void
    private var manager: DownloadManager { store.downloads }

    var body: some View {
        VStack(spacing: 0) {
            if showSearch { searchBar.transition(.move(edge: .trailing).combined(with: .opacity)) }
            else { titleBar.transition(.move(edge: .leading).combined(with: .opacity)) }
            FlowTabs(labels: tabLabels, selection: $filter)
                .padding(.horizontal, 16)
                .padding(.bottom, 10)

            Group {
                if visibleItems.isEmpty { emptyState }
                else { downloadList }
            }
            .transition(.opacity.combined(with: .move(edge: filter == 2 ? .trailing : .leading)))
        }
        .overlay(alignment: .bottomTrailing) {
            if !manager.items.isEmpty {
                Button { showAdd = true } label: {
                    Image(systemName: "plus")
                        .font(.system(size: 22, weight: .bold))
                        .foregroundStyle(FlowPalette.onAction)
                        .frame(width: 56, height: 56)
                        .background(FlowPalette.action)
                        .clipShape(Circle())
                        .shadow(color: .black.opacity(0.18), radius: 7, y: 4)
                }
                .buttonStyle(FlowPressButtonStyle())
                .padding(20)
                .accessibilityLabel("Add download")
            }
        }
        .flowPage()
        .animation(FlowMotion.deliberate, value: showSearch)
        .animation(FlowMotion.deliberate, value: filter)
        .sheet(isPresented: $showAdd) { AddDownloadView().presentationDragIndicator(.visible) }
        .alert("Send to PC", isPresented: $showDesktopNotice) {
            Button("Got it", role: .cancel) {}
        } message: {
            Text("Open FlowGet Desktop and link it to this account. Native iPhone-to-PC delivery will appear here when the shared FlowGet transfer core is linked.")
        }
        .confirmationDialog("Clear all downloads?", isPresented: $showClearConfirmation, titleVisibility: .visible) {
            Button("Clear all", role: .destructive) {
                manager.items.forEach { manager.remove($0.id) }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("Download records and their local files will be removed.")
        }
        .onReceive(manager.$items) { _ in itemsVersion &+= 1 }
    }

    private var titleBar: some View {
        FlowTopBar(title: "Downloads", onMenu: openMenu, trailing: AnyView(
            HStack(spacing: 0) {
                topButton("desktopcomputer", label: "Send link to PC") { showDesktopNotice = true }
                topButton("magnifyingglass", label: "Search downloads") { showSearch = true }
                Menu {
                    Button("Add download", systemImage: "plus") { showAdd = true }
                    Button("Send link to PC", systemImage: "desktopcomputer") { showDesktopNotice = true }
                    Button("Clear all", systemImage: "trash", role: .destructive) { showClearConfirmation = true }
                } label: {
                    Image(systemName: "ellipsis")
                        .font(.system(size: 21, weight: .semibold))
                        .rotationEffect(.degrees(90))
                        .frame(width: 42, height: 42)
                }
                .accessibilityLabel("More actions")
            }
        ))
    }

    private var searchBar: some View {
        HStack(spacing: 10) {
            Button {
                search = ""
                showSearch = false
            } label: {
                Image(systemName: "chevron.left").font(.system(size: 21, weight: .semibold)).frame(width: 42, height: 42)
            }
            TextField("Search downloads", text: $search)
                .font(.flowBody)
                .textInputAutocapitalization(.never)
                .submitLabel(.search)
            if !search.isEmpty {
                Button { search = "" } label: { Image(systemName: "xmark.circle.fill").foregroundStyle(FlowPalette.tertiary) }
                    .accessibilityLabel("Clear search")
            }
        }
        .padding(.horizontal, 14)
        .frame(height: 62)
        .background(FlowPalette.background)
    }

    private var tabLabels: [String] {
        ["All \(filteredBySearch.count)", "Active \(activeItems.count)", "Completed \(completedItems.count)"]
    }

    private var emptyState: some View {
        VStack {
            Spacer(minLength: 20)
            FlowEmptyState(
                image: "DownloadEmpty",
                title: filter == 1 ? "No active downloads" : filter == 2 ? "No completed downloads" : "No downloads yet",
                message: filter == 1 ? "Active downloads will appear here." : filter == 2 ? "Your completed downloads will appear here." : "Your downloaded files will appear here.",
                primaryTitle: "Start downloading",
                primaryAction: { showAdd = true },
                secondaryTitle: "Send to PC",
                secondaryIcon: "desktopcomputer",
                secondaryAction: { showDesktopNotice = true }
            )
            Spacer(minLength: 10)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private var downloadList: some View {
        ScrollView {
            LazyVStack(alignment: .leading, spacing: 12) {
                if filter != 2, !activeItems.isEmpty {
                    FlowSectionTitle(title: "Active", count: activeItems.count)
                        .padding(.top, 4)
                    ForEach(activeItems) { item in DownloadRow(item: item, manager: manager) }
                }
                if filter != 1, !completedItems.isEmpty {
                    FlowSectionTitle(title: "Completed", count: completedItems.count)
                        .padding(.top, filter == 0 && !activeItems.isEmpty ? 4 : 0)
                    ForEach(completedItems) { item in DownloadRow(item: item, manager: manager) }
                }
                if filter == 0, !otherItems.isEmpty {
                    FlowSectionTitle(title: "Other", count: otherItems.count).padding(.top, 4)
                    ForEach(otherItems) { item in DownloadRow(item: item, manager: manager) }
                }
            }
            .padding(.horizontal, 16)
            .padding(.top, 4)
            .padding(.bottom, 90)
        }
        .scrollIndicators(.hidden)
    }

    private var filteredBySearch: [DownloadItem] {
        manager.items.filter { search.isEmpty || $0.title.localizedCaseInsensitiveContains(search) }
    }
    private var activeItems: [DownloadItem] { filteredBySearch.filter { !$0.status.isTerminal } }
    private var completedItems: [DownloadItem] { filteredBySearch.filter { $0.status == .completed } }
    private var otherItems: [DownloadItem] { filteredBySearch.filter { $0.status.isTerminal && $0.status != .completed } }
    private var visibleItems: [DownloadItem] {
        switch filter { case 1: activeItems; case 2: completedItems; default: filteredBySearch }
    }

    private func topButton(_ icon: String, label: String, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            Image(systemName: icon).font(.system(size: 20, weight: .medium)).frame(width: 42, height: 42)
        }
        .buttonStyle(.plain)
        .accessibilityLabel(label)
    }
}

private struct DownloadRow: View {
    @Environment(\.openURL) private var openURL
    let item: DownloadItem
    @ObservedObject var manager: DownloadManager

    var body: some View {
        FlowCard(content: VStack(spacing: 0) {
            HStack(alignment: .top, spacing: 12) {
                FlowIcon(name: icon)
                VStack(alignment: .leading, spacing: 4) {
                    Text(item.title).font(.flowTitleSmall).lineLimit(1)
                    Text(detail).font(.flowCaption).foregroundStyle(FlowPalette.secondary).lineLimit(2)
                }
                Spacer(minLength: 4)
                statusMenu
            }
            if item.status == .downloading || item.progress > 0 {
                FlowProgressBar(value: item.progress).padding(.top, 12)
                HStack {
                    Text("\(Int(item.progress * 100))%")
                    Spacer()
                    if item.speedBytesPerSecond > 0 { Text("\(item.speedBytesPerSecond.fileSize)/s") }
                }
                .font(.flowLabel)
                .foregroundStyle(FlowPalette.secondary)
                .padding(.top, 6)
            }
        }.padding(14), elevated: item.status == .downloading)
    }

    private var statusMenu: some View {
        Menu {
            if item.status == .downloading {
                Button("Pause", systemImage: "pause") { manager.pause(item.id) }
            } else if item.status != .completed {
                Button("Resume", systemImage: "play") { manager.start(item.id) }
            }
            if let local = manager.localURL(for: item) {
                Button("Open", systemImage: "arrow.up.forward.app") { openURL(local) }
                ShareLink(item: local) { Label("Share file", systemImage: "square.and.arrow.up") }
            }
            Button("Delete", systemImage: "trash", role: .destructive) { manager.remove(item.id) }
        } label: {
            if item.status == .completed {
                Image(systemName: "checkmark.circle.fill").font(.system(size: 22)).foregroundStyle(FlowPalette.success)
            } else {
                Image(systemName: "ellipsis").font(.system(size: 20, weight: .semibold)).rotationEffect(.degrees(90))
            }
        }
        .frame(width: 34, height: 34)
        .accessibilityLabel("Actions for \(item.title)")
    }

    private var icon: String {
        item.mimeType?.hasPrefix("video") == true ? "film" : item.mimeType?.hasPrefix("image") == true ? "photo" : "doc"
    }
    private var detail: String {
        var values: [String] = []
        if let total = item.totalBytes { values.append(total.fileSize) }
        values.append(item.status.label)
        if let error = item.errorMessage, !error.isEmpty { values.append(error) }
        return values.joined(separator: " • ")
    }
}

struct AddDownloadView: View {
    @EnvironmentObject private var store: AppStore
    @Environment(\.dismiss) private var dismiss
    @FocusState private var inputFocused: Bool
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
                VStack(alignment: .leading, spacing: 18) {
                    FlowTabs(labels: ["URL", "Torrent", "Magnet"], selection: $mode)

                    FlowSectionTitle(title: "Download source")
                    if mode == 1 { torrentPicker }
                    else { linkInput }

                    FlowSectionTitle(title: "Save location")
                    FlowCard(content: HStack(spacing: 12) {
                        FlowIcon(name: "folder")
                        VStack(alignment: .leading, spacing: 3) {
                            Text("Save to").font(.flowTitleSmall)
                            Text(store.settings.downloadDirectory).font(.flowCaption).foregroundStyle(FlowPalette.secondary).lineLimit(2)
                        }
                        Spacer()
                        Image(systemName: "chevron.right").foregroundStyle(FlowPalette.tertiary)
                    }.padding(14))

                    FlowSectionTitle(title: "Options")
                    FlowCard(content: VStack(spacing: 0) {
                        optionRow("Wi-Fi only", "Download only on Wi-Fi", "wifi", value: $wifiOnly)
                        Divider().padding(.leading, 68)
                        optionRow("Auto start", "Start download immediately", "play.circle", value: $autoStart)
                    })

                    if let error {
                        Text(error).font(.flowCaption).foregroundStyle(FlowPalette.danger)
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                    FlowPrimaryButton(title: "Download", icon: "arrow.down", disabled: mode == 1 || input.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty) { submit() }
                }
                .padding(16)
            }
            .scrollDismissesKeyboard(.interactively)
            .flowPage()
            .navigationTitle("Add Download")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
            }
            .onAppear {
                if let prefilledURL { input = prefilledURL.absoluteString }
                if prefilledURL == nil { inputFocused = true }
            }
            .fileImporter(isPresented: $showImporter, allowedContentTypes: [UTType(filenameExtension: "torrent") ?? .data]) { result in
                if case .success = result { error = "Torrent transfer is ready when the shared native core is linked." }
            }
        }
    }

    private var linkInput: some View {
        HStack(spacing: 12) {
            Image(systemName: mode == 0 ? "link" : "bolt.horizontal")
                .font(.system(size: 19, weight: .medium)).foregroundStyle(FlowPalette.secondary)
            TextField(mode == 0 ? "Enter download link" : "Paste magnet link", text: $input, axis: .vertical)
                .font(.flowBody).focused($inputFocused).textInputAutocapitalization(.never).autocorrectionDisabled().keyboardType(.URL)
        }
        .padding(.horizontal, 16).frame(minHeight: 58)
        .background(FlowPalette.surface).clipShape(RoundedRectangle(cornerRadius: FlowRadius.medium))
        .overlay(RoundedRectangle(cornerRadius: FlowRadius.medium).stroke(error == nil ? FlowPalette.outline : FlowPalette.danger))
    }

    private var torrentPicker: some View {
        FlowCard(content: Button { showImporter = true } label: {
            VStack(spacing: 12) {
                FlowIcon(name: "doc.badge.plus", emphasized: true, size: 52)
                Text("Choose .torrent file").font(.flowTitle)
                Text("Select a torrent with the native iOS document picker.")
                    .font(.flowCaption).foregroundStyle(FlowPalette.secondary).multilineTextAlignment(.center)
            }
            .frame(maxWidth: .infinity).padding(28)
        }.buttonStyle(FlowPressButtonStyle()))
    }

    private func optionRow(_ title: String, _ subtitle: String, _ icon: String, value: Binding<Bool>) -> some View {
        HStack(spacing: 12) {
            FlowIcon(name: icon)
            VStack(alignment: .leading, spacing: 3) {
                Text(title).font(.flowTitleSmall)
                Text(subtitle).font(.flowCaption).foregroundStyle(FlowPalette.secondary)
            }
            Spacer()
            Toggle("", isOn: value).labelsHidden().toggleStyle(FlowSwitchToggleStyle())
        }
        .padding(14)
    }

    private func submit() {
        guard mode == 0, let url = URLInput.downloadURL(from: input) else {
            error = mode == 2 ? "Torrent magnet support requires the native iOS core." : "Enter a valid HTTP or HTTPS link."
            return
        }
        guard store.downloads.add(url: url, wifiOnly: wifiOnly, autoStart: autoStart) != nil else {
            error = "This link cannot be handed to the iOS download service."
            return
        }
        store.incomingURL = nil
        dismiss()
    }
}
