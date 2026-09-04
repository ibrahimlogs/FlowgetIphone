import SwiftUI
import UniformTypeIdentifiers
import UIKit

struct FlowShareView: View {
    private enum Screen: Equatable { case home, send, receive }

    @EnvironmentObject private var store: AppStore
    @ObservedObject var flowShare: FlowShareCoordinator
    @State private var screen: Screen = .home
    @State private var selectedFiles: [URL] = []
    @State private var selectedDeviceID: String?
    @State private var showFiles = false
    @State private var showHistory = false
    @State private var showReceiveCode = false
    @State private var presentedIncoming: FlowShareIncomingRequest?
    @State private var friendCode = ""
    let openMenu: () -> Void

    var body: some View {
        VStack(spacing: 0) {
            topBar
            Group {
                if let transfer = flowShare.focusedTransfer {
                    transferSessionView(transfer)
                } else if flowShare.isBusy {
                    connectingSessionView
                } else {
                    switch screen {
                    case .home: homeView
                    case .send: sendView
                    case .receive: receiveView
                    }
                }
            }
            .transition(.asymmetric(insertion: .move(edge: .trailing).combined(with: .opacity), removal: .move(edge: .leading).combined(with: .opacity)))
        }
        .flowPage()
        .animation(FlowMotion.deliberate, value: screen)
        .fileImporter(isPresented: $showFiles, allowedContentTypes: [.item], allowsMultipleSelection: true) { result in
            if case .success(let urls) = result { selectedFiles = urls }
        }
        .sheet(isPresented: $showHistory) { historySheet.presentationDetents([.medium, .large]).presentationDragIndicator(.visible) }
        .sheet(isPresented: $showReceiveCode) { receiveCodeSheet.presentationDetents([.medium]).presentationDragIndicator(.visible) }
        .fullScreenCover(item: $presentedIncoming) { request in
            incomingRequestView(request)
                .interactiveDismissDisabled()
        }
        .alert("FlowShare", isPresented: Binding(
            get: { flowShare.errorMessage != nil },
            set: { if !$0 { flowShare.errorMessage = nil } }
        )) {
            Button("OK", role: .cancel) { flowShare.errorMessage = nil }
        } message: {
            Text(flowShare.errorMessage ?? "FlowShare could not complete that action.")
        }
        .task { await store.activateFlowShare() }
        .onReceive(flowShare.$incoming) { requests in
            if presentedIncoming == nil { presentedIncoming = requests.first }
        }
    }

    private var topBar: some View {
        let transfer = flowShare.focusedTransfer
        let isSession = transfer != nil || flowShare.isBusy
        return FlowTopBar(
            title: isSession ? "FlowShare – Transfer" : screen == .home ? "FlowShare" : screen == .send ? "FlowShare – Send" : "FlowShare – Receive",
            onMenu: {
                if let transfer {
                    if isTerminal(transfer) { flowShare.dismissSession() }
                    else { Task { await flowShare.cancelFocusedTransfer() } }
                } else if flowShare.isBusy {
                    return
                } else if screen == .home { openMenu() }
                else { screen = .home; selectedFiles.removeAll() }
            },
            leadingIcon: transfer != nil ? "xmark" : screen == .home ? "line.3.horizontal" : "chevron.left",
            trailing: AnyView(HStack(spacing: 0) {
                if !isSession {
                    Button {
                        if screen == .receive {
                            Task { await flowShare.createReceiveCode(); showReceiveCode = flowShare.invite != nil }
                        } else {
                            screen = .send
                        }
                    } label: {
                        Image(systemName: screen == .receive ? "qrcode" : "viewfinder")
                            .font(.system(size: 20, weight: .medium)).frame(width: 42, height: 42)
                    }
                    .buttonStyle(.plain)
                    .accessibilityLabel(screen == .receive ? "Show QR code" : "Scan QR code")
                    Button { showHistory = true } label: {
                        Image(systemName: "clock.arrow.circlepath").font(.system(size: 20, weight: .medium)).frame(width: 42, height: 42)
                    }
                    .buttonStyle(.plain)
                    .accessibilityLabel("Transfer history")
                    Menu {
                        if !selectedFiles.isEmpty { Button("Clear selected files", systemImage: "xmark.circle") { selectedFiles.removeAll() } }
                        if !flowShare.transfers.isEmpty { Button("Clear transfer history", systemImage: "trash", role: .destructive) { flowShare.clearHistory() } }
                    } label: {
                        Image(systemName: "ellipsis").font(.system(size: 21, weight: .semibold)).rotationEffect(.degrees(90)).frame(width: 42, height: 42)
                    }
                }
            })
        )
    }

    private var homeView: some View {
        ScrollView {
            VStack(spacing: 0) {
                Image("FlowShareHero")
                    .resizable().scaledToFit()
                    .frame(maxWidth: 260, maxHeight: 190)
                    .accessibilityHidden(true)
                Text("Share files with people\nand your devices.")
                    .font(.flowTitle)
                    .multilineTextAlignment(.center)
                    .lineSpacing(3)
                    .padding(.top, 8)

                VStack(spacing: 10) {
                    capsuleButton("Send Files", "paperplane") { screen = .send }
                    capsuleOutlineButton("Receive Files", "arrow.down.to.line") { screen = .receive }
                }
                .padding(.top, 24)

                VStack(alignment: .leading, spacing: 10) {
                    Text("Quick connect").font(.flowTitleSmall).foregroundStyle(FlowPalette.secondary)
                    HStack(spacing: 10) {
                        compactAction("Receive code", "qrcode") {
                            Task { await flowShare.createReceiveCode(); showReceiveCode = flowShare.invite != nil }
                        }
                        compactAction("My Devices", "iphone.gen3") { screen = .send }
                    }
                }
                .padding(.top, 18)

                Button { showHistory = true } label: {
                    HStack(spacing: 12) {
                        Image(systemName: "clock.arrow.circlepath")
                        Text("Transfer history").font(.flowTitleSmall)
                        Spacer()
                        if !flowShare.transfers.isEmpty { FlowStatusBadge(title: "\(flowShare.transfers.count)", color: FlowPalette.secondary) }
                        Image(systemName: "chevron.right").foregroundStyle(FlowPalette.tertiary)
                    }
                    .padding(.horizontal, 15).frame(height: 50)
                    .background(FlowPalette.surface)
                    .clipShape(RoundedRectangle(cornerRadius: FlowRadius.medium))
                    .overlay(RoundedRectangle(cornerRadius: FlowRadius.medium).stroke(FlowPalette.outline))
                }
                .buttonStyle(FlowPressButtonStyle())
                .padding(.top, 18)
            }
            .padding(.horizontal, 24)
            .padding(.top, 16)
            .padding(.bottom, 24)
        }
        .scrollIndicators(.hidden)
    }

    private var sendView: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                FlowSectionTitle(title: "Files to send", count: selectedFiles.count)
                if selectedFiles.isEmpty {
                    FlowCard(content: Button { showFiles = true } label: {
                        VStack(spacing: 12) {
                            FlowIcon(name: "doc.badge.plus", emphasized: true, size: 52)
                            Text("Choose files to send").font(.flowTitle)
                            Text("Photos, videos, documents and other files")
                                .font(.flowCaption).foregroundStyle(FlowPalette.secondary)
                        }
                        .frame(maxWidth: .infinity).padding(26)
                    }.buttonStyle(FlowPressButtonStyle()), elevated: true)
                } else {
                    FlowCard(content: VStack(spacing: 0) {
                        ForEach(Array(selectedFiles.enumerated()), id: \.element) { index, url in
                            HStack(spacing: 12) {
                                FlowIcon(name: fileIcon(url))
                                VStack(alignment: .leading, spacing: 3) {
                                    Text(url.lastPathComponent).font(.flowTitleSmall).lineLimit(1)
                                    Text(url.pathExtension.uppercased().nonEmpty ?? "FILE").font(.flowLabel).foregroundStyle(FlowPalette.secondary)
                                }
                                Spacer()
                                Button { selectedFiles.remove(at: index) } label: { Image(systemName: "xmark.circle.fill").foregroundStyle(FlowPalette.tertiary) }
                                    .buttonStyle(.plain).accessibilityLabel("Remove \(url.lastPathComponent)")
                            }
                            .padding(14)
                            if index < selectedFiles.count - 1 { Divider().padding(.leading, 68) }
                        }
                    }, elevated: true)
                    FlowOutlineButton(title: "Add more files", icon: "plus") { showFiles = true }
                }

                FlowSectionTitle(title: "Choose destination")
                if flowShare.devices.isEmpty {
                    FlowCard(content: HStack(spacing: 14) {
                        FlowIcon(name: "antenna.radiowaves.left.and.right", emphasized: true, size: 52)
                        VStack(alignment: .leading, spacing: 4) {
                            Text(flowShare.connection.title).font(.flowTitle)
                            Text("Waiting for your online FlowGet devices")
                                .font(.flowCaption).foregroundStyle(FlowPalette.secondary)
                        }
                        Spacer()
                        if flowShare.connection == .connecting || flowShare.connection == .reconnecting { ProgressView() }
                    }.padding(14))
                } else {
                    FlowCard(content: VStack(spacing: 0) {
                        ForEach(Array(flowShare.devices.enumerated()), id: \.element.id) { index, device in
                            destinationRow(device)
                            if index < flowShare.devices.count - 1 { Divider().padding(.leading, 68) }
                        }
                    })
                }

                FlowSectionTitle(title: "Send with code")
                HStack(spacing: 10) {
                    Image(systemName: "number").foregroundStyle(FlowPalette.secondary)
                    TextField("Receiver code", text: $friendCode)
                        .font(.flowBody).textInputAutocapitalization(.characters).autocorrectionDisabled()
                    Button("Connect") {
                        Task {
                            await flowShare.connect(friendCode: friendCode)
                            if flowShare.connectedFriend != nil { selectedDeviceID = nil }
                        }
                    }
                    .font(.flowTitleSmall)
                    .disabled(friendCode.filter { $0.isLetter || $0.isNumber }.count != 12 || flowShare.isBusy)
                }
                .padding(.horizontal, 14).frame(height: 54)
                .background(FlowPalette.surface).clipShape(RoundedRectangle(cornerRadius: FlowRadius.medium))
                .overlay(RoundedRectangle(cornerRadius: FlowRadius.medium).stroke(FlowPalette.outline))

                if let friend = flowShare.connectedFriend {
                    FlowCard(content: HStack(spacing: 12) {
                        FlowIcon(name: platformIcon(friend.platform), emphasized: true, size: 48)
                        VStack(alignment: .leading, spacing: 3) {
                            Text("Connected securely").font(.flowLabel).foregroundStyle(FlowPalette.success)
                            Text(friend.displayName).font(.flowTitleSmall).lineLimit(1)
                            Text("FlowShare Internet · One-time Code")
                                .font(.flowCaption).foregroundStyle(FlowPalette.secondary)
                        }
                        Spacer()
                        Button { flowShare.disconnectFriend() } label: {
                            Image(systemName: "xmark.circle.fill")
                                .font(.system(size: 21)).foregroundStyle(FlowPalette.tertiary)
                        }
                        .buttonStyle(.plain)
                        .accessibilityLabel("Disconnect friend")
                    }.padding(14), elevated: true)
                }

                FlowPrimaryButton(
                    title: flowShare.isBusy ? "Preparing…" : "Continue",
                    icon: "arrow.right",
                    disabled: selectedFiles.isEmpty || !hasSelectedDestination || flowShare.isBusy
                ) {
                    if flowShare.connectedFriend != nil {
                        Task { await flowShare.send(files: selectedFiles, friendCode: friendCode) }
                    } else if let selectedDeviceID {
                        Task { await flowShare.send(files: selectedFiles, toDeviceID: selectedDeviceID) }
                    }
                }
            }
            .padding(.horizontal, 16).padding(.top, 12).padding(.bottom, 28)
        }
        .scrollDismissesKeyboard(.interactively)
        .scrollIndicators(.hidden)
        .onChange(of: friendCode) {
            if flowShare.connectedFriend != nil { flowShare.disconnectFriend() }
        }
    }

    private var receiveView: some View {
        ScrollView {
            VStack(spacing: 0) {
                Image("NearbyWelcome")
                    .resizable().scaledToFit().frame(maxWidth: 270, maxHeight: 230)
                    .accessibilityHidden(true)
                Text("Ready to receive").font(.flowTitleLarge)
                Text("Share files quickly with devices near you\nwithout using mobile data.")
                    .font(.flowBody).foregroundStyle(FlowPalette.secondary)
                    .multilineTextAlignment(.center).padding(.top, 8)

                HStack(spacing: 10) {
                    capsuleButton("Reconnect", "antenna.radiowaves.left.and.right") { flowShare.reconnectIfNeeded() }
                    capsuleOutlineButton("Receive code", "qrcode") {
                        Task { await flowShare.createReceiveCode(); showReceiveCode = flowShare.invite != nil }
                    }
                }
                .padding(.top, 26)

                FlowCard(content: HStack(spacing: 14) {
                    FlowIcon(name: "iphone.gen3", emphasized: true, size: 52)
                    VStack(alignment: .leading, spacing: 4) {
                        Text(UIDevice.current.name).font(.flowTitle)
                        Text(flowShare.connection == .online ? "Ready for compatible devices" : flowShare.connection.title)
                            .font(.flowCaption).foregroundStyle(FlowPalette.secondary)
                    }
                    Spacer()
                    if flowShare.connection == .online {
                        Image(systemName: "checkmark.circle.fill").foregroundStyle(.green)
                    } else {
                        ProgressView().tint(FlowPalette.content)
                    }
                }.padding(16), elevated: true)
                .padding(.top, 24)
            }
            .padding(.horizontal, 20).padding(.top, 12).padding(.bottom, 28)
        }
        .scrollIndicators(.hidden)
    }

    private var connectingSessionView: some View {
        ScrollView {
            VStack(spacing: 24) {
                Text(flowShare.sessionTitle ?? "Establishing secure connection")
                    .font(.flowTitleLarge)
                    .multilineTextAlignment(.center)

                FlowCard(content: VStack(spacing: 22) {
                    HStack(spacing: 16) {
                        FlowIcon(name: "iphone.gen3", emphasized: true, size: 62)
                        VStack(spacing: 8) {
                            ProgressView().controlSize(.large).tint(FlowPalette.action)
                            Image(systemName: "lock.shield.fill").foregroundStyle(FlowPalette.secondary)
                        }
                        FlowIcon(name: "desktopcomputer", emphasized: true, size: 62)
                    }
                    Text("Establishing an authenticated direct connection…")
                        .font(.flowBody).foregroundStyle(FlowPalette.secondary)
                        .multilineTextAlignment(.center)
                }.frame(maxWidth: .infinity).padding(24), elevated: true)

                Text("Keep FlowGet open on both devices. The receiver will be asked to accept before file transfer begins.")
                    .font(.flowCaption).foregroundStyle(FlowPalette.secondary)
                    .multilineTextAlignment(.center)
            }
            .padding(.horizontal, 20).padding(.top, 36).padding(.bottom, 28)
        }
        .scrollIndicators(.hidden)
    }

    private func transferSessionView(_ transfer: FlowShareTransfer) -> some View {
        let terminal = ["Completed", "Cancelled", "Rejected", "Failed"].contains(transfer.state)
        let progress = transfer.totalBytes > 0
            ? min(1, max(0, Double(transfer.completedBytes) / Double(transfer.totalBytes)))
            : 0
        let remainingBytes = max(0, transfer.totalBytes - transfer.completedBytes)
        let etaSeconds = transfer.bytesPerSecond > 0 ? remainingBytes / transfer.bytesPerSecond : 0
        return ScrollView {
            VStack(spacing: 18) {
                FlowCard(content: VStack(spacing: 20) {
                    HStack(spacing: 16) {
                        FlowIcon(name: transfer.direction == .send ? "iphone.gen3" : "desktopcomputer", emphasized: true, size: 58)
                        VStack(spacing: 7) {
                            Image(systemName: transfer.state == "Completed" ? "checkmark.circle.fill" : "lock.shield.fill")
                                .font(.system(size: 31, weight: .semibold))
                                .foregroundStyle(transfer.state == "Completed" ? FlowPalette.success : FlowPalette.action)
                            Text(connectionLabel(for: transfer))
                                .font(.flowLabel).foregroundStyle(FlowPalette.secondary)
                        }
                        FlowIcon(name: transfer.direction == .send ? "desktopcomputer" : "iphone.gen3", emphasized: true, size: 58)
                    }
                    Text(transfer.direction == .send ? "Sending securely" : "Receiving securely")
                        .font(.flowTitleLarge)
                    Text(transfer.peerName ?? "FlowGet device")
                        .font(.flowBody).foregroundStyle(FlowPalette.secondary)
                }.frame(maxWidth: .infinity).padding(22), elevated: true)

                FlowCard(content: VStack(alignment: .leading, spacing: 13) {
                    HStack(spacing: 12) {
                        FlowIcon(name: fileIcon(URL(fileURLWithPath: transfer.fileName)))
                        VStack(alignment: .leading, spacing: 3) {
                            Text(transfer.fileName).font(.flowTitleSmall).lineLimit(2)
                            Text("\(transfer.completedBytes.fileSize) / \(transfer.totalBytes.fileSize)")
                                .font(.flowCaption).foregroundStyle(FlowPalette.secondary)
                        }
                        Spacer()
                        Text("\(Int(progress * 100))%").font(.flowTitleSmall)
                    }
                    FlowProgressBar(value: progress)
                    HStack(spacing: 0) {
                        transferMetric(icon: "doc", value: transfer.state == "Completed" ? "1/1" : "0/1", label: "Items")
                        Divider().frame(height: 40)
                        transferMetric(icon: "folder", value: transfer.totalBytes.fileSize, label: "Size")
                        Divider().frame(height: 40)
                        transferMetric(icon: "gauge.with.dots.needle.67percent", value: "\(transfer.bytesPerSecond.fileSize)/s", label: "Speed")
                        Divider().frame(height: 40)
                        transferMetric(icon: "clock", value: etaText(etaSeconds), label: "ETA")
                    }
                    .padding(.vertical, 9)
                    .background(FlowPalette.inset)
                    .clipShape(RoundedRectangle(cornerRadius: FlowRadius.medium, style: .continuous))
                    if let error = transfer.errorCode, !error.isEmpty {
                        Text(error).font(.flowCaption).foregroundStyle(FlowPalette.danger)
                    }
                }.padding(16), elevated: !terminal)

                if terminal {
                    FlowPrimaryButton(title: transfer.state == "Completed" ? "Done" : "Close", icon: "checkmark") {
                        selectedFiles.removeAll()
                        friendCode = ""
                        flowShare.dismissSession()
                    }
                } else {
                    FlowOutlineButton(title: "Cancel transfer", icon: "xmark") {
                        Task { await flowShare.cancelFocusedTransfer() }
                    }
                }
            }
            .padding(.horizontal, 16).padding(.top, 18).padding(.bottom, 28)
        }
        .scrollIndicators(.hidden)
    }

    private func incomingRequestView(_ request: FlowShareIncomingRequest) -> some View {
        NavigationStack {
            VStack(spacing: 22) {
                Spacer(minLength: 12)
                Text("Incoming File Request").font(.flowTitleLarge)
                Text(request.friendTransfer ? "FlowShare Internet · One-time Code" : "FlowShare Device")
                    .font(.flowCaption).foregroundStyle(FlowPalette.secondary)

                FlowCard(content: VStack(spacing: 20) {
                    HStack(spacing: 16) {
                        FlowIcon(name: "desktopcomputer", emphasized: true, size: 60)
                        Image(systemName: "arrow.right").font(.system(size: 24, weight: .semibold))
                            .foregroundStyle(FlowPalette.action)
                        FlowIcon(name: "iphone.gen3", emphasized: true, size: 60)
                    }
                    Text(request.sourceDisplayName).font(.flowTitle)
                    Divider()
                    VStack(spacing: 5) {
                        Text(request.fileName).font(.flowTitleSmall).lineLimit(2)
                        Text(request.fileSize.fileSize).font(.flowCaption).foregroundStyle(FlowPalette.secondary)
                    }
                }.frame(maxWidth: .infinity).padding(22), elevated: true)

                Spacer()
                FlowPrimaryButton(title: "Accept & receive", icon: "checkmark") {
                    screen = .receive
                    presentedIncoming = nil
                    Task { await flowShare.accept(request) }
                }
                FlowOutlineButton(title: "Decline", icon: "xmark") {
                    presentedIncoming = nil
                    Task { await flowShare.reject(request) }
                }
            }
            .padding(20).flowPage()
        }
    }

    private var historySheet: some View {
        NavigationStack {
            Group {
                if flowShare.transfers.isEmpty {
                    ContentUnavailableView("No transfers yet", systemImage: "clock.arrow.circlepath", description: Text("Sent and received files will appear here."))
                } else {
                    List {
                        ForEach(flowShare.transfers) { transfer in
                            HStack(spacing: 12) {
                                FlowIcon(name: transfer.direction == .send ? "arrow.up" : "arrow.down")
                                VStack(alignment: .leading, spacing: 3) {
                                    Text(transfer.fileName).font(.flowTitleSmall).lineLimit(1)
                                    Text(transfer.state).font(.flowCaption).foregroundStyle(FlowPalette.secondary)
                                }
                            }
                        }
                    }
                    .listStyle(.plain)
                }
            }
            .navigationTitle("Transfer history")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar { ToolbarItem(placement: .confirmationAction) { Button("Done") { showHistory = false } } }
        }
    }

    private var receiveCodeSheet: some View {
        NavigationStack {
            VStack(spacing: 18) {
                FlowIcon(name: "qrcode", emphasized: true, size: 70)
                Text("Receive with code").font(.flowTitleLarge)
                if let invite = flowShare.invite {
                    Text(invite.code).font(.system(size: 30, weight: .bold, design: .monospaced))
                        .textSelection(.enabled)
                    Text("Share this one-time code. It expires at \(invite.expiresAt.formatted(date: .omitted, time: .shortened)).")
                        .font(.flowBodySmall).foregroundStyle(FlowPalette.secondary).multilineTextAlignment(.center)
                } else {
                    ProgressView("Creating secure code…")
                }
            }
            .padding(28).frame(maxWidth: .infinity, maxHeight: .infinity).flowPage()
            .navigationTitle("FlowShare")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar { ToolbarItem(placement: .confirmationAction) { Button("Done") { showReceiveCode = false } } }
        }
    }

    private func capsuleButton(_ title: String, _ icon: String, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            Label(title, systemImage: icon).font(.flowTitle)
                .foregroundStyle(FlowPalette.onAction).frame(maxWidth: .infinity, minHeight: 48)
                .background(FlowPalette.action).clipShape(Capsule())
        }.buttonStyle(FlowPressButtonStyle())
    }

    private func capsuleOutlineButton(_ title: String, _ icon: String, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            Label(title, systemImage: icon).font(.flowTitle)
                .foregroundStyle(FlowPalette.content).frame(maxWidth: .infinity, minHeight: 48)
                .background(FlowPalette.surface).clipShape(Capsule()).overlay(Capsule().stroke(FlowPalette.outline, lineWidth: 1.5))
        }.buttonStyle(FlowPressButtonStyle())
    }

    private func compactAction(_ title: String, _ icon: String, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            Label(title, systemImage: icon).font(.flowTitleSmall)
                .foregroundStyle(FlowPalette.content).frame(maxWidth: .infinity, minHeight: 46)
                .background(FlowPalette.surface).clipShape(RoundedRectangle(cornerRadius: FlowRadius.medium))
                .overlay(RoundedRectangle(cornerRadius: FlowRadius.medium).stroke(FlowPalette.outline))
        }.buttonStyle(FlowPressButtonStyle())
    }

    private func destinationRow(_ device: FlowShareDevice) -> some View {
        Button {
            selectedDeviceID = device.id
            flowShare.disconnectFriend()
        } label: {
            HStack(spacing: 12) {
                FlowIcon(name: device.nearby ? "antenna.radiowaves.left.and.right" : platformIcon(device.platform))
                VStack(alignment: .leading, spacing: 3) {
                    Text(device.displayName).font(.flowTitleSmall)
                    Text(device.nearby ? "Nearby · \(device.platform.capitalized)" : device.platform.capitalized)
                        .font(.flowCaption).foregroundStyle(FlowPalette.secondary)
                }
                Spacer()
                Image(systemName: selectedDeviceID == device.id ? "checkmark.circle.fill" : "circle")
                    .foregroundStyle(selectedDeviceID == device.id ? FlowPalette.content : FlowPalette.tertiary)
            }.padding(14)
        }.buttonStyle(.plain)
    }

    private func platformIcon(_ platform: String) -> String {
        switch platform.lowercased() {
        case "windows", "macos": "desktopcomputer"
        case "android": "smartphone"
        default: "iphone.gen3"
        }
    }

    private func isTerminal(_ transfer: FlowShareTransfer) -> Bool {
        ["Completed", "Cancelled", "Rejected", "Failed"].contains(transfer.state)
    }

    private var hasSelectedDestination: Bool {
        selectedDeviceID != nil || flowShare.connectedFriend != nil
    }

    private func connectionLabel(for transfer: FlowShareTransfer) -> String {
        switch transfer.state {
        case "Prepared", "Incoming", "Awaiting acceptance", "Waiting for peer", "Connecting":
            return "Connecting"
        case "Connected", "Transferring", "Resuming", "Verifying":
            return "Connected"
        default:
            return transfer.state
        }
    }

    private func transferMetric(icon: String, value: String, label: String) -> some View {
        VStack(spacing: 3) {
            Image(systemName: icon)
                .font(.system(size: 13, weight: .semibold))
                .foregroundStyle(FlowPalette.secondary)
            Text(value)
                .font(.flowLabelSmall.weight(.bold))
                .foregroundStyle(FlowPalette.content)
                .lineLimit(1)
                .minimumScaleFactor(0.65)
            Text(label)
                .font(.system(size: 9, weight: .medium))
                .foregroundStyle(FlowPalette.tertiary)
        }
        .frame(maxWidth: .infinity)
    }

    private func etaText(_ seconds: Int64) -> String {
        guard seconds > 0 else { return "--" }
        if seconds < 60 { return "\(seconds)s" }
        if seconds < 3_600 { return "\(seconds / 60)m \(seconds % 60)s" }
        return "\(seconds / 3_600)h \((seconds % 3_600) / 60)m"
    }

    private func fileIcon(_ url: URL) -> String {
        switch url.pathExtension.lowercased() {
        case "jpg", "jpeg", "png", "heic": "photo"
        case "mov", "mp4", "mkv": "film"
        case "mp3", "m4a", "wav": "waveform"
        default: "doc"
        }
    }
}

private extension String {
    var nonEmpty: String? { isEmpty ? nil : self }
}
