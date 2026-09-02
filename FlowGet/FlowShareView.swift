import SwiftUI
import UniformTypeIdentifiers
import UIKit

struct FlowShareView: View {
    private enum Screen: Equatable { case home, send, receive }

    @EnvironmentObject private var store: AppStore
    @State private var screen: Screen = .home
    @State private var selectedFiles: [URL] = []
    @State private var showFiles = false
    @State private var showHistory = false
    @State private var showCoreNotice = false
    @State private var friendCode = ""
    let openMenu: () -> Void

    var body: some View {
        VStack(spacing: 0) {
            topBar
            Group {
                switch screen {
                case .home: homeView
                case .send: sendView
                case .receive: receiveView
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
        .alert("Native FlowShare core required", isPresented: $showCoreNotice) {
            Button("OK", role: .cancel) {}
        } message: {
            Text("This interface is ready. Cross-platform FlowShare protocol-v3 transfer requires the shared FlowGet core compiled as an iOS XCFramework.")
        }
    }

    private var topBar: some View {
        FlowTopBar(
            title: screen == .home ? "FlowShare" : screen == .send ? "FlowShare – Send" : "FlowShare – Receive",
            onMenu: {
                if screen == .home { openMenu() }
                else { screen = .home; selectedFiles.removeAll() }
            },
            leadingIcon: screen == .home ? "line.3.horizontal" : "chevron.left",
            trailing: AnyView(HStack(spacing: 0) {
                Button { showCoreNotice = true } label: {
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
                    if !store.flowShareTransfers.isEmpty { Button("Clear transfer history", systemImage: "trash", role: .destructive) { store.flowShareTransfers.removeAll() } }
                } label: {
                    Image(systemName: "ellipsis").font(.system(size: 21, weight: .semibold)).rotationEffect(.degrees(90)).frame(width: 42, height: 42)
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
                        compactAction("Scan QR", "viewfinder") { showCoreNotice = true }
                        compactAction("My Devices", "iphone.gen3") { screen = .send }
                    }
                }
                .padding(.top, 18)

                Button { showHistory = true } label: {
                    HStack(spacing: 12) {
                        Image(systemName: "clock.arrow.circlepath")
                        Text("Transfer history").font(.flowTitleSmall)
                        Spacer()
                        if !store.flowShareTransfers.isEmpty { FlowStatusBadge(title: "\(store.flowShareTransfers.count)", color: FlowPalette.secondary) }
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
                FlowCard(content: VStack(spacing: 0) {
                    destinationRow("Nearby device", "Find FlowGet devices on the same Wi-Fi", "antenna.radiowaves.left.and.right")
                    Divider().padding(.leading, 68)
                    destinationRow("My devices", "Send to a linked computer or phone", "desktopcomputer")
                })

                FlowSectionTitle(title: "Send with code")
                HStack(spacing: 10) {
                    Image(systemName: "number").foregroundStyle(FlowPalette.secondary)
                    TextField("Receiver code", text: $friendCode)
                        .font(.flowBody).textInputAutocapitalization(.characters).autocorrectionDisabled()
                    Button("Connect") { showCoreNotice = true }
                        .font(.flowTitleSmall).disabled(friendCode.isEmpty)
                }
                .padding(.horizontal, 14).frame(height: 54)
                .background(FlowPalette.surface).clipShape(RoundedRectangle(cornerRadius: FlowRadius.medium))
                .overlay(RoundedRectangle(cornerRadius: FlowRadius.medium).stroke(FlowPalette.outline))

                FlowPrimaryButton(title: "Continue", icon: "arrow.right", disabled: selectedFiles.isEmpty) { showCoreNotice = true }
            }
            .padding(.horizontal, 16).padding(.top, 12).padding(.bottom, 28)
        }
        .scrollDismissesKeyboard(.interactively)
        .scrollIndicators(.hidden)
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
                    capsuleButton("Nearby", "antenna.radiowaves.left.and.right") { showCoreNotice = true }
                    capsuleOutlineButton("Receive code", "qrcode") { showCoreNotice = true }
                }
                .padding(.top, 26)

                FlowCard(content: HStack(spacing: 14) {
                    FlowIcon(name: "iphone.gen3", emphasized: true, size: 52)
                    VStack(alignment: .leading, spacing: 4) {
                        Text(UIDevice.current.name).font(.flowTitle)
                        Text("Waiting for compatible devices").font(.flowCaption).foregroundStyle(FlowPalette.secondary)
                    }
                    Spacer()
                    ProgressView().tint(FlowPalette.content)
                }.padding(16), elevated: true)
                .padding(.top, 24)
            }
            .padding(.horizontal, 20).padding(.top, 12).padding(.bottom, 28)
        }
        .scrollIndicators(.hidden)
    }

    private var historySheet: some View {
        NavigationStack {
            Group {
                if store.flowShareTransfers.isEmpty {
                    ContentUnavailableView("No transfers yet", systemImage: "clock.arrow.circlepath", description: Text("Sent and received files will appear here."))
                } else {
                    List {
                        ForEach(store.flowShareTransfers) { transfer in
                            HStack(spacing: 12) {
                                FlowIcon(name: transfer.direction == .send ? "arrow.up" : "arrow.down")
                                VStack(alignment: .leading, spacing: 3) {
                                    Text(transfer.fileName).font(.flowTitleSmall).lineLimit(1)
                                    Text(transfer.state).font(.flowCaption).foregroundStyle(FlowPalette.secondary)
                                }
                            }
                        }
                        .onDelete { store.flowShareTransfers.remove(atOffsets: $0) }
                    }
                    .listStyle(.plain)
                }
            }
            .navigationTitle("Transfer history")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar { ToolbarItem(placement: .confirmationAction) { Button("Done") { showHistory = false } } }
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

    private func destinationRow(_ title: String, _ subtitle: String, _ icon: String) -> some View {
        Button { showCoreNotice = true } label: {
            HStack(spacing: 12) {
                FlowIcon(name: icon)
                VStack(alignment: .leading, spacing: 3) {
                    Text(title).font(.flowTitleSmall)
                    Text(subtitle).font(.flowCaption).foregroundStyle(FlowPalette.secondary)
                }
                Spacer()
                Image(systemName: "chevron.right").foregroundStyle(FlowPalette.tertiary)
            }.padding(14)
        }.buttonStyle(.plain)
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
