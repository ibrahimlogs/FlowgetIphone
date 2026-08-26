import SwiftUI
import UniformTypeIdentifiers
import UIKit

struct FlowShareView: View {
    @EnvironmentObject private var store: AppStore
    @State private var tab = 0
    @State private var showFiles = false
    @State private var showCoreNotice = false
    let openMenu: () -> Void

    var body: some View {
        VStack(spacing: 0) {
            FlowTopBar(title: "FlowShare", onMenu: openMenu)
            Picker("FlowShare mode", selection: $tab) { Text("Send").tag(0); Text("Receive").tag(1); Text("Nearby").tag(2) }
                .pickerStyle(.segmented).padding(.horizontal, 18).padding(.bottom, 14)
            ScrollView {
                VStack(alignment: .leading, spacing: 18) {
                    if tab == 0 { sendView }
                    else if tab == 1 { receiveView }
                    else { nearbyView }
                    if !store.flowShareTransfers.isEmpty {
                        FlowSectionTitle(title: "Transfers")
                        ForEach(store.flowShareTransfers) { transfer in transferRow(transfer) }
                    }
                }.padding(18).padding(.bottom, 20)
            }
        }
        .flowPage().fileImporter(isPresented: $showFiles, allowedContentTypes: [.item], allowsMultipleSelection: true) { result in
            if case .success(let urls) = result {
                store.flowShareTransfers.append(contentsOf: urls.map { FlowShareTransfer(direction: .send, fileName: $0.lastPathComponent, totalBytes: 0, state: "Awaiting native core") })
                showCoreNotice = true
            }
        }
        .alert("Native FlowShare core required", isPresented: $showCoreNotice) {
            Button("OK", role: .cancel) {}
        } message: {
            Text("The UI and file selection are ready. Cross-platform protocol-v3 transfer requires the authoritative core compiled as an iOS XCFramework.")
        }
    }

    private var sendView: some View {
        Group {
            FlowCard(content: VStack(spacing: 16) {
                FlowIcon(name: "paperplane.fill", emphasized: true)
                Text("Send files anywhere").font(.title2.bold())
                Text("Choose files, then select a connected device or enter a receiver code.").multilineTextAlignment(.center).foregroundStyle(.secondary)
                FlowPrimaryButton(title: "Choose files", icon: "doc.badge.plus") { showFiles = true }
            }.frame(maxWidth: .infinity).padding(22))
            FlowSectionTitle(title: "Your devices")
            if store.flowShareDevices.isEmpty {
                FlowCard(content: HStack(spacing: 14) { FlowIcon(name: "desktopcomputer"); VStack(alignment: .leading) { Text("No other devices online").font(.headline); Text("Sign in on FlowGet desktop to see it here.").font(.caption).foregroundStyle(.secondary) } }.padding(14))
            }
        }
    }

    private var receiveView: some View {
        Group {
            FlowCard(content: HStack {
                VStack(alignment: .leading, spacing: 8) { Text("This device").font(.title3.bold()); Text(UIDevice.current.name); Text("Online").foregroundStyle(FlowPalette.success) }
                Spacer(); ZStack { ForEach([110.0, 80, 50], id: \.self) { size in Circle().stroke(FlowPalette.outline).frame(width: size, height: size) }; FlowGetLogo(size: 42) }
            }.padding(20))
            FlowCard(content: VStack(alignment: .leading, spacing: 18) {
                Text("Receive files").font(.title3.bold())
                Text("Share this code or link with sender").foregroundStyle(.secondary)
                if let invite = store.flowShareInvite {
                    Text(invite.code).font(.system(size: 38, weight: .bold, design: .monospaced)).tracking(4).frame(maxWidth: .infinity)
                    Text("Expires " + invite.expiresAt.formatted(date: .omitted, time: .shortened)).font(.subheadline).foregroundStyle(.secondary).frame(maxWidth: .infinity)
                    HStack {
                        ShareLink(item: invite.code) { Label("Share code", systemImage: "square.and.arrow.up").frame(maxWidth: .infinity, minHeight: 48).overlay(RoundedRectangle(cornerRadius: 12).stroke(FlowPalette.outline)) }
                        Button { UIPasteboard.general.string = invite.code } label: { Label("Copy", systemImage: "doc.on.doc").frame(maxWidth: .infinity, minHeight: 48).overlay(RoundedRectangle(cornerRadius: 12).stroke(FlowPalette.outline)) }
                    }
                } else { FlowPrimaryButton(title: "Create receive code", icon: "qrcode") { showCoreNotice = true } }
            }.padding(20))
        }
    }

    private var nearbyView: some View {
        Group {
            FlowCard(content: VStack(spacing: 14) { Image(systemName: "wifi.circle").font(.system(size: 56)); Text("Nearby devices").font(.title2.bold()); Text("Compatible FlowGet devices on the same network will appear here after the iOS native core is linked.").multilineTextAlignment(.center).foregroundStyle(.secondary) }.frame(maxWidth: .infinity).padding(24))
            FlowSectionTitle(title: "Discovery")
            FlowCard(content: HStack { FlowIcon(name: "antenna.radiowaves.left.and.right"); VStack(alignment: .leading) { Text("Local network").font(.headline); Text("Waiting for compatible devices").font(.caption).foregroundStyle(.secondary) }; Spacer(); ProgressView() }.padding(14))
        }
    }

    private func transferRow(_ transfer: FlowShareTransfer) -> some View {
        FlowCard(content: HStack { FlowIcon(name: transfer.direction == .send ? "arrow.up" : "arrow.down"); VStack(alignment: .leading) { Text(transfer.fileName).font(.headline); Text(transfer.state).font(.caption).foregroundStyle(.secondary) }; Spacer() }.padding(14))
    }
}
