import Foundation
import SwiftUI
import WebKit

struct BrowserHomeView: View {
    @EnvironmentObject private var store: AppStore
    @State private var input = ""
    @State private var destination: URL?
    @State private var collection: BrowserCollection?
    @FocusState private var addressFocused: Bool
    let openMenu: () -> Void

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                header
                ScrollView {
                    VStack(alignment: .leading, spacing: 12) {
                        favorites
                        continueBrowsing
                        downloadPromo
                    }
                    .padding(.horizontal, 18)
                    .padding(.top, 10)
                    .padding(.bottom, 20)
                }
                .scrollIndicators(.hidden)
            }
            .flowPage()
            .toolbar(.hidden, for: .navigationBar)
            .navigationDestination(item: $destination) { url in BrowserPage(initialURL: url, settings: store.settings) }
            .sheet(item: $collection) { value in BrowserCollectionView(collection: value, destination: $destination) }
        }
    }

    private var header: some View {
        VStack(spacing: 6) {
            FlowTopBar(title: "Browser", onMenu: openMenu, trailing: AnyView(HStack(spacing: 1) {
                Button { collection = .tabs } label: {
                    ZStack(alignment: .topTrailing) {
                        Image(systemName: "square.on.square").font(.system(size: 22, weight: .medium))
                        Text("1").font(.system(size: 9, weight: .bold)).frame(width: 16, height: 16)
                            .background(FlowPalette.surface).clipShape(RoundedRectangle(cornerRadius: 4)).offset(x: 7, y: -7)
                    }.frame(width: 42, height: 42)
                }
                .buttonStyle(.plain).accessibilityLabel("Tabs")
                Menu {
                    Button("New private tab", systemImage: "eye.slash") { input = ""; addressFocused = true }
                    Button("History", systemImage: "clock.arrow.circlepath") { collection = .history }
                    Button("Bookmarks", systemImage: "star") { collection = .saved }
                    Button("Downloads", systemImage: "arrow.down.to.line") { collection = .files }
                } label: {
                    Image(systemName: "ellipsis").font(.system(size: 21, weight: .semibold)).rotationEffect(.degrees(90)).frame(width: 42, height: 42)
                }
            }))

            HStack(spacing: 10) {
                Image(systemName: "globe").font(.system(size: 19, weight: .medium)).foregroundStyle(FlowPalette.secondary)
                TextField("Search or enter address", text: $input)
                    .font(.flowBody).focused($addressFocused).textInputAutocapitalization(.never).autocorrectionDisabled().keyboardType(.webSearch).submitLabel(.go).onSubmit(open)
                Button(action: open) {
                    Image(systemName: "arrow.right")
                        .font(.system(size: 19, weight: .bold)).foregroundStyle(FlowPalette.onAction)
                        .frame(width: 44, height: 44).background(FlowPalette.action).clipShape(Circle())
                }
                .buttonStyle(FlowPressButtonStyle()).accessibilityLabel("Go")
            }
            .padding(.leading, 15).padding(.trailing, 6).frame(height: 56)
            .background(FlowPalette.elevated).clipShape(RoundedRectangle(cornerRadius: 22, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: 22).stroke(FlowPalette.outline.opacity(0.6)))
            .shadow(color: .black.opacity(0.07), radius: 4, y: 2)
            .padding(.horizontal, 12).padding(.bottom, 5)
        }
        .background(FlowPalette.background)
    }

    private var favorites: some View {
        VStack(spacing: 2) {
            HStack {
                Text("Favorites").font(.flowTitleSmall)
                Spacer()
                Button("Edit") { collection = .saved }.font(.flowBodySmall).foregroundStyle(FlowPalette.secondary)
            }
            HStack(spacing: 12) {
                favorite("FlowGet", "FlowGetMark") { destination = AppConfig.authBaseURL }
                favorite("Google", "magnifyingglass") { destination = URL(string: "https://www.google.com") }
                favorite("Docs", "doc.text") { destination = URL(string: "https://docs.google.com") }
                favorite("Files", "folder") { collection = .files }
            }
        }
    }

    private var continueBrowsing: some View {
        VStack(spacing: 2) {
            HStack {
                Text("Continue browsing").font(.flowTitleSmall)
                Spacer()
                Button("Clear all") { store.browserHistory.removeAll() }
                    .font(.flowBodySmall).foregroundStyle(FlowPalette.secondary).disabled(store.browserHistory.isEmpty)
            }
            FlowCard(content: VStack(spacing: 0) {
                let links = store.browserHistory.isEmpty ? sampleLinks : Array(store.browserHistory.prefix(3))
                ForEach(Array(links.enumerated()), id: \.element.id) { index, link in
                    browserRow(link, badge: store.browserHistory.isEmpty ? (index == 0 ? "Start" : "Open") : relativeTime(link.visitedAt))
                    if index < links.count - 1 { Divider().overlay(FlowPalette.outline.opacity(0.45)) }
                }
            }, elevated: true)
        }
    }

    private var downloadPromo: some View {
        Button { destination = AppConfig.authBaseURL } label: {
            HStack(spacing: 16) {
                Image(systemName: "icloud.and.arrow.down")
                    .font(.system(size: 27, weight: .medium)).foregroundStyle(Color(red: 0.26, green: 0.52, blue: 0.80))
                    .frame(width: 52, height: 52).background(Color(red: 0.87, green: 0.92, blue: 0.99)).clipShape(Circle())
                VStack(alignment: .leading, spacing: 4) {
                    Text("Download with ease").font(.flowTitleSmall)
                    Text("Use FlowGet to download videos, images, and files quickly and securely.")
                        .font(.flowLabelSmall).foregroundStyle(FlowPalette.secondary).multilineTextAlignment(.leading)
                }
                Spacer(minLength: 0)
                Image(systemName: "arrow.right").foregroundStyle(FlowPalette.tertiary)
            }
            .padding(.horizontal, 16).padding(.vertical, 15)
            .background(FlowPalette.elevated).clipShape(RoundedRectangle(cornerRadius: 14))
            .overlay(RoundedRectangle(cornerRadius: 14).stroke(FlowPalette.outline.opacity(0.6)))
        }
        .buttonStyle(FlowPressButtonStyle())
    }

    private var sampleLinks: [BrowserLink] {
        [
            BrowserLink(title: "FlowGet - Fast & private downloads", url: AppConfig.authBaseURL),
            BrowserLink(title: "Google Docs", url: URL(string: "https://docs.google.com")!),
            BrowserLink(title: "Design inspiration", url: URL(string: "https://www.behance.net")!)
        ]
    }

    private func favorite(_ title: String, _ icon: String, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            VStack(spacing: 7) {
                Group {
                    if icon == "FlowGetMark" { FlowGetLogo(size: 27) }
                    else { Image(systemName: icon).font(.system(size: 22, weight: .medium)) }
                }
                .frame(width: 42, height: 42).background(FlowPalette.selected).clipShape(RoundedRectangle(cornerRadius: 11))
                Text(title).font(.flowLabel).lineLimit(1)
                Text(title == "FlowGet" ? "flowget.xyz" : title.lowercased() + ".com").font(.flowLabelSmall).foregroundStyle(FlowPalette.tertiary).lineLimit(1)
            }
            .frame(maxWidth: .infinity).frame(height: 110)
            .background(FlowPalette.elevated).clipShape(RoundedRectangle(cornerRadius: 14))
            .overlay(RoundedRectangle(cornerRadius: 14).stroke(FlowPalette.outline.opacity(0.35)))
            .shadow(color: .black.opacity(0.05), radius: 2, y: 1)
        }
        .buttonStyle(FlowPressButtonStyle())
    }

    private func browserRow(_ link: BrowserLink, badge: String) -> some View {
        Button { destination = link.url } label: {
            HStack(spacing: 12) {
                Image(systemName: "globe").font(.system(size: 16, weight: .medium)).foregroundStyle(FlowPalette.secondary)
                    .frame(width: 30, height: 30).background(FlowPalette.selected).clipShape(RoundedRectangle(cornerRadius: 8))
                VStack(alignment: .leading, spacing: 2) {
                    Text(link.title).font(.flowCaption).lineLimit(1)
                    Text(link.url.host ?? link.url.absoluteString).font(.flowLabelSmall).foregroundStyle(FlowPalette.secondary).lineLimit(1)
                }
                Spacer(minLength: 6)
                Text(badge).font(.flowLabelSmall).foregroundStyle(FlowPalette.secondary)
                    .padding(.horizontal, 10).frame(height: 25).background(FlowPalette.inset).clipShape(Capsule())
            }.padding(.horizontal, 12).frame(height: 58)
        }.buttonStyle(.plain)
    }

    private func open() {
        guard let url = URLInput.browserURL(from: input) else { return }
        addressFocused = false
        destination = url
    }

    private func relativeTime(_ date: Date) -> String {
        RelativeDateTimeFormatter().localizedString(for: date, relativeTo: Date())
    }
}

private enum BrowserCollection: String, Identifiable {
    case history = "History", saved = "Bookmarks", files = "Files", tabs = "Tabs"
    var id: String { rawValue }
}

private struct BrowserCollectionView: View {
    @EnvironmentObject private var store: AppStore
    @Environment(\.dismiss) private var dismiss
    let collection: BrowserCollection
    @Binding var destination: URL?

    var body: some View {
        NavigationStack {
            List {
                if collection == .files {
                    ForEach(store.downloads.items.filter { $0.status == .completed }) { item in
                        if let url = store.downloads.localURL(for: item) {
                            ShareLink(item: url) { Label(item.title, systemImage: "doc").lineLimit(1) }
                        }
                    }
                } else if collection == .tabs {
                    Label("Current private tab", systemImage: "globe").font(.flowBody)
                } else {
                    ForEach(collection == .history ? store.browserHistory : store.bookmarks) { link in
                        Button {
                            destination = link.url
                            dismiss()
                        } label: {
                            VStack(alignment: .leading, spacing: 4) {
                                Text(link.title).font(.flowTitleSmall).foregroundStyle(FlowPalette.content)
                                Text(link.url.absoluteString).font(.flowCaption).foregroundStyle(FlowPalette.secondary).lineLimit(1)
                            }
                        }
                    }
                    .onDelete { offsets in
                        if collection == .history { store.browserHistory.remove(atOffsets: offsets) }
                        else { store.bookmarks.remove(atOffsets: offsets) }
                    }
                }
            }
            .scrollContentBackground(.hidden).background(FlowPalette.background)
            .overlay { if isEmpty { ContentUnavailableView(collection.rawValue, systemImage: collection == .files ? "folder" : "tray") } }
            .navigationTitle(collection.rawValue).navigationBarTitleDisplayMode(.inline)
            .toolbar { ToolbarItem(placement: .confirmationAction) { Button("Done") { dismiss() } } }
        }
    }

    private var isEmpty: Bool {
        (collection == .history && store.browserHistory.isEmpty) ||
        (collection == .saved && store.bookmarks.isEmpty) ||
        (collection == .files && store.downloads.items.allSatisfy { $0.status != .completed })
    }
}

struct BrowserPage: View {
    @EnvironmentObject private var store: AppStore
    let initialURL: URL
    let settings: AppSettings
    @State private var currentURL: URL
    @State private var address: String
    @State private var title = "Browser"
    @State private var progress = 0.0
    @State private var canBack = false
    @State private var canForward = false
    @State private var webView: WKWebView
    @State private var showAdd = false

    init(initialURL: URL, settings: AppSettings) {
        self.initialURL = initialURL
        self.settings = settings
        _currentURL = State(initialValue: initialURL)
        _address = State(initialValue: initialURL.absoluteString)
        let configuration = WKWebViewConfiguration()
        configuration.websiteDataStore = .nonPersistent()
        configuration.allowsInlineMediaPlayback = true
        configuration.allowsPictureInPictureMediaPlayback = settings.pictureInPicture
        _webView = State(initialValue: WKWebView(frame: .zero, configuration: configuration))
    }

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 9) {
                Image(systemName: currentURL.scheme == "https" ? "lock" : "globe").foregroundStyle(FlowPalette.secondary)
                TextField("Search or enter address", text: $address)
                    .font(.flowBodySmall).textInputAutocapitalization(.never).autocorrectionDisabled().keyboardType(.URL).submitLabel(.go).onSubmit(navigate)
                Button(action: navigate) {
                    Image(systemName: "arrow.right").font(.system(size: 16, weight: .bold)).foregroundStyle(FlowPalette.onAction)
                        .frame(width: 36, height: 36).background(FlowPalette.action).clipShape(Circle())
                }.buttonStyle(FlowPressButtonStyle())
            }
            .padding(.leading, 14).padding(.trailing, 5).frame(height: 46)
            .background(FlowPalette.elevated).clipShape(Capsule()).overlay(Capsule().stroke(FlowPalette.outline.opacity(0.6)))
            .padding(.horizontal, 12).padding(.vertical, 6)

            if progress < 1 { ProgressView(value: progress).tint(FlowPalette.action).frame(height: 2) }
            WebContainer(webView: webView, url: initialURL,
                         contentBlocking: settings.contentBlocking,
                         aggressiveBlocking: settings.aggressiveBlocking,
                         popupBlocking: settings.popupBlocking,
                         currentURL: $currentURL, title: $title, progress: $progress,
                         canBack: $canBack, canForward: $canForward)
            HStack {
                browserAction("chevron.left", "Back", enabled: canBack) { webView.goBack() }
                Spacer(); browserAction("chevron.right", "Forward", enabled: canForward) { webView.goForward() }
                Spacer(); browserAction("arrow.clockwise", "Reload") { webView.reload() }
                Spacer(); browserAction("arrow.down.circle", "Download") { showAdd = true }
                Spacer(); browserAction(store.bookmarks.contains { $0.url == currentURL } ? "star.fill" : "star", "Bookmark") { store.toggleBookmark(title: title, url: currentURL) }
                Spacer(); ShareLink(item: currentURL) { Image(systemName: "square.and.arrow.up").frame(width: 34, height: 42) }
            }
            .font(.system(size: 18, weight: .medium)).padding(.horizontal, 20).frame(height: 52).background(.ultraThinMaterial)
        }
        .flowPage().navigationTitle(title).navigationBarTitleDisplayMode(.inline)
        .toolbar(.visible, for: .navigationBar)
        .onChange(of: currentURL) { _, value in address = value.absoluteString; store.addBrowserHistory(title: title, url: value) }
        .sheet(isPresented: $showAdd) { AddDownloadView(prefilledURL: currentURL).presentationDragIndicator(.visible) }
    }

    private func browserAction(_ icon: String, _ label: String, enabled: Bool = true, action: @escaping () -> Void) -> some View {
        Button(action: action) { Image(systemName: icon).frame(width: 34, height: 42) }.disabled(!enabled).accessibilityLabel(label)
    }

    private func navigate() {
        guard let url = URLInput.browserURL(from: address) else { return }
        currentURL = url
        webView.load(URLRequest(url: url))
    }
}

struct WebContainer: UIViewRepresentable {
    let webView: WKWebView
    let url: URL
    let contentBlocking: Bool
    let aggressiveBlocking: Bool
    let popupBlocking: Bool
    @Binding var currentURL: URL
    @Binding var title: String
    @Binding var progress: Double
    @Binding var canBack: Bool
    @Binding var canForward: Bool

    func makeCoordinator() -> Coordinator { Coordinator(self) }
    func makeUIView(context: Context) -> WKWebView {
        webView.navigationDelegate = context.coordinator
        webView.uiDelegate = context.coordinator
        webView.allowsBackForwardNavigationGestures = true
        webView.configuration.preferences.isElementFullscreenEnabled = true
        context.coordinator.observe(webView)
        if contentBlocking {
            let identifier = aggressiveBlocking ? "flowget-aggressive-v1" : "flowget-standard-v1"
            WKContentRuleListStore.default().compileContentRuleList(forIdentifier: identifier, encodedContentRuleList: Self.blockingRules(aggressive: aggressiveBlocking)) { ruleList, _ in
                DispatchQueue.main.async {
                    if let ruleList { webView.configuration.userContentController.add(ruleList) }
                    webView.load(URLRequest(url: url))
                }
            }
        } else { webView.load(URLRequest(url: url)) }
        return webView
    }
    func updateUIView(_ uiView: WKWebView, context: Context) {}

    private static func blockingRules(aggressive: Bool) -> String {
        let standard = ["*doubleclick.net", "*googlesyndication.com", "*google-analytics.com", "*facebook.net"]
        let strict = standard + ["*scorecardresearch.com", "*app-measurement.com", "*amazon-adsystem.com"]
        let domains = (aggressive ? strict : standard).map { "\"\($0)\"" }.joined(separator: ",")
        return "[{\"trigger\":{\"url-filter\":\".*\",\"if-domain\":[\(domains)]},\"action\":{\"type\":\"block\"}}]"
    }

    final class Coordinator: NSObject, WKNavigationDelegate, WKUIDelegate {
        var parent: WebContainer
        var observations: [NSKeyValueObservation] = []
        init(_ parent: WebContainer) { self.parent = parent }
        func observe(_ webView: WKWebView) {
            observations = [
                webView.observe(\.estimatedProgress) { [weak self] web, _ in DispatchQueue.main.async { self?.parent.progress = web.estimatedProgress } },
                webView.observe(\.url) { [weak self] web, _ in if let value = web.url { DispatchQueue.main.async { self?.parent.currentURL = value } } },
                webView.observe(\.title) { [weak self] web, _ in if let value = web.title, !value.isEmpty { DispatchQueue.main.async { self?.parent.title = value } } },
                webView.observe(\.canGoBack) { [weak self] web, _ in DispatchQueue.main.async { self?.parent.canBack = web.canGoBack } },
                webView.observe(\.canGoForward) { [weak self] web, _ in DispatchQueue.main.async { self?.parent.canForward = web.canGoForward } }
            ]
        }
        func webView(_ webView: WKWebView, decidePolicyFor navigationAction: WKNavigationAction, decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
            guard let scheme = navigationAction.request.url?.scheme?.lowercased() else { decisionHandler(.cancel); return }
            decisionHandler(["http", "https", "about"].contains(scheme) ? .allow : .cancel)
        }
        func webView(_ webView: WKWebView, createWebViewWith configuration: WKWebViewConfiguration,
                     for navigationAction: WKNavigationAction, windowFeatures: WKWindowFeatures) -> WKWebView? {
            guard navigationAction.targetFrame == nil else { return nil }
            if !parent.popupBlocking { webView.load(navigationAction.request) }
            return nil
        }
    }
}
