import SwiftUI
import WebKit

struct BrowserHomeView: View {
    @EnvironmentObject private var store: AppStore
    @State private var input = ""
    @State private var destination: URL?
    @State private var collection: BrowserCollection?
    let openMenu: () -> Void

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 20) {
                    HStack(spacing: 14) {
                        Image(systemName: "magnifyingglass").font(.title2)
                        TextField("Paste a link or search", text: $input).textInputAutocapitalization(.never).keyboardType(.webSearch).onSubmit(open)
                        Button(action: open) { Image(systemName: "arrow.right").font(.title2.bold()).foregroundStyle(FlowPalette.onAction).frame(width: 52, height: 52).background(FlowPalette.action).clipShape(Circle()) }
                    }
                    .padding(.leading, 16).padding(.trailing, 8).frame(height: 64)
                    .background(FlowPalette.surface).clipShape(RoundedRectangle(cornerRadius: 18)).overlay(RoundedRectangle(cornerRadius: 18).stroke(FlowPalette.outline))

                    FlowCard(content: HStack(spacing: 14) {
                        FlowIcon(name: "globe.americas.fill")
                        VStack(alignment: .leading, spacing: 5) { Text("Private link browser").font(.headline); Text("Open download pages without leaving FlowGet.").font(.subheadline).foregroundStyle(.secondary) }
                        Spacer(); Text("Private").font(.caption.bold()).foregroundStyle(FlowPalette.success).padding(.horizontal, 12).padding(.vertical, 7).background(FlowPalette.success.opacity(0.12)).clipShape(Capsule())
                    }.padding(16))

                    FlowSectionTitle(title: "Quick access")
                    HStack(spacing: 12) {
                        quick("History", "clock.arrow.circlepath") { collection = .history }
                        quick("Saved", "star") { collection = .saved }
                        quick("Files", "folder") { collection = .files }
                    }

                    FlowSectionTitle(title: "Recent links")
                    FlowCard(content: VStack(spacing: 0) {
                        if store.browserHistory.isEmpty {
                            linkRow(BrowserLink(title: "FlowGet", url: AppConfig.authBaseURL))
                        } else {
                            ForEach(Array(store.browserHistory.prefix(5)).enumerated(), id: \.element.id) { index, link in
                                linkRow(link)
                                if index < min(4, store.browserHistory.count - 1) { Divider().padding(.leading, 68) }
                            }
                        }
                    })
                }.padding(18).padding(.bottom, 10)
            }
            .toolbar { ToolbarItem(placement: .topBarLeading) { Button(action: openMenu) { Image(systemName: "line.3.horizontal").font(.title2.bold()) } }; ToolbarItem(placement: .principal) { Text("Browser").font(.largeTitle.bold()) } }
            .toolbarTitleDisplayMode(.inline).flowPage()
            .navigationDestination(item: $destination) { url in BrowserPage(initialURL: url, settings: store.settings) }
            .sheet(item: $collection) { value in BrowserCollectionView(collection: value, destination: $destination) }
        }
    }

    private func quick(_ title: String, _ icon: String, action: @escaping () -> Void) -> some View {
        Button(action: action) { VStack(spacing: 9) { Image(systemName: icon).font(.title2); Text(title).font(.subheadline.bold()) }.frame(maxWidth: .infinity, minHeight: 96).background(FlowPalette.surface).clipShape(RoundedRectangle(cornerRadius: 18)).overlay(RoundedRectangle(cornerRadius: 18).stroke(FlowPalette.outline)) }
    }
    private func linkRow(_ link: BrowserLink) -> some View {
        Button { destination = link.url } label: {
            HStack(spacing: 14) { FlowIcon(name: "globe"); VStack(alignment: .leading) { Text(link.title).font(.headline); Text(link.url.host ?? link.url.absoluteString).font(.subheadline).foregroundStyle(.secondary) }; Spacer(); Image(systemName: "arrow.right").font(.title2).foregroundStyle(.secondary) }.padding(14)
        }.foregroundStyle(FlowPalette.content)
    }
    private func open() {
        destination = URLInput.browserURL(from: input)
    }
}

private enum BrowserCollection: String, Identifiable {
    case history = "History", saved = "Saved", files = "Files"
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
                            ShareLink(item: url) {
                                Label(item.title, systemImage: "doc").lineLimit(1)
                            }
                        }
                    }
                } else {
                    ForEach(collection == .history ? store.browserHistory : store.bookmarks) { link in
                        Button {
                            destination = link.url
                            dismiss()
                        } label: {
                            VStack(alignment: .leading, spacing: 4) {
                                Text(link.title).font(.headline).foregroundStyle(FlowPalette.content)
                                Text(link.url.absoluteString).font(.caption).foregroundStyle(.secondary).lineLimit(1)
                            }
                        }
                    }
                    .onDelete { offsets in
                        if collection == .history { store.browserHistory.remove(atOffsets: offsets) }
                        else { store.bookmarks.remove(atOffsets: offsets) }
                    }
                }
            }
            .overlay {
                if (collection == .history && store.browserHistory.isEmpty) ||
                    (collection == .saved && store.bookmarks.isEmpty) ||
                    (collection == .files && store.downloads.items.allSatisfy { $0.status != .completed }) {
                    ContentUnavailableView(collection.rawValue, systemImage: collection == .files ? "folder" : "tray")
                }
            }
            .navigationTitle(collection.rawValue)
            .toolbar { ToolbarItem(placement: .confirmationAction) { Button("Done") { dismiss() } } }
        }
    }
}

struct BrowserPage: View {
    @EnvironmentObject private var store: AppStore
    let initialURL: URL
    let settings: AppSettings
    @State private var currentURL: URL
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
        let configuration = WKWebViewConfiguration()
        configuration.websiteDataStore = .nonPersistent()
        configuration.allowsInlineMediaPlayback = true
        configuration.allowsPictureInPictureMediaPlayback = settings.pictureInPicture
        _webView = State(initialValue: WKWebView(frame: .zero, configuration: configuration))
    }

    var body: some View {
        VStack(spacing: 0) {
            if progress < 1 { ProgressView(value: progress).tint(FlowPalette.action) }
            WebContainer(webView: webView, url: initialURL,
                         contentBlocking: settings.contentBlocking,
                         aggressiveBlocking: settings.aggressiveBlocking,
                         popupBlocking: settings.popupBlocking,
                         currentURL: $currentURL, title: $title, progress: $progress,
                         canBack: $canBack, canForward: $canForward)
            HStack {
                Button { webView.goBack() } label: { Image(systemName: "chevron.left") }.disabled(!canBack)
                Spacer(); Button { webView.goForward() } label: { Image(systemName: "chevron.right") }.disabled(!canForward)
                Spacer(); Button { webView.reload() } label: { Image(systemName: "arrow.clockwise") }
                Spacer(); Button { showAdd = true } label: { Image(systemName: "arrow.down.circle") }
                Spacer(); Button { store.toggleBookmark(title: title, url: currentURL) } label: { Image(systemName: store.bookmarks.contains { $0.url == currentURL } ? "star.fill" : "star") }
                Spacer(); ShareLink(item: currentURL) { Image(systemName: "square.and.arrow.up") }
            }.font(.title3).padding(.horizontal, 26).frame(height: 52).background(FlowPalette.surface)
        }
        .navigationTitle(title).navigationBarTitleDisplayMode(.inline)
        .onChange(of: currentURL) { _, value in store.addBrowserHistory(title: title, url: value) }
        .sheet(isPresented: $showAdd) { AddDownloadView(prefilledURL: currentURL) }
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
            WKContentRuleListStore.default().compileContentRuleList(
                forIdentifier: identifier,
                encodedContentRuleList: Self.blockingRules(aggressive: aggressiveBlocking)
            ) { ruleList, _ in
                DispatchQueue.main.async {
                    if let ruleList { webView.configuration.userContentController.add(ruleList) }
                    webView.load(URLRequest(url: url))
                }
            }
        } else {
            webView.load(URLRequest(url: url))
        }
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
                     for navigationAction: WKNavigationAction,
                     windowFeatures: WKWindowFeatures) -> WKWebView? {
            guard navigationAction.targetFrame == nil else { return nil }
            if !parent.popupBlocking { webView.load(navigationAction.request) }
            return nil
        }
    }
}
