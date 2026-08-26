import Foundation
import SwiftUI
import UserNotifications
import UIKit

@MainActor
final class AppStore: ObservableObject {
    enum Session { case restoring, signedOut, authenticated }
    @Published var session: Session = .restoring
    @Published var account: FlowGetAccount?
    @Published var settings: AppSettings {
        didSet {
            Persistence.save(settings, name: "settings.json")
            downloads.apply(settings: settings)
        }
    }
    @Published var activity: [ActivityItem] { didSet { Persistence.save(activity, name: "activity.json") } }
    @Published var browserHistory: [BrowserLink] { didSet { Persistence.save(browserHistory, name: "browser-history.json") } }
    @Published var bookmarks: [BrowserLink] { didSet { Persistence.save(bookmarks, name: "bookmarks.json") } }
    @Published var schedules: [DownloadSchedule] {
        didSet {
            Persistence.save(schedules, name: "schedules.json")
            BackgroundScheduler.reschedule(schedules)
        }
    }
    @Published var flowShareDevices: [FlowShareDevice] = []
    @Published var flowShareInvite: FlowShareInvite?
    @Published var flowShareTransfers: [FlowShareTransfer] = []
    @Published var incomingURL: URL?
    @Published var loginError: String?
    @Published var isAuthenticating = false
    let downloads = DownloadManager()
    private let auth = AuthService()
    private var tokens: AuthTokens?

    init() {
        settings = Persistence.load(AppSettings.self, name: "settings.json", fallback: AppSettings())
        activity = Persistence.load([ActivityItem].self, name: "activity.json", fallback: [])
        browserHistory = Persistence.load([BrowserLink].self, name: "browser-history.json", fallback: [])
        bookmarks = Persistence.load([BrowserLink].self, name: "bookmarks.json", fallback: [])
        schedules = Persistence.load([DownloadSchedule].self, name: "schedules.json", fallback: [])
        downloads.onActivity = { [weak self] item in self?.activity.insert(item, at: 0) }
        downloads.apply(settings: settings)
        if settings.notifications {
            UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound, .badge]) { _, _ in }
        }
        restoreSession()
    }

    func restoreSession() {
        guard let stored = KeychainStore.load(StoredSession.self, account: "primary") else {
            session = .signedOut
            return
        }
        if stored.tokens.expiresAt > Date().addingTimeInterval(30) {
            tokens = stored.tokens; account = stored.account; session = .authenticated
        } else {
            Task { await refreshSession(stored) }
        }
    }

    func login(email: String, password: String) async {
        guard !email.isEmpty, !password.isEmpty else { loginError = "Enter your email and password."; return }
        isAuthenticating = true; loginError = nil
        defer { isAuthenticating = false }
        do {
            let result = try await auth.login(email: email, password: password, deviceLabel: UIDevice.current.name)
            account = result.account; tokens = result.tokens
            KeychainStore.save(StoredSession(account: result.account, tokens: result.tokens), account: "primary")
            session = .authenticated
            activity.insert(ActivityItem(title: "Signed in", detail: result.account.email, kind: .system), at: 0)
        } catch { loginError = (error as? LocalizedError)?.errorDescription ?? error.localizedDescription }
    }

    private func refreshSession(_ stored: StoredSession) async {
        do {
            let result = try await auth.refresh(refreshToken: stored.tokens.refreshToken)
            account = result.account; tokens = result.tokens
            KeychainStore.save(StoredSession(account: result.account, tokens: result.tokens), account: "primary")
            session = .authenticated
        } catch {
            KeychainStore.delete(account: "primary")
            tokens = nil; account = nil; session = .signedOut
        }
    }

    func logout() {
        let token = tokens?.accessToken
        tokens = nil; account = nil; session = .signedOut
        KeychainStore.delete(account: "primary")
        if let token { Task { await auth.revoke(token: token) } }
    }

    func addBrowserHistory(title: String, url: URL) {
        browserHistory.removeAll { $0.url == url }
        browserHistory.insert(BrowserLink(title: title.nonEmpty ?? url.host ?? "Website", url: url), at: 0)
        browserHistory = Array(browserHistory.prefix(100))
    }

    func toggleBookmark(title: String, url: URL) {
        if let index = bookmarks.firstIndex(where: { $0.url == url }) { bookmarks.remove(at: index) }
        else { bookmarks.insert(BrowserLink(title: title.nonEmpty ?? url.host ?? "Website", url: url), at: 0) }
    }

    func handleIncomingURL(_ url: URL) {
        if let scheme = url.scheme?.lowercased(), ["http", "https"].contains(scheme) { incomingURL = url }
        else if url.scheme == "flowget", let value = URLComponents(url: url, resolvingAgainstBaseURL: false)?.queryItems?.first(where: { $0.name == "url" })?.value.flatMap(URL.init(string:)) { incomingURL = value }
    }

    private struct StoredSession: Codable { let account: FlowGetAccount; let tokens: AuthTokens }
}

private extension String {
    var nonEmpty: String? { isEmpty ? nil : self }
}
