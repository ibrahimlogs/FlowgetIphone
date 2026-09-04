import Foundation
import SwiftUI
import UserNotifications
import UIKit

@MainActor
final class AppStore: ObservableObject {
    enum Session: Equatable { case restoring, signedOut, authenticated }
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
    @Published var incomingURL: URL?
    @Published var loginError: String?
    @Published var isAuthenticating = false
    @Published var license = LicenseSnapshot.notSynced
    @Published var isRefreshingLicense = false
    let downloads = DownloadManager()
    let flowShare = FlowShareCoordinator()
    private let auth = AuthService()
    private lazy var licensingService = LicensingService(auth: auth)
    private let googleSignIn = GoogleSignInService()
    private var tokens: AuthTokens?
    private var licenseHeartbeatTask: Task<Void, Never>?
    private var licenseRefreshTask: Task<Void, Never>?
    private var licenseRefreshGeneration: UUID?
    private var flowShareRequested = false

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
            Task { await refreshLicensing() }
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
            accept(result)
            await refreshLicensing()
        } catch { loginError = (error as? LocalizedError)?.errorDescription ?? error.localizedDescription }
    }

    func loginWithGoogle() async {
        guard !isAuthenticating else { return }
        isAuthenticating = true; loginError = nil
        defer { isAuthenticating = false }
        do {
            let credential = try await googleSignIn.signIn()
            let result = try await auth.google(
                idToken: credential.idToken,
                nonce: credential.nonce,
                deviceLabel: UIDevice.current.name
            )
            accept(result)
            await refreshLicensing()
        } catch {
            loginError = (error as? LocalizedError)?.errorDescription ?? error.localizedDescription
        }
    }

    private func refreshSession(_ stored: StoredSession) async {
        do {
            let result = try await auth.refresh(refreshToken: stored.tokens.refreshToken)
            account = result.account; tokens = result.tokens
            KeychainStore.save(StoredSession(account: result.account, tokens: result.tokens), account: "primary")
            session = .authenticated
            await refreshLicensing()
        } catch {
            KeychainStore.delete(account: "primary")
            tokens = nil; account = nil; session = .signedOut
            license = .notSynced
        }
    }

    func logout() {
        let token = tokens?.accessToken
        licenseHeartbeatTask?.cancel(); licenseHeartbeatTask = nil
        licenseRefreshTask?.cancel(); licenseRefreshTask = nil
        licenseRefreshGeneration = nil
        tokens = nil; account = nil; session = .signedOut
        license = .notSynced
        flowShareRequested = false
        KeychainStore.delete(account: "primary")
        googleSignIn.signOut()
        Task {
            await flowShare.stop()
            if let token {
                await licensingService.close(accessToken: token)
                await auth.revoke(token: token)
            } else {
                await licensingService.reset()
            }
        }
    }

    func refreshLicensing() async {
        if let activeRefresh = licenseRefreshTask {
            await activeRefresh.value
            return
        }
        let refresh = Task { @MainActor [weak self] in
            guard let self else { return }
            await self.performLicensingRefresh()
        }
        let generation = UUID()
        licenseRefreshTask = refresh
        licenseRefreshGeneration = generation
        await refresh.value
        if licenseRefreshGeneration == generation {
            licenseRefreshTask = nil
            licenseRefreshGeneration = nil
        }
    }

    private func performLicensingRefresh() async {
        guard session == .authenticated, let account else {
            license = .notSynced
            return
        }
        licenseHeartbeatTask?.cancel()
        licenseHeartbeatTask = nil
        isRefreshingLicense = true
        license = .syncing
        defer { isRefreshingLicense = false }
        do {
            let token = try await validAccessToken()
            let snapshot = await licensingService.synchronize(
                account: account,
                accessToken: token,
                deviceLabel: UIDevice.current.name
            )
            guard !Task.isCancelled,
                  session == .authenticated,
                  self.account?.id == account.id else { return }
            license = snapshot
            if flowShareRequested, let context = await licensingService.flowShareContext() {
                await flowShare.activate(context: context)
            } else if flowShareRequested {
                await flowShare.stop()
            }
            startLicenseHeartbeatIfNeeded()
        } catch {
            guard !Task.isCancelled,
                  session == .authenticated,
                  self.account?.id == account.id else { return }
            license = .unavailable(
                (error as? LocalizedError)?.errorDescription ?? error.localizedDescription,
                device: UIDevice.current.name
            )
        }
    }

    func activateFlowShare() async {
        flowShareRequested = true
        if let context = await licensingService.flowShareContext() {
            await flowShare.activate(context: context)
            return
        }
        await refreshLicensing()
        guard let context = await licensingService.flowShareContext() else {
            flowShare.errorMessage = "A verified FlowShare license is required. Refresh licensing and try again."
            return
        }
        await flowShare.activate(context: context)
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
        if GoogleSignInService.handle(url) { return }
        if let scheme = url.scheme?.lowercased(), ["http", "https"].contains(scheme) { incomingURL = url }
        else if url.scheme == "flowget", let value = URLComponents(url: url, resolvingAgainstBaseURL: false)?.queryItems?.first(where: { $0.name == "url" })?.value.flatMap(URL.init(string:)) { incomingURL = value }
    }

    private func accept(_ result: LoginResult) {
        account = result.account
        tokens = result.tokens
        KeychainStore.save(StoredSession(account: result.account, tokens: result.tokens), account: "primary")
        session = .authenticated
        activity.insert(ActivityItem(title: "Signed in", detail: result.account.email, kind: .system), at: 0)
    }

    private func validAccessToken() async throws -> String {
        guard let current = tokens else { throw AuthError.invalidResponse }
        if current.expiresAt > Date().addingTimeInterval(30) { return current.accessToken }
        let result = try await auth.refresh(refreshToken: current.refreshToken)
        account = result.account
        tokens = result.tokens
        KeychainStore.save(StoredSession(account: result.account, tokens: result.tokens), account: "primary")
        return result.tokens.accessToken
    }

    private func startLicenseHeartbeatIfNeeded() {
        licenseHeartbeatTask?.cancel()
        guard license.kind == .paid || license.kind == .trial else { return }
        licenseHeartbeatTask = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 10 * 60 * 1_000_000_000)
                guard !Task.isCancelled, let self, self.session == .authenticated else { return }
                guard let token = try? await self.validAccessToken() else { continue }
                if let snapshot = await self.licensingService.heartbeat(accessToken: token) {
                    self.license = snapshot
                    if self.flowShareRequested,
                       let context = await self.licensingService.flowShareContext() {
                        await self.flowShare.activate(context: context)
                    }
                }
            }
        }
    }

    private struct StoredSession: Codable { let account: FlowGetAccount; let tokens: AuthTokens }
}

private extension String {
    var nonEmpty: String? { isEmpty ? nil : self }
}
