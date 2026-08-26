import SwiftUI
import UIKit

@main
struct FlowGetApp: App {
    @UIApplicationDelegateAdaptor(FlowGetAppDelegate.self) private var appDelegate
    @StateObject private var store = AppStore()

    var body: some Scene {
        WindowGroup {
            RootView()
                .environmentObject(store)
                .preferredColorScheme(store.settings.theme.colorScheme)
                .environment(\.font, .custom("Product Sans", size: 17, relativeTo: .body))
                .tint(FlowPalette.action)
                .onOpenURL { store.handleIncomingURL($0) }
                .onAppear {
                    BackgroundScheduler.runQueuedDownloads = { store.downloads.startQueuedDownloads() }
                    BackgroundScheduler.reschedule(store.schedules)
                }
        }
    }
}

final class FlowGetAppDelegate: NSObject, UIApplicationDelegate {
    static var backgroundSessionCompletion: (() -> Void)?

    func application(_ application: UIApplication,
                     didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]? = nil) -> Bool {
        BackgroundScheduler.register()
        return true
    }

    func application(_ application: UIApplication,
                     handleEventsForBackgroundURLSession identifier: String,
                     completionHandler: @escaping () -> Void) {
        Self.backgroundSessionCompletion = completionHandler
    }
}
