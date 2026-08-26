import SwiftUI

struct RootView: View {
    @EnvironmentObject private var store: AppStore

    var body: some View {
        Group {
            switch store.session {
            case .restoring:
                VStack(spacing: 16) { ProgressView(); Text("Restoring your account…").foregroundStyle(.secondary) }
                    .frame(maxWidth: .infinity, maxHeight: .infinity).flowPage()
            case .signedOut: LoginView()
            case .authenticated: MainShellView()
            }
        }
        .animation(.easeInOut(duration: 0.2), value: sessionKey)
    }

    private var sessionKey: Int {
        switch store.session { case .restoring: 0; case .signedOut: 1; case .authenticated: 2 }
    }
}
