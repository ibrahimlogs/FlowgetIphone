import SwiftUI

struct RootView: View {
    @EnvironmentObject private var store: AppStore

    var body: some View {
        Group {
            switch store.session {
            case .restoring: RestoringView()
            case .signedOut: LoginView()
            case .authenticated: MainShellView()
            }
        }
        .animation(FlowMotion.standard, value: sessionKey)
    }

    private var sessionKey: Int {
        switch store.session { case .restoring: 0; case .signedOut: 1; case .authenticated: 2 }
    }
}

private struct RestoringView: View {
    @State private var spinning = false

    var body: some View {
        VStack(spacing: 16) {
            Spacer()
            ZStack {
                Circle().fill(FlowPalette.inset).frame(width: 112, height: 112)
                Circle()
                    .trim(from: 0.12, to: 0.78)
                    .stroke(FlowPalette.content, style: StrokeStyle(lineWidth: 3, lineCap: .round))
                    .frame(width: 94, height: 94)
                    .rotationEffect(.degrees(spinning ? 360 : 0))
                FlowGetLogo(size: 58)
            }
            Text("FlowGet").font(.flowHeadline)
            Text("Restoring your account…")
                .font(.flowBodySmall)
                .foregroundStyle(FlowPalette.secondary)
            Spacer()
            Text("Fast downloads. Smart transfer.")
                .font(.flowCaption)
                .foregroundStyle(FlowPalette.tertiary)
                .padding(.bottom, 24)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .flowPage()
        .onAppear {
            withAnimation(.linear(duration: 1).repeatForever(autoreverses: false)) { spinning = true }
        }
    }
}
