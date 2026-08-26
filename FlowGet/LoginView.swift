import SwiftUI

struct LoginView: View {
    @EnvironmentObject private var store: AppStore
    @State private var email = ""
    @State private var password = ""
    @State private var showPassword = false
    @Environment(\.openURL) private var openURL

    var body: some View {
        ScrollView {
            VStack(spacing: 0) {
                Spacer(minLength: 70)
                ZStack {
                    Circle().stroke(FlowPalette.outline, lineWidth: 1).frame(width: 112, height: 112)
                    FlowGetLogo(size: 62)
                }
                .padding(.bottom, 24)
                Text("Welcome back").font(.largeTitle.bold())
                Text("Sign in to sync your downloads\nand devices")
                    .multilineTextAlignment(.center).foregroundStyle(.secondary).padding(.top, 8)

                VStack(spacing: 14) {
                    field("Email", icon: "envelope", text: $email)
                        .textInputAutocapitalization(.never).keyboardType(.emailAddress).textContentType(.emailAddress)
                    HStack {
                        Image(systemName: "lock")
                        Group {
                            if showPassword { TextField("Password", text: $password) }
                            else { SecureField("Password", text: $password) }
                        }.textContentType(.password)
                        Button { showPassword.toggle() } label: { Image(systemName: showPassword ? "eye.slash" : "eye") }
                    }
                    .padding(.horizontal, 16).frame(height: 58)
                    .background(FlowPalette.surface).clipShape(RoundedRectangle(cornerRadius: 14))
                    .overlay(RoundedRectangle(cornerRadius: 14).stroke(FlowPalette.outline))

                    HStack {
                        Spacer()
                        Button("Forgot password?") { openURL(AppConfig.passwordResetURL) }.font(.subheadline.bold())
                    }

                    if let error = store.loginError {
                        Text(error).font(.footnote).foregroundStyle(FlowPalette.danger)
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }

                    FlowPrimaryButton(title: store.isAuthenticating ? "Signing in…" : "Sign in", disabled: store.isAuthenticating) {
                        Task { await store.login(email: email, password: password) }
                    }

                    HStack { Rectangle().frame(height: 1); Text("or").font(.footnote); Rectangle().frame(height: 1) }
                        .foregroundStyle(FlowPalette.outline).padding(.vertical, 6)
                    Button { openURL(AppConfig.authBaseURL) } label: {
                        Label("Create account", systemImage: "person.badge.plus")
                            .frame(maxWidth: .infinity, minHeight: 50).fontWeight(.semibold)
                            .overlay(RoundedRectangle(cornerRadius: 14).stroke(FlowPalette.outline))
                    }
                }
                .padding(.top, 34)
                Text("By continuing, you agree to FlowGet's terms and privacy policy.")
                    .font(.caption).foregroundStyle(.tertiary).multilineTextAlignment(.center).padding(.top, 28)
            }
            .padding(.horizontal, 26)
        }
        .scrollDismissesKeyboard(.interactively)
        .flowPage()
    }

    private func field(_ title: String, icon: String, text: Binding<String>) -> some View {
        HStack { Image(systemName: icon); TextField(title, text: text) }
            .padding(.horizontal, 16).frame(height: 58)
            .background(FlowPalette.surface).clipShape(RoundedRectangle(cornerRadius: 14))
            .overlay(RoundedRectangle(cornerRadius: 14).stroke(FlowPalette.outline))
    }
}
