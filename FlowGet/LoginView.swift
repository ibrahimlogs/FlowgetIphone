import SwiftUI

struct LoginView: View {
    private enum Field { case email, password }

    @EnvironmentObject private var store: AppStore
    @Environment(\.openURL) private var openURL
    @FocusState private var focusedField: Field?
    @State private var email = ""
    @State private var password = ""
    @State private var showPassword = false

    private var canSubmit: Bool {
        !store.isAuthenticating && !email.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty && !password.isEmpty
    }

    var body: some View {
        GeometryReader { proxy in
            ScrollView {
                VStack(spacing: 0) {
                    Spacer(minLength: 28)
                    FlowGetLogo(size: 76)
                    Text("FlowGet")
                        .font(.flowHeadline)
                        .padding(.top, 14)
                    Text("Welcome back")
                        .font(.custom("Product Sans", size: 24).weight(.bold))
                        .padding(.top, 28)
                    Text("Sign in to sync your downloads\nand devices")
                        .font(.flowBody)
                        .foregroundStyle(FlowPalette.secondary)
                        .multilineTextAlignment(.center)
                        .padding(.top, 6)

                    VStack(spacing: 12) {
                        inputField(title: "Email", icon: "envelope", text: $email)
                            .focused($focusedField, equals: .email)
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                            .keyboardType(.emailAddress)
                            .textContentType(.emailAddress)
                            .submitLabel(.next)
                            .onSubmit { focusedField = .password }

                        HStack(spacing: 12) {
                            Image(systemName: "lock")
                                .font(.system(size: 18, weight: .regular))
                                .foregroundStyle(FlowPalette.secondary)
                                .frame(width: 24)
                            Group {
                                if showPassword {
                                    TextField("Password", text: $password)
                                } else {
                                    SecureField("Password", text: $password)
                                }
                            }
                            .font(.flowBody)
                            .focused($focusedField, equals: .password)
                            .textContentType(.password)
                            .submitLabel(.go)
                            .onSubmit(signIn)
                            Button { showPassword.toggle() } label: {
                                Image(systemName: showPassword ? "eye.slash" : "eye")
                                    .font(.system(size: 18, weight: .regular))
                                    .foregroundStyle(FlowPalette.secondary)
                                    .frame(width: 34, height: 44)
                            }
                            .buttonStyle(.plain)
                            .accessibilityLabel(showPassword ? "Hide password" : "Show password")
                        }
                        .padding(.horizontal, 16)
                        .frame(height: 58)
                        .background(FlowPalette.surface)
                        .clipShape(RoundedRectangle(cornerRadius: FlowRadius.medium, style: .continuous))
                        .overlay(RoundedRectangle(cornerRadius: FlowRadius.medium).stroke(FlowPalette.outline))

                        HStack {
                            Spacer()
                            Button("Forgot password?") { openURL(AppConfig.passwordResetURL) }
                                .font(.flowBodySmall.weight(.medium))
                                .foregroundStyle(FlowPalette.content)
                        }

                        if let error = store.loginError {
                            Text(error)
                                .font(.flowCaption)
                                .foregroundStyle(FlowPalette.danger)
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .transition(.opacity.combined(with: .move(edge: .top)))
                        }

                        FlowPrimaryButton(
                            title: store.isAuthenticating ? "Signing in…" : "Sign in",
                            disabled: !canSubmit,
                            action: signIn
                        )

                        HStack(spacing: 12) {
                            Rectangle().frame(height: 1)
                            Text("or").font(.flowBodySmall)
                            Rectangle().frame(height: 1)
                        }
                        .foregroundStyle(FlowPalette.outline)
                        .padding(.vertical, 10)

                        FlowOutlineButton(title: "Create account", icon: "person.badge.plus") {
                            openURL(AppConfig.authBaseURL)
                        }
                    }
                    .padding(.top, 24)

                    Text("By continuing, you agree to FlowGet's terms and privacy policy.")
                        .font(.flowLabel)
                        .foregroundStyle(FlowPalette.tertiary)
                        .multilineTextAlignment(.center)
                        .padding(.top, 24)
                    Spacer(minLength: 26)
                }
                .frame(maxWidth: 420)
                .frame(minHeight: proxy.size.height)
                .padding(.horizontal, 24)
                .frame(maxWidth: .infinity)
            }
            .scrollDismissesKeyboard(.interactively)
        }
        .flowPage()
        .animation(FlowMotion.standard, value: store.loginError)
    }

    private func inputField(title: String, icon: String, text: Binding<String>) -> some View {
        HStack(spacing: 12) {
            Image(systemName: icon)
                .font(.system(size: 18, weight: .regular))
                .foregroundStyle(FlowPalette.secondary)
                .frame(width: 24)
            TextField(title, text: text).font(.flowBody)
        }
        .padding(.horizontal, 16)
        .frame(height: 58)
        .background(FlowPalette.surface)
        .clipShape(RoundedRectangle(cornerRadius: FlowRadius.medium, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: FlowRadius.medium).stroke(FlowPalette.outline))
    }

    private func signIn() {
        guard canSubmit else { return }
        focusedField = nil
        Task { await store.login(email: email, password: password) }
    }
}
