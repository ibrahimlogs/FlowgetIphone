import Foundation
import GoogleSignIn
import Security
import UIKit

struct GoogleCredential {
    let idToken: String
    let nonce: String
}

enum GoogleSignInFlowError: LocalizedError {
    case notConfigured
    case presenterUnavailable
    case cancelled
    case missingIDToken
    case failed(String)

    var errorDescription: String? {
        switch self {
        case .notConfigured:
            "Google Sign-In needs the FlowGet iOS OAuth client ID and reversed URL scheme."
        case .presenterUnavailable:
            "Google Sign-In could not open from the current screen."
        case .cancelled:
            "Google Sign-In was cancelled."
        case .missingIDToken:
            "Google did not return a valid identity token."
        case .failed(let message):
            message
        }
    }
}

@MainActor
final class GoogleSignInService {
    static func handle(_ url: URL) -> Bool {
        GIDSignIn.sharedInstance.handle(url)
    }

    func signIn() async throws -> GoogleCredential {
        guard let clientID = AppConfig.googleIOSClientID,
              let serverClientID = AppConfig.googleServerClientID,
              Self.hasRegisteredScheme(for: clientID) else {
            throw GoogleSignInFlowError.notConfigured
        }
        guard let presenter = Self.presentingViewController() else {
            throw GoogleSignInFlowError.presenterUnavailable
        }

        let nonce = try Self.randomNonce()
        GIDSignIn.sharedInstance.configuration = GIDConfiguration(
            clientID: clientID,
            serverClientID: serverClientID
        )

        return try await withCheckedThrowingContinuation { continuation in
            GIDSignIn.sharedInstance.signIn(
                withPresenting: presenter,
                hint: nil,
                additionalScopes: nil,
                nonce: nonce
            ) { result, error in
                if let error {
                    let nsError = error as NSError
                    if nsError.domain == kGIDSignInErrorDomain,
                       nsError.code == GIDSignInError.canceled.rawValue {
                        continuation.resume(throwing: GoogleSignInFlowError.cancelled)
                    } else {
                        continuation.resume(throwing: GoogleSignInFlowError.failed(error.localizedDescription))
                    }
                    return
                }
                guard let token = result?.user.idToken?.tokenString, !token.isEmpty else {
                    continuation.resume(throwing: GoogleSignInFlowError.missingIDToken)
                    return
                }
                continuation.resume(returning: GoogleCredential(idToken: token, nonce: nonce))
            }
        }
    }

    func signOut() { GIDSignIn.sharedInstance.signOut() }

    private static func randomNonce() throws -> String {
        var bytes = [UInt8](repeating: 0, count: 32)
        guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else {
            throw GoogleSignInFlowError.failed("A secure Google Sign-In request could not be created.")
        }
        return Data(bytes).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    private static func hasRegisteredScheme(for clientID: String) -> Bool {
        let suffix = ".apps.googleusercontent.com"
        guard clientID.hasSuffix(suffix) else { return false }
        let identifier = String(clientID.dropLast(suffix.count))
        let expected = "com.googleusercontent.apps.\(identifier)"
        let types = Bundle.main.object(forInfoDictionaryKey: "CFBundleURLTypes") as? [[String: Any]] ?? []
        return types.contains { type in
            (type["CFBundleURLSchemes"] as? [String])?.contains(expected) == true
        }
    }

    private static func presentingViewController() -> UIViewController? {
        let scenes = UIApplication.shared.connectedScenes.compactMap { $0 as? UIWindowScene }
        let window = scenes
            .flatMap(\.windows)
            .first(where: \.isKeyWindow)
        var presenter = window?.rootViewController
        while let presented = presenter?.presentedViewController { presenter = presented }
        return presenter
    }
}
