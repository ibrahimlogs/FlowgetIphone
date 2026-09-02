import Foundation

enum AppConfig {
    static let version = "0.1.0"
    static let authBaseURL = URL(string: "https://flowget.xyz/")!
    static let workerBaseURL = URL(string: "https://flowget-worker-v2-production.flowget-api.workers.dev/")!
    static let flowShareBaseURL = URL(string: "https://share.flowget.xyz/")!
    static let clientID = Bundle.main.object(forInfoDictionaryKey: "FLOWGET_IOS_CLIENT_ID") as? String
        ?? "flowget-ios-client-not-registered"
    static var googleIOSClientID: String? { configuredValue(for: "GIDClientID") }
    static var googleServerClientID: String? { configuredValue(for: "GIDServerClientID") }
    static let passwordResetURL = URL(string: "https://flowget.xyz/customer/forgot-password")!
    static let privacyURL = URL(string: "https://flowget.xyz/privacy-policy")!
    static let contactURL = URL(string: "https://flowget.xyz/contact")!

    private static func configuredValue(for key: String) -> String? {
        guard let value = Bundle.main.object(forInfoDictionaryKey: key) as? String else { return nil }
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, !trimmed.contains("CONFIGURE_") else { return nil }
        return trimmed
    }
}
