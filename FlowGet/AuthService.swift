import Foundation

enum AuthError: LocalizedError {
    case invalidCredentials, unverified, suspended, rateLimited, invalidClient, server(String), invalidResponse
    var errorDescription: String? {
        switch self {
        case .invalidCredentials: "Email or password is incorrect."
        case .unverified: "Verify your email before signing in."
        case .suspended: "This account is not currently available."
        case .rateLimited: "Too many attempts. Please wait and try again."
        case .invalidClient: "The iPhone client must be enabled by the FlowGet server."
        case .server(let message): message
        case .invalidResponse: "FlowGet returned an unexpected response."
        }
    }
}

struct LoginResult {
    var account: FlowGetAccount
    var tokens: AuthTokens
}

actor AuthService {
    private struct LoginRequest: Encodable {
        let clientID: String, email: String, password: String, platform: String, deviceLabel: String
        enum CodingKeys: String, CodingKey { case clientID = "client_id", email, password, platform, deviceLabel = "device_label" }
    }
    private struct Envelope: Decodable {
        struct Payload: Decodable {
            struct AccountDTO: Decodable {
                let accountID: String, email: String, status: String, emailVerified: Bool
                enum CodingKeys: String, CodingKey { case accountID = "account_id", email, status, emailVerified = "email_verified" }
            }
            let accessToken: String, expiresIn: Int, refreshToken: String, account: AccountDTO
            enum CodingKeys: String, CodingKey { case accessToken = "access_token", expiresIn = "expires_in", refreshToken = "refresh_token", account }
        }
        let ok: Bool
        let data: Payload
    }
    private struct RefreshRequest: Encodable {
        let refreshToken: String
        enum CodingKeys: String, CodingKey { case refreshToken = "refresh_token" }
    }
    private struct ErrorEnvelope: Decodable { struct Detail: Decodable { let code: String; let message: String }; let error: Detail }
    private let session: URLSession

    init() {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = 30
        configuration.httpCookieStorage = nil
        configuration.urlCredentialStorage = nil
        session = URLSession(configuration: configuration, delegate: NoRedirectDelegate(), delegateQueue: nil)
    }

    func login(email: String, password: String, deviceLabel: String) async throws -> LoginResult {
        let url = AppConfig.authBaseURL.appendingPathComponent("api/v2/auth/login")
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.timeoutInterval = 30
        request.httpBody = try JSONEncoder().encode(LoginRequest(clientID: AppConfig.clientID,
                                                                  email: email.trimmingCharacters(in: .whitespacesAndNewlines),
                                                                  password: password,
                                                                  platform: "ios",
                                                                  deviceLabel: deviceLabel))
        return try await tokenRequest(request)
    }

    func refresh(refreshToken: String) async throws -> LoginResult {
        let url = AppConfig.authBaseURL.appendingPathComponent("api/v2/auth/refresh")
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONEncoder().encode(RefreshRequest(refreshToken: refreshToken))
        return try await tokenRequest(request)
    }

    private func tokenRequest(_ request: URLRequest) async throws -> LoginResult {
        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse else { throw AuthError.invalidResponse }
        guard (200..<300).contains(http.statusCode) else {
            let detail = try? JSONDecoder().decode(ErrorEnvelope.self, from: data).error
            switch detail?.code {
            case "INVALID_CREDENTIALS": throw AuthError.invalidCredentials
            case "EMAIL_NOT_VERIFIED", "ACCOUNT_UNVERIFIED": throw AuthError.unverified
            case "ACCOUNT_SUSPENDED", "ACCOUNT_INACTIVE": throw AuthError.suspended
            case "RATE_LIMITED": throw AuthError.rateLimited
            case "INVALID_NATIVE_CLIENT", "INVALID_PLATFORM": throw AuthError.invalidClient
            default: throw AuthError.server(detail?.message ?? "Sign in failed (HTTP \(http.statusCode)).")
            }
        }
        let envelope = try JSONDecoder().decode(Envelope.self, from: data)
        let dto = envelope.data.account
        let name = dto.email.split(separator: "@").first.map(String.init) ?? "FlowGet user"
        return LoginResult(account: FlowGetAccount(id: dto.accountID, name: name, email: dto.email, emailVerified: dto.emailVerified),
                           tokens: AuthTokens(accessToken: envelope.data.accessToken,
                                              refreshToken: envelope.data.refreshToken,
                                              expiresAt: Date().addingTimeInterval(TimeInterval(envelope.data.expiresIn))))
    }

    func revoke(token: String) async {
        var request = URLRequest(url: AppConfig.authBaseURL.appendingPathComponent("api/v2/auth/revoke"))
        request.httpMethod = "POST"
        request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        _ = try? await session.data(for: request)
    }
}

private final class NoRedirectDelegate: NSObject, URLSessionTaskDelegate {
    func urlSession(_ session: URLSession, task: URLSessionTask,
                    willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest,
                    completionHandler: @escaping (URLRequest?) -> Void) {
        completionHandler(nil)
    }
}
