import CryptoKit
import Foundation

enum LicenseKind: Equatable {
    case notSynced, syncing, free, paid, trial, denied, unavailable
}

struct LicenseSnapshot: Equatable {
    var kind: LicenseKind
    var title: String
    var badge: String
    var summary: String
    var plan: String
    var device: String
    var expiry: String

    static let notSynced = LicenseSnapshot(
        kind: .notSynced,
        title: "License not synced",
        badge: "Unknown",
        summary: "Refresh licensing to verify this iPhone with FlowGet.",
        plan: "Not verified",
        device: "This iPhone",
        expiry: "Not available"
    )

    static let syncing = LicenseSnapshot(
        kind: .syncing,
        title: "Verifying license",
        badge: "Checking",
        summary: "Securely checking your Mobile access and registered devices.",
        plan: "Checking…",
        device: "This iPhone",
        expiry: "Checking…"
    )

    static func free(device: String) -> LicenseSnapshot {
        LicenseSnapshot(
            kind: .free,
            title: "Free mode",
            badge: "Free",
            summary: "Your account is verified. Paid Mobile features are not currently active.",
            plan: "Free",
            device: device,
            expiry: "Refreshes daily"
        )
    }

    static func denied(_ message: String, device: String) -> LicenseSnapshot {
        LicenseSnapshot(
            kind: .denied,
            title: "Mobile access unavailable",
            badge: "Action needed",
            summary: message,
            plan: "Not available",
            device: device,
            expiry: "Not available"
        )
    }

    static func unavailable(_ message: String, device: String) -> LicenseSnapshot {
        LicenseSnapshot(
            kind: .unavailable,
            title: "License check unavailable",
            badge: "Offline",
            summary: message,
            plan: "Last check unavailable",
            device: device,
            expiry: "Try again"
        )
    }
}

struct FlowShareCredentialContext: Sendable {
    let entitlementJWT: String
    let accountID: String
    let globalDeviceID: String
}

actor LicensingService {
    private let auth: AuthService
    private let session: URLSession
    private var runtime: RuntimeSession?
    private var verificationKeys: [String: Data] = [:]

    init(auth: AuthService) {
        self.auth = auth
        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = 30
        configuration.httpCookieStorage = nil
        configuration.urlCredentialStorage = nil
        session = URLSession(
            configuration: configuration,
            delegate: LicensingNoRedirectDelegate(),
            delegateQueue: nil
        )
    }

    func synchronize(account: FlowGetAccount, accessToken: String, deviceLabel: String) async -> LicenseSnapshot {
        do {
            var identity = try InstallationIdentity.loadOrCreate()
            let assertion = try await auth.workerAssertion(token: accessToken)
            let evaluation: AccessEvaluationResponse = try await post(
                "v3/client/access/evaluate",
                assertion: assertion,
                body: AccessEvaluationRequest(platform: "ios", installationFingerprint: identity.fingerprint)
            )
            try validate(evaluation: evaluation, account: account, identity: identity)

            if evaluation.access == "free" {
                runtime = nil
                return .free(device: deviceLabel)
            }

            var globalDeviceID = identity.globalDeviceID
            if globalDeviceID == nil {
                globalDeviceID = try await register(
                    account: account,
                    identity: identity,
                    assertion: assertion,
                    deviceLabel: deviceLabel
                )
                identity.globalDeviceID = globalDeviceID
                identity.save()
            }

            var claim: DeviceClaimResponse
            do {
                claim = try await claimDevice(globalDeviceID: globalDeviceID!, assertion: assertion)
            } catch WorkerAPIError.policy(let code, _, _) where code == "DEVICE_NOT_REGISTERED" {
                globalDeviceID = try await register(
                    account: account,
                    identity: identity,
                    assertion: assertion,
                    deviceLabel: deviceLabel
                )
                identity.globalDeviceID = globalDeviceID
                identity.save()
                claim = try await claimDevice(globalDeviceID: globalDeviceID!, assertion: assertion)
            }
            try validate(claim: claim, account: account, globalDeviceID: globalDeviceID!)

            let opened: SessionLeaseResponse = try await post(
                "v3/client/sessions/open",
                assertion: assertion,
                body: SessionOpenRequest(
                    globalDeviceID: globalDeviceID!,
                    platform: "ios",
                    sessionType: "mobile_companion",
                    appVersion: AppConfig.version,
                    buildID: Self.buildID
                )
            )
            try validate(lease: opened)
            var active = RuntimeSession(
                accountID: account.id,
                globalDeviceID: globalDeviceID!,
                bindingID: claim.bindingID,
                slotIndex: claim.slotIndex,
                sessionID: opened.sessionID,
                leaseExpiresAt: opened.leaseExpiresAt,
                deviceLabel: deviceLabel,
                signedEntitlement: opened.signedAssertion,
                features: []
            )
            let openedClaims = try await verify(opened.signedAssertion, expected: active)
            active.features = Set(openedClaims.features)

            let synced: EntitlementSyncResponse = try await post(
                "v3/client/entitlement/sync",
                assertion: assertion,
                body: EntitlementSyncRequest(
                    globalDeviceID: globalDeviceID!,
                    platform: "ios",
                    appVersion: AppConfig.version,
                    buildID: Self.buildID
                )
            )
            let claims = try await verify(synced.signedAssertion, expected: active)
            try validate(sync: synced, claims: claims)
            active.leaseExpiresAt = claims.sessionLeaseExpiresAt
            active.signedEntitlement = synced.signedAssertion
            active.features = Set(claims.features)
            runtime = active
            return Self.snapshot(from: claims, deviceLabel: deviceLabel)
        } catch WorkerAPIError.policy(let code, let message, _) {
            if code == "ENTITLEMENT_INACTIVE" { return .free(device: deviceLabel) }
            return .denied(Self.policyMessage(code: code, fallback: message), device: deviceLabel)
        } catch {
            return .unavailable(
                (error as? LocalizedError)?.errorDescription ?? "Connect to the internet and try again.",
                device: deviceLabel
            )
        }
    }

    func heartbeat(accessToken: String) async -> LicenseSnapshot? {
        guard let active = runtime else { return nil }
        do {
            let assertion = try await auth.workerAssertion(token: accessToken)
            let lease: SessionLeaseResponse = try await post(
                "v3/client/sessions/heartbeat",
                assertion: assertion,
                body: SessionHeartbeatRequest(
                    sessionID: active.sessionID,
                    globalDeviceID: active.globalDeviceID,
                    platform: "ios",
                    appVersion: AppConfig.version,
                    buildID: Self.buildID
                )
            )
            try validate(lease: lease)
            let updated = RuntimeSession(
                accountID: active.accountID,
                globalDeviceID: active.globalDeviceID,
                bindingID: active.bindingID,
                slotIndex: active.slotIndex,
                sessionID: active.sessionID,
                leaseExpiresAt: lease.leaseExpiresAt,
                deviceLabel: active.deviceLabel,
                signedEntitlement: lease.signedAssertion,
                features: active.features
            )
            let claims = try await verify(lease.signedAssertion, expected: updated)
            var verified = updated
            verified.features = Set(claims.features)
            runtime = verified
            return Self.snapshot(from: claims, deviceLabel: active.deviceLabel)
        } catch {
            return nil
        }
    }

    func close(accessToken: String) async {
        guard let active = runtime else { return }
        runtime = nil
        guard let assertion = try? await auth.workerAssertion(token: accessToken) else { return }
        let _: SessionCloseResponse? = try? await post(
            "v3/client/sessions/close",
            assertion: assertion,
            body: SessionCloseRequest(sessionID: active.sessionID, reason: "USER_LOGOUT")
        )
    }

    func reset() { runtime = nil }

    func flowShareContext() -> FlowShareCredentialContext? {
        guard let active = runtime,
              let leaseExpiry = Self.parseDate(active.leaseExpiresAt),
              leaseExpiry > Date(),
              active.features.contains("flowshare") || active.features.contains("p2p.global") else {
            return nil
        }
        return FlowShareCredentialContext(
            entitlementJWT: active.signedEntitlement,
            accountID: active.accountID,
            globalDeviceID: active.globalDeviceID
        )
    }

    private func register(
        account: FlowGetAccount,
        identity: InstallationIdentity,
        assertion: String,
        deviceLabel: String
    ) async throws -> String {
        let challenge: DeviceChallengeResponse = try await post(
            "v3/client/devices/challenge",
            assertion: assertion,
            body: DeviceChallengeRequest(platform: "ios", publicKeyFingerprint: identity.fingerprint)
        )
        guard challenge.ok,
              !challenge.challenge.isEmpty,
              let expiry = Self.parseDate(challenge.expiresAt), expiry > Date() else {
            throw WorkerAPIError.invalidResponse
        }
        let message = "flowget-device-register:\(challenge.challenge):\(account.id):ios"
        let signature = try identity.privateKey.signature(for: Data(message.utf8)).hexString
        let response: DeviceRegisterResponse = try await post(
            "v3/client/devices/register",
            assertion: assertion,
            body: DeviceRegisterRequest(
                platform: "ios",
                publicKey: identity.publicKeyHex,
                publicKeyFingerprint: identity.fingerprint,
                deviceLabel: deviceLabel,
                challenge: challenge.challenge,
                proof: signature,
                appVersion: AppConfig.version,
                buildID: Self.buildID
            )
        )
        guard response.ok,
              response.platform == "ios",
              response.publicKeyFingerprint == identity.fingerprint,
              !response.globalDeviceID.isEmpty else {
            throw WorkerAPIError.invalidResponse
        }
        return response.globalDeviceID
    }

    private func claimDevice(globalDeviceID: String, assertion: String) async throws -> DeviceClaimResponse {
        try await post(
            "v3/client/device-bindings/claim",
            assertion: assertion,
            body: DeviceClaimRequest(globalDeviceID: globalDeviceID, platform: "ios")
        )
    }

    private func validate(evaluation: AccessEvaluationResponse, account: FlowGetAccount, identity: InstallationIdentity) throws {
        let accessValid: Bool
        switch evaluation.access {
        case "paid": accessValid = evaluation.paidAccess && !evaluation.trialAccess && evaluation.platformCapacity > 0
        case "trial": accessValid = !evaluation.paidAccess && evaluation.trialAccess && evaluation.platformCapacity > 0
        case "free": accessValid = !evaluation.paidAccess && !evaluation.trialAccess && evaluation.platformCapacity == 0
        default: accessValid = false
        }
        guard evaluation.ok,
              evaluation.accountID == account.id,
              evaluation.platform == "ios",
              evaluation.slotFamily == "mobile",
              evaluation.installationFingerprint == identity.fingerprint,
              evaluation.freeRefreshAfterSeconds == 86_400,
              accessValid,
              let checked = Self.parseDate(evaluation.checkedAt),
              abs(checked.timeIntervalSinceNow) <= 300 else {
            throw WorkerAPIError.invalidResponse
        }
    }

    private func validate(claim: DeviceClaimResponse, account: FlowGetAccount, globalDeviceID: String) throws {
        guard claim.ok,
              claim.accountID == account.id,
              claim.globalDeviceID == globalDeviceID,
              claim.platform == "ios",
              claim.slotFamily == "mobile",
              claim.slotIndex >= 1,
              claim.status == "active" else {
            throw WorkerAPIError.invalidResponse
        }
    }

    private func validate(lease: SessionLeaseResponse) throws {
        guard lease.ok,
              !lease.sessionID.isEmpty,
              !lease.signedAssertion.isEmpty,
              let expiry = Self.parseDate(lease.leaseExpiresAt), expiry > Date() else {
            throw WorkerAPIError.invalidResponse
        }
    }

    private func validate(sync: EntitlementSyncResponse, claims: EntitlementClaims) throws {
        guard sync.ok,
              sync.paidAccess == claims.paidAccess,
              sync.trialAccess == claims.trialAccess,
              sync.activeProducts == claims.activeProducts,
              sync.planByProduct == claims.planByProduct,
              sync.capacities == claims.capacities else {
            throw WorkerAPIError.invalidResponse
        }
    }

    private func verify(_ token: String, expected: RuntimeSession) async throws -> EntitlementClaims {
        let pieces = token.split(separator: ".", omittingEmptySubsequences: false)
        guard pieces.count == 3,
              token.count <= 32 * 1024,
              let headerData = Data(base64URL: String(pieces[0])),
              let payloadData = Data(base64URL: String(pieces[1])),
              let signature = Data(base64URL: String(pieces[2])), signature.count == 64,
              let header = try? JSONDecoder().decode(JWTHeader.self, from: headerData),
              header.algorithm == "EdDSA", header.type == "JWT",
              !header.keyID.isEmpty else {
            throw WorkerAPIError.invalidEntitlement
        }
        let keyData = try await verificationKey(for: header.keyID)
        let key = try Curve25519.Signing.PublicKey(rawRepresentation: keyData)
        let signingInput = Data("\(pieces[0]).\(pieces[1])".utf8)
        guard key.isValidSignature(signature, for: signingInput),
              let claims = try? JSONDecoder().decode(EntitlementClaims.self, from: payloadData) else {
            throw WorkerAPIError.invalidEntitlement
        }
        let now = Int64(Date().timeIntervalSince1970)
        guard claims.issuer == "flowget-worker-v3",
              claims.audience == "flowget-ios",
              claims.schemaVersion == 3,
              claims.protocolVersion == 3,
              claims.platform == "ios",
              claims.slotFamily == "mobile",
              claims.accountID == expected.accountID,
              claims.globalDeviceID == expected.globalDeviceID,
              claims.bindingID == expected.bindingID,
              claims.slotIndex == expected.slotIndex,
              claims.sessionID == expected.sessionID,
              claims.sessionLeaseExpiresAt == expected.leaseExpiresAt,
              claims.signingKeyVersion == header.keyID,
              !claims.tokenID.isEmpty,
              claims.issuedAt <= now + 60,
              claims.expiresAt > now,
              claims.offlineGraceUntil >= claims.expiresAt,
              claims.capacities.windows >= 0,
              claims.capacities.macos >= 0,
              claims.capacities.mobile >= 0,
              !(claims.paidAccess && claims.trialAccess) else {
            throw WorkerAPIError.invalidEntitlement
        }
        return claims
    }

    private func verificationKey(for keyID: String) async throws -> Data {
        if let existing = verificationKeys[keyID] { return existing }
        let response: PublicKeysResponse = try await get("v3/public/entitlement-keys")
        guard response.ok,
              response.algorithm == "Ed25519",
              response.encoding == "base64-raw-public-key" else {
            throw WorkerAPIError.invalidResponse
        }
        let decoded = response.keys.compactMapValues { Data(base64Encoded: $0) }
        verificationKeys = decoded
        guard let key = decoded[keyID], key.count == 32 else { throw WorkerAPIError.invalidEntitlement }
        return key
    }

    private func get<Response: Decodable>(_ path: String) async throws -> Response {
        var request = URLRequest(url: AppConfig.workerBaseURL.appendingPathComponent(path))
        request.httpMethod = "GET"
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        return try await execute(request)
    }

    private func post<Body: Encodable, Response: Decodable>(
        _ path: String,
        assertion: String,
        body: Body
    ) async throws -> Response {
        var request = URLRequest(url: AppConfig.workerBaseURL.appendingPathComponent(path))
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("Bearer \(assertion)", forHTTPHeaderField: "Authorization")
        request.httpBody = try JSONEncoder().encode(body)
        return try await execute(request)
    }

    private func execute<Response: Decodable>(_ request: URLRequest) async throws -> Response {
        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse,
              http.url?.scheme == AppConfig.workerBaseURL.scheme,
              http.url?.host == AppConfig.workerBaseURL.host else {
            throw WorkerAPIError.invalidResponse
        }
        guard (200..<300).contains(http.statusCode) else {
            let envelope = try? JSONDecoder().decode(WorkerErrorEnvelope.self, from: data)
            throw WorkerAPIError.policy(
                code: envelope?.error.code ?? "HTTP_\(http.statusCode)",
                message: envelope?.error.message ?? "The licensing service rejected the request.",
                status: http.statusCode
            )
        }
        guard let result = try? JSONDecoder().decode(Response.self, from: data) else {
            throw WorkerAPIError.invalidResponse
        }
        return result
    }

    private static func snapshot(from claims: EntitlementClaims, deviceLabel: String) -> LicenseSnapshot {
        let kind: LicenseKind = claims.paidAccess ? .paid : (claims.trialAccess ? .trial : .free)
        let badge = claims.paidAccess ? "Premium" : (claims.trialAccess ? "Trial" : "Free")
        let plan: String
        if claims.trialAccess {
            plan = "Trial"
        } else if claims.planByProduct.values.contains("lifetime") {
            plan = "Lifetime"
        } else if claims.planByProduct.values.contains("pro_yearly") {
            plan = "Pro yearly"
        } else if claims.planByProduct.values.contains("pro_monthly") {
            plan = "Pro monthly"
        } else {
            plan = claims.paidAccess ? "Premium" : "Free"
        }
        let expiry: String
        if let trial = claims.trialEndsAt.flatMap(parseDate) {
            expiry = trial.formatted(date: .abbreviated, time: .omitted)
        } else {
            let paidDates = claims.commercialExpiresAtByProduct.values.compactMap { $0 }.compactMap { parseDate($0) }
            expiry = paidDates.max()?.formatted(date: .abbreviated, time: .omitted) ?? (claims.paidAccess ? "Lifetime" : "Not applicable")
        }
        return LicenseSnapshot(
            kind: kind,
            title: claims.paidAccess ? "Premium active" : (claims.trialAccess ? "Trial active" : "Free mode"),
            badge: badge,
            summary: claims.paidAccess || claims.trialAccess
                ? "This iPhone is verified for FlowGet Mobile access."
                : "Your FlowGet account is verified.",
            plan: plan,
            device: deviceLabel,
            expiry: expiry
        )
    }

    private static func policyMessage(code: String, fallback: String) -> String {
        switch code {
        case "ACCOUNT_SLOT_OCCUPIED": return "All Mobile device slots are currently in use. Release a device from your FlowGet dashboard and try again."
        case "DEVICE_REPLACEMENT_LIMIT": return "The self-service device replacement limit has been reached."
        case "DEVICE_BLOCKED", "DEVICE_COMPROMISED", "DEVICE_RETIRED": return "This device cannot be authorized. Contact FlowGet support."
        case "ACCOUNT_SUSPENDED", "ACCOUNT_DELETED": return "This FlowGet account is not currently active."
        case "PLAN_PLATFORM_NOT_INCLUDED": return "Your current plan does not include another Mobile device slot."
        default: return fallback.isEmpty ? "Mobile access could not be verified." : fallback
        }
    }

    private static func parseDate(_ value: String) -> Date? {
        let precise = ISO8601DateFormatter()
        precise.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return precise.date(from: value) ?? ISO8601DateFormatter().date(from: value)
    }

    private static var buildID: String {
        Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? "1"
    }
}

private struct InstallationIdentity: Codable {
    var privateKeyData: Data
    var globalDeviceID: String?

    var privateKey: Curve25519.Signing.PrivateKey {
        get throws { try Curve25519.Signing.PrivateKey(rawRepresentation: privateKeyData) }
    }
    var publicKeyHex: String { (try? privateKey.publicKey.rawRepresentation.hexString) ?? "" }
    var fingerprint: String { Data(SHA256.hash(data: Data(publicKeyHex.utf8))).hexString }

    static func loadOrCreate() throws -> InstallationIdentity {
        if let stored = KeychainStore.load(InstallationIdentity.self, account: "licensing.identity.v1"),
           (try? Curve25519.Signing.PrivateKey(rawRepresentation: stored.privateKeyData)) != nil {
            return stored
        }
        let key = Curve25519.Signing.PrivateKey()
        let identity = InstallationIdentity(privateKeyData: key.rawRepresentation, globalDeviceID: nil)
        identity.save()
        return identity
    }

    func save() { KeychainStore.save(self, account: "licensing.identity.v1") }
}

private struct RuntimeSession {
    let accountID: String
    let globalDeviceID: String
    let bindingID: String
    let slotIndex: Int
    let sessionID: String
    var leaseExpiresAt: String
    let deviceLabel: String
    var signedEntitlement: String
    var features: Set<String>
}

private enum WorkerAPIError: LocalizedError {
    case policy(code: String, message: String, status: Int)
    case invalidResponse
    case invalidEntitlement

    var errorDescription: String? {
        switch self {
        case .policy(_, let message, _): message
        case .invalidResponse: "The licensing service returned an unexpected response."
        case .invalidEntitlement: "FlowGet could not verify the signed licensing response."
        }
    }
}

private struct AccessEvaluationRequest: Encodable {
    let platform: String
    let installationFingerprint: String
    enum CodingKeys: String, CodingKey { case platform, installationFingerprint = "installation_fingerprint" }
}
private struct AccessEvaluationResponse: Decodable {
    let ok: Bool, accountID: String, platform: String, slotFamily: String, installationFingerprint: String
    let access: String, paidAccess: Bool, trialAccess: Bool, platformCapacity: Int, checkedAt: String
    let freeRefreshAfterSeconds: Int
    enum CodingKeys: String, CodingKey {
        case ok, platform, access
        case accountID = "account_id", slotFamily = "slot_family", installationFingerprint = "installation_fingerprint"
        case paidAccess = "paid_access", trialAccess = "trial_access", platformCapacity = "platform_capacity"
        case checkedAt = "checked_at", freeRefreshAfterSeconds = "free_refresh_after_seconds"
    }
}
private struct DeviceChallengeRequest: Encodable {
    let platform: String, publicKeyFingerprint: String
    enum CodingKeys: String, CodingKey { case platform, publicKeyFingerprint = "public_key_fingerprint" }
}
private struct DeviceChallengeResponse: Decodable {
    let ok: Bool, challenge: String, expiresAt: String
    enum CodingKeys: String, CodingKey { case ok, challenge, expiresAt = "expires_at" }
}
private struct DeviceRegisterRequest: Encodable {
    let platform: String, publicKey: String, publicKeyFingerprint: String, deviceLabel: String
    let challenge: String, proof: String, appVersion: String, buildID: String
    enum CodingKeys: String, CodingKey {
        case platform, challenge, proof
        case publicKey = "public_key", publicKeyFingerprint = "public_key_fingerprint", deviceLabel = "device_label"
        case appVersion = "app_version", buildID = "build_id"
    }
}
private struct DeviceRegisterResponse: Decodable {
    let ok: Bool, globalDeviceID: String, publicKeyFingerprint: String, platform: String
    enum CodingKeys: String, CodingKey {
        case ok, platform
        case globalDeviceID = "global_device_id", publicKeyFingerprint = "public_key_fingerprint"
    }
}
private struct DeviceClaimRequest: Encodable {
    let globalDeviceID: String, platform: String
    enum CodingKeys: String, CodingKey { case globalDeviceID = "global_device_id", platform }
}
private struct DeviceClaimResponse: Decodable {
    let ok: Bool, bindingID: String, accountID: String, globalDeviceID: String
    let platform: String, slotFamily: String, slotIndex: Int, status: String
    enum CodingKeys: String, CodingKey {
        case ok, platform, status
        case bindingID = "binding_id", accountID = "account_id", globalDeviceID = "global_device_id"
        case slotFamily = "slot_family", slotIndex = "slot_index"
    }
}
private struct SessionOpenRequest: Encodable {
    let globalDeviceID: String, platform: String, sessionType: String, appVersion: String, buildID: String
    enum CodingKeys: String, CodingKey {
        case globalDeviceID = "global_device_id", platform, sessionType = "session_type"
        case appVersion = "app_version", buildID = "build_id"
    }
}
private struct SessionHeartbeatRequest: Encodable {
    let sessionID: String, globalDeviceID: String, platform: String, appVersion: String, buildID: String
    enum CodingKeys: String, CodingKey {
        case sessionID = "session_id", globalDeviceID = "global_device_id", platform
        case appVersion = "app_version", buildID = "build_id"
    }
}
private struct SessionLeaseResponse: Decodable {
    let ok: Bool, sessionID: String, leaseExpiresAt: String, signedAssertion: String
    enum CodingKeys: String, CodingKey {
        case ok, sessionID = "session_id", leaseExpiresAt = "lease_expires_at", signedAssertion = "signed_assertion"
    }
}
private struct SessionCloseRequest: Encodable { let sessionID: String, reason: String; enum CodingKeys: String, CodingKey { case sessionID = "session_id", reason } }
private struct SessionCloseResponse: Decodable { let ok: Bool }
private struct EntitlementSyncRequest: Encodable {
    let globalDeviceID: String, platform: String, appVersion: String, buildID: String
    enum CodingKeys: String, CodingKey {
        case globalDeviceID = "global_device_id", platform, appVersion = "app_version", buildID = "build_id"
    }
}
private struct EntitlementSyncResponse: Decodable {
    let ok: Bool, signedAssertion: String, activeProducts: [String], planByProduct: [String: String]
    let paidAccess: Bool, trialAccess: Bool, capacities: EntitlementCapacities
    enum CodingKeys: String, CodingKey {
        case ok, capacities
        case signedAssertion = "signed_assertion", activeProducts = "active_products", planByProduct = "plan_by_product"
        case paidAccess = "paid_access", trialAccess = "trial_access"
    }
}
private struct EntitlementCapacities: Codable, Equatable { let windows: Int, macos: Int, mobile: Int }
private struct PublicKeysResponse: Decodable {
    let ok: Bool, algorithm: String, encoding: String, keys: [String: String]
}
private struct WorkerErrorEnvelope: Decodable { struct Detail: Decodable { let code: String, message: String }; let error: Detail }
private struct JWTHeader: Decodable {
    let algorithm: String, type: String, keyID: String
    enum CodingKeys: String, CodingKey { case algorithm = "alg", type = "typ", keyID = "kid" }
}
private struct EntitlementClaims: Decodable {
    let issuer: String, audience: String, schemaVersion: Int, tokenID: String, accountID: String, globalDeviceID: String
    let bindingID: String, platform: String, slotFamily: String, slotIndex: Int
    let activeProducts: [String], planByProduct: [String: String], commercialExpiresAtByProduct: [String: String?]
    let trialEndsAt: String?, paidAccess: Bool, trialAccess: Bool, capacities: EntitlementCapacities
    let features: [String]
    let issuedAt: Int64, expiresAt: Int64, offlineGraceUntil: Int64, sessionID: String
    let sessionLeaseExpiresAt: String, protocolVersion: Int, signingKeyVersion: String
    enum CodingKeys: String, CodingKey {
        case issuer, audience, platform, capacities, features
        case schemaVersion = "schema_version", tokenID = "token_id", accountID = "account_id", globalDeviceID = "global_device_id"
        case bindingID = "binding_id", slotFamily = "slot_family", slotIndex = "slot_index"
        case activeProducts = "active_products", planByProduct = "plan_by_product"
        case commercialExpiresAtByProduct = "commercial_expires_at_by_product", trialEndsAt = "trial_ends_at"
        case paidAccess = "paid_access", trialAccess = "trial_access", issuedAt = "issued_at", expiresAt = "expires_at"
        case offlineGraceUntil = "offline_grace_until", sessionID = "session_id"
        case sessionLeaseExpiresAt = "session_lease_expires_at", protocolVersion = "protocol_version"
        case signingKeyVersion = "signing_key_version"
    }
}

private final class LicensingNoRedirectDelegate: NSObject, URLSessionTaskDelegate {
    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest,
        completionHandler: @escaping (URLRequest?) -> Void
    ) { completionHandler(nil) }
}

private extension Data {
    init?(base64URL value: String) {
        var normalized = value.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        normalized += String(repeating: "=", count: (4 - normalized.count % 4) % 4)
        self.init(base64Encoded: normalized)
    }

    var hexString: String { map { String(format: "%02x", $0) }.joined() }
}
