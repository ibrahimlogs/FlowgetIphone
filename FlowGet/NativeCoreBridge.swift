import CryptoKit
import Foundation
import Security

enum NativeCoreBridgeError: LocalizedError {
    case incompatibleCore
    case sourceUnavailable
    case secureStorageUnavailable
    case receiverNotReady

    var errorDescription: String? {
        switch self {
        case .incompatibleCore: "The installed FlowShare core is not compatible with protocol v3."
        case .sourceUnavailable: "The selected file is no longer available."
        case .secureStorageUnavailable: "FlowShare secure storage is unavailable on this device."
        case .receiverNotReady: "The FlowShare receiver could not become ready for the sender."
        }
    }
}

/// Thin iOS adapter around the same authoritative Rust/UniFFI engine used by Android.
/// Signaling and UI stay in Swift; protocol framing, authorization, QUIC, hashing and resume stay in Rust.
actor NativeCoreBridge {
    static let protocolVersion: UInt16 = 3
    static let moduleName = "flowget_flowshare_coreFFI"
    static let isLinked = true

    private let engine: FlowShareEngine
    private let eventSink: NativeEventSink
    private let fileManager = FileManager.default
    private let outgoingDirectory: URL
    private let incomingDirectory: URL
    private var stagedSources: [String: URL] = [:]

    init(onEvent: @escaping @Sendable (FlowShareTransferStatus) -> Void) throws {
        let contract = flowshareCoreContract()
        guard contract.nativeQuicProtocolVersion == Self.protocolVersion,
              contract.coreApiVersion == 1 else {
            throw NativeCoreBridgeError.incompatibleCore
        }

        let support = try Self.applicationSupportDirectory()
        let stateRoot = support.appendingPathComponent("NativeState", isDirectory: true)
        outgoingDirectory = support.appendingPathComponent("Outgoing", isDirectory: true)
        incomingDirectory = Self.documentsDirectory().appendingPathComponent("FlowGet", isDirectory: true)
        try fileManager.createDirectory(at: stateRoot, withIntermediateDirectories: true)
        try fileManager.createDirectory(at: outgoingDirectory, withIntermediateDirectories: true)
        try fileManager.createDirectory(at: incomingDirectory, withIntermediateDirectories: true)

        eventSink = NativeEventSink(onEvent: onEvent)
        engine = FlowShareEngine(local: FlowShareCapabilities(
            schemaVersion: 1,
            protocolVersion: Self.protocolVersion,
            platform: .ios,
            nativeQuic: true,
            webrtcDirect: false,
            resume: true,
            completionAck: true,
            sha256: true,
            lanDiscovery: true,
            deviceMode: true,
            maxFileSize: 64 * 1024 * 1024 * 1024,
            appVersion: AppConfig.version
        ))
        _ = try engine.configureStateRoot(path: stateRoot.path)
        _ = try engine.setSecretProtector(protector: try AppleFlowShareSecretProtector())
        _ = try engine.initialize()
        engine.setEventListener(listener: eventSink)
    }

    func prepareReceiver() async throws -> PrepareReceiveResult {
        try await engine.prepareReceive(request: PrepareReceiveRequest(lifetimeMs: 15 * 60 * 1_000))
    }

    func prepareSender(sourceURL: URL, receiverBootstrapPackage: String) async throws -> PrepareSendResult {
        let staged = try stageSource(sourceURL)
        do {
            let result = try await engine.prepareSend(request: PrepareSendRequest(
                sourceHandle: staged.path,
                receiverBootstrapPackage: receiverBootstrapPackage,
                invitationLifetimeMs: 15 * 60 * 1_000
            ))
            stagedSources[result.transfer.transferId] = staged
            return result
        } catch {
            try? fileManager.removeItem(at: staged)
            throw error
        }
    }

    func importInvitation(_ request: FlowShareIncomingRequest) async throws -> FlowShareTransferStatus {
        try await engine.importInvitation(request: ImportInvitationRequest(
            receiverBootstrapId: request.receiverBootstrapID,
            invitationPackage: request.invitationPackage,
            destinationHandle: incomingDirectory.path,
            retentionExpiresUnixMs: UInt64(request.expiresAt.timeIntervalSince1970 * 1_000)
        ))
    }

    func accept(_ request: FlowShareIncomingRequest) async throws -> FlowShareTransferStatus {
        try await engine.acceptTransfer(request: AcceptTransferRequest(
            transferId: request.transferID,
            displayFilename: request.fileName,
            fileSize: UInt64(request.fileSize),
            expectedSha256: request.fileSHA256,
            overwrite: false
        ))
    }

    func reject(transferID: String) async throws -> FlowShareTransferStatus {
        try await engine.rejectTransfer(request: TransferLookupRequest(
            transferId: transferID,
            direction: .receive
        ))
    }

    func startSender(transferID: String, endpoint: String) async throws -> FlowShareTransferStatus {
        try await engine.startSender(request: startRequest(transferID: transferID, endpoint: endpoint))
    }

    func startReceiver(transferID: String, endpoint: String) async throws -> FlowShareTransferStatus {
        try await engine.startReceiver(request: startRequest(transferID: transferID, endpoint: endpoint))
    }

    func transferStatus(transferID: String, direction: FlowShareDirection) async throws -> FlowShareTransferStatus {
        try await engine.getTransferStatus(request: TransferLookupRequest(
            transferId: transferID,
            direction: direction
        ))
    }

    func awaitReceiverReady(transferID: String, timeoutSeconds: TimeInterval = 15) async throws -> FlowShareTransferStatus {
        let deadline = Date().addingTimeInterval(timeoutSeconds)
        while Date() < deadline {
            let status = try await engine.getTransferStatus(request: TransferLookupRequest(
                transferId: transferID,
                direction: .receive
            ))
            switch status.state {
            case .waitingForPeer, .connected, .transferring:
                return status
            case .failed, .cancelled, .rejected:
                throw NativeCoreBridgeError.receiverNotReady
            default:
                try await Task.sleep(nanoseconds: 50_000_000)
            }
        }
        throw NativeCoreBridgeError.receiverNotReady
    }

    func pause(transferID: String, direction: FlowShareDirection) async throws -> FlowShareTransferStatus {
        try await engine.pause(request: TransferControlRequest(
            transferId: transferID,
            direction: direction,
            retainPartial: true
        ))
    }

    func cancel(transferID: String, direction: FlowShareDirection) async throws -> FlowShareTransferStatus {
        let status = try await engine.cancel(request: TransferControlRequest(
            transferId: transferID,
            direction: direction,
            retainPartial: true
        ))
        releaseStagedSource(for: transferID)
        return status
    }

    func releaseStagedSource(for transferID: String) {
        guard let source = stagedSources.removeValue(forKey: transferID) else { return }
        try? fileManager.removeItem(at: source)
    }

    func shutdown() async {
        engine.clearEventListener()
        try? await engine.shutdown()
        for source in stagedSources.values { try? fileManager.removeItem(at: source) }
        stagedSources.removeAll()
    }

    private func startRequest(transferID: String, endpoint: String) -> StartTransferRequest {
        StartTransferRequest(
            transferId: transferID,
            signalingEndpoint: endpoint,
            allowLoopbackTest: false,
            signalingTimeoutMs: 10 * 60 * 1_000,
            connectivityTimeoutMs: 45_000
        )
    }

    private func stageSource(_ source: URL) throws -> URL {
        let hasScope = source.startAccessingSecurityScopedResource()
        defer { if hasScope { source.stopAccessingSecurityScopedResource() } }
        guard (try? source.resourceValues(forKeys: [.isRegularFileKey]).isRegularFile) == true else {
            throw NativeCoreBridgeError.sourceUnavailable
        }
        let name = Self.safeFileName(source.lastPathComponent)
        let destination = outgoingDirectory.appendingPathComponent("\(UUID().uuidString)-\(name)")
        try fileManager.copyItem(at: source, to: destination)
        try? fileManager.setAttributes([.protectionKey: FileProtectionType.completeUntilFirstUserAuthentication],
                                       ofItemAtPath: destination.path)
        return destination
    }

    private static func applicationSupportDirectory() throws -> URL {
        let root = try FileManager.default.url(for: .applicationSupportDirectory,
                                               in: .userDomainMask,
                                               appropriateFor: nil,
                                               create: true)
        return root.appendingPathComponent("FlowGet/FlowShare", isDirectory: true)
    }

    private static func documentsDirectory() -> URL {
        FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
    }

    private static func safeFileName(_ value: String) -> String {
        let invalid = CharacterSet.controlCharacters.union(CharacterSet(charactersIn: "/\\"))
        let cleaned = value.unicodeScalars.map { invalid.contains($0) ? "_" : String($0) }.joined()
        let name = cleaned.trimmingCharacters(in: .whitespacesAndNewlines)
        return String((name.isEmpty ? "FlowGet-file" : name).prefix(180))
    }
}

private final class NativeEventSink: FlowShareEventListener, @unchecked Sendable {
    private let onEvent: @Sendable (FlowShareTransferStatus) -> Void

    init(onEvent: @escaping @Sendable (FlowShareTransferStatus) -> Void) {
        self.onEvent = onEvent
    }

    func onEvent(event: FlowShareEvent) {
        onEvent(event.status)
    }
}

private final class AppleFlowShareSecretProtector: FlowShareSecretProtector, @unchecked Sendable {
    private static let service = "com.flowget.ios.flowshare"
    private static let account = "native-secret-protection-key.v1"
    private let key: SymmetricKey

    init() throws {
        key = SymmetricKey(data: try Self.loadOrCreateKey())
    }

    func protect(plaintext: Data) throws -> Data {
        guard let combined = try AES.GCM.seal(plaintext, using: key).combined else {
            throw FlowShareApiError.Internal
        }
        return combined
    }

    func unprotect(protected: Data) throws -> Data {
        do {
            return try AES.GCM.open(AES.GCM.SealedBox(combined: protected), using: key)
        } catch {
            throw FlowShareApiError.AuthorizationFailed
        }
    }

    private static func loadOrCreateKey() throws -> Data {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecSuccess, let data = result as? Data, data.count == 32 { return data }
        guard status == errSecItemNotFound else { throw NativeCoreBridgeError.secureStorageUnavailable }

        var bytes = [UInt8](repeating: 0, count: 32)
        guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else {
            throw NativeCoreBridgeError.secureStorageUnavailable
        }
        let data = Data(bytes)
        var item = query
        item.removeValue(forKey: kSecReturnData as String)
        item.removeValue(forKey: kSecMatchLimit as String)
        item[kSecValueData as String] = data
        item[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        guard SecItemAdd(item as CFDictionary, nil) == errSecSuccess else {
            throw NativeCoreBridgeError.secureStorageUnavailable
        }
        return data
    }
}
