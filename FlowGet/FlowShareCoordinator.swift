import Combine
import Foundation
import UIKit

enum FlowShareClientError: LocalizedError {
    case licenseRequired
    case notConnected
    case targetUnavailable
    case invalidCode
    case invalidResponse
    case rejected(String)
    case timedOut

    var errorDescription: String? {
        switch self {
        case .licenseRequired: "A verified FlowShare license is required. Refresh licensing and try again."
        case .notConnected: "FlowShare is not connected yet."
        case .targetUnavailable: "The selected device is no longer ready to receive."
        case .invalidCode: "Enter a valid 12-character FlowGet friend code."
        case .invalidResponse: "The FlowShare service returned an unexpected response."
        case .rejected(let message): message
        case .timedOut: "The FlowShare operation timed out."
        }
    }
}

enum FlowShareWirePolicy {
    static func normalizeFriendCode(_ value: String) -> String {
        value.uppercased().filter { $0.isLetter || $0.isNumber }
    }

    static func validFileName(_ value: String) -> Bool {
        !value.isEmpty && value.count <= 255 && !value.contains("/") && !value.contains("\\") &&
        !value.unicodeScalars.contains { CharacterSet.controlCharacters.contains($0) }
    }

    static func validSHA256(_ value: String) -> Bool {
        value.count == 64 && value.allSatisfy { $0.isHexDigit }
    }

    static func validSignalingEndpoint(_ value: String) -> Bool {
        guard let url = URL(string: value),
              url.scheme?.lowercased() == "wss",
              url.host?.lowercased() == AppConfig.flowShareBaseURL.host?.lowercased() else { return false }
        return url.path == "/ws"
    }

    static func acknowledgementForExistingTransfer(state: String, isPending: Bool) -> String? {
        guard !isPending else { return nil }
        switch state {
        case "Completed": return "completed"
        case "Rejected": return "rejected"
        case "Failed", "Cancelled": return "failed"
        case "Waiting for peer", "Connecting", "Connected", "Transferring", "Resuming", "Verifying":
            return "accepted"
        default: return nil
        }
    }
}

@MainActor
final class FlowShareCoordinator: ObservableObject {
    @Published private(set) var connection: FlowShareConnectionState = .stopped
    @Published private(set) var devices: [FlowShareDevice] = []
    @Published private(set) var transfers: [FlowShareTransfer]
    @Published private(set) var incoming: [FlowShareIncomingRequest] = []
    @Published private(set) var invite: FlowShareInvite?
    @Published private(set) var isBusy = false
    @Published private(set) var focusedTransferID: String?
    @Published private(set) var sessionTitle: String?
    @Published var errorMessage: String?

    private struct Registration {
        let context: FlowShareCredentialContext
        let bootstrap: PrepareReceiveResult
    }

    private struct PendingOutgoing {
        let transferID: String
        let endpoint: String
    }

    private struct FriendSession {
        let id: String
        let credential: String
        let expiresAt: Date
        let target: FlowShareDevice
    }

    private let session: URLSession
    private var native: NativeCoreBridge?
    private var context: FlowShareCredentialContext?
    private var registration: Registration?
    private var socket: URLSessionWebSocketTask?
    private var presenceTask: Task<Void, Never>?
    private var heartbeatTask: Task<Void, Never>?
    private var transferMonitorTasks: [String: Task<Void, Never>] = [:]
    private var active = false
    private var pendingOutgoing: [String: PendingOutgoing] = [:]
    private var earlyAcceptedCommands: Set<String> = []
    private var startedCommands: Set<String> = []
    private var ackReceipts: Set<String> = []
    private var incomingCommandByTransfer: [String: String] = [:]
    private var peerByTransfer: [String: String] = [:]
    private var completedAcknowledged: Set<String> = []
    private var acceptedFriendSessions: Set<String> = []
    private var backgroundTask: UIBackgroundTaskIdentifier = .invalid

    init() {
        transfers = Persistence.load([FlowShareTransfer].self, name: "flowshare-transfers.json", fallback: [])
        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = 30
        configuration.waitsForConnectivity = true
        configuration.httpCookieStorage = nil
        configuration.urlCredentialStorage = nil
        session = URLSession(configuration: configuration,
                             delegate: FlowShareNoRedirectDelegate(),
                             delegateQueue: nil)
    }

    func activate(context: FlowShareCredentialContext) async {
        if active, self.context?.accountID == context.accountID {
            self.context = context
            if presenceTask == nil { startPresenceLoop() }
            return
        }
        await stop()
        do {
            native = try NativeCoreBridge { [weak self] status in
                Task { @MainActor [weak self] in self?.handleNative(status) }
            }
            self.context = context
            active = true
            errorMessage = nil
            startPresenceLoop()
        } catch {
            connection = .stopped
            errorMessage = Self.message(for: error)
        }
    }

    func stop() async {
        active = false
        presenceTask?.cancel()
        heartbeatTask?.cancel()
        transferMonitorTasks.values.forEach { $0.cancel() }
        presenceTask = nil
        heartbeatTask = nil
        transferMonitorTasks.removeAll()
        socket?.cancel(with: .goingAway, reason: nil)
        socket = nil
        registration = nil
        devices = []
        invite = nil
        incoming = []
        pendingOutgoing.removeAll()
        earlyAcceptedCommands.removeAll()
        startedCommands.removeAll()
        ackReceipts.removeAll()
        incomingCommandByTransfer.removeAll()
        peerByTransfer.removeAll()
        completedAcknowledged.removeAll()
        acceptedFriendSessions.removeAll()
        focusedTransferID = nil
        sessionTitle = nil
        context = nil
        connection = .stopped
        endBackgroundTask()
        let bridge = native
        native = nil
        await bridge?.shutdown()
    }

    func reconnectIfNeeded() {
        guard active, presenceTask == nil else { return }
        startPresenceLoop()
    }

    func send(files: [URL], toDeviceID deviceID: String) async {
        guard !files.isEmpty, !isBusy else { return }
        isBusy = true
        focusedTransferID = nil
        sessionTitle = "Connecting to your device"
        errorMessage = nil
        defer { isBusy = false }
        do {
            var previousBootstrapID: String?
            for (index, file) in files.enumerated() {
                let target = try await readyDevice(id: deviceID,
                                                   differentFrom: index == 0 ? nil : previousBootstrapID)
                previousBootstrapID = target.receiverBootstrapID
                let transferID = try await send(file: file, target: target, friend: nil)
                if index < files.count - 1 { try await waitForTerminal(transferID: transferID) }
            }
        } catch {
            errorMessage = Self.message(for: error)
            if focusedTransferID == nil { sessionTitle = nil }
        }
    }

    func send(files: [URL], friendCode: String) async {
        guard !files.isEmpty, !isBusy else { return }
        let normalized = FlowShareWirePolicy.normalizeFriendCode(friendCode)
        guard normalized.count == 12 else { errorMessage = FlowShareClientError.invalidCode.localizedDescription; return }
        isBusy = true
        focusedTransferID = nil
        sessionTitle = "Connecting via Friend Code"
        errorMessage = nil
        defer { isBusy = false }
        do {
            var previousBootstrapID: String?
            for (index, file) in files.enumerated() {
                let friend: FriendSession
                if index == 0 {
                    friend = try await resolveFriend(code: normalized)
                } else {
                    friend = try await resolveFriendWithFreshBootstrap(
                        code: normalized,
                        differentFrom: previousBootstrapID
                    )
                }
                previousBootstrapID = friend.target.receiverBootstrapID
                let transferID = try await send(file: file, target: friend.target, friend: friend)
                if index < files.count - 1 { try await waitForTerminal(transferID: transferID) }
            }
        } catch {
            errorMessage = Self.message(for: error)
            if focusedTransferID == nil { sessionTitle = nil }
        }
    }

    func createReceiveCode() async {
        guard let registration else { errorMessage = FlowShareClientError.notConnected.localizedDescription; return }
        do {
            let response = try await post(path: "friend/invite",
                                          authorization: "Bearer \(registration.context.entitlementJWT)",
                                          body: ["deviceId": registration.context.globalDeviceID, "platform": "ios"])
            guard let sessionID = response["sessionId"] as? String,
                  let code = response["code"] as? String,
                  let expiry = response.int64("expiresUnixMs") else { throw FlowShareClientError.invalidResponse }
            invite = FlowShareInvite(sessionID: sessionID,
                                     code: code,
                                     expiresAt: Date(timeIntervalSince1970: TimeInterval(expiry) / 1_000))
        } catch {
            errorMessage = Self.message(for: error)
        }
    }

    func accept(_ request: FlowShareIncomingRequest) async {
        guard let native else { return }
        do {
            focusedTransferID = request.transferID
            sessionTitle = "Receiving from \(request.sourceDisplayName)"
            handleNative(try await native.accept(request))
            // The receiver listens before acceptance is acknowledged, preventing a fast-sender race.
            monitorTransfer(id: request.transferID, direction: .receive)
            handleNative(try await native.startReceiver(transferID: request.transferID,
                                                        endpoint: request.signalingEndpoint))
            handleNative(try await native.awaitReceiverReady(transferID: request.transferID))
            guard try await sendAckConfirmed(commandID: request.commandID, status: "accepted") else {
                _ = try? await native.cancel(transferID: request.transferID, direction: .receive)
                throw FlowShareClientError.timedOut
            }
            if let friendSessionID = request.friendSessionID { acceptedFriendSessions.insert(friendSessionID) }
            incoming.removeAll { $0.id == request.id }
        } catch {
            markFailed(transferID: request.transferID, message: Self.message(for: error))
            incoming.removeAll { $0.id == request.id }
            errorMessage = Self.message(for: error)
        }
    }

    func reject(_ request: FlowShareIncomingRequest) async {
        if let native { _ = try? await native.reject(transferID: request.transferID) }
        try? await sendAck(commandID: request.commandID, status: "rejected", detail: "user-declined")
        incoming.removeAll { $0.id == request.id }
        updateTransfer(id: request.transferID) { $0.state = "Rejected" }
    }

    func clearHistory() {
        transfers.removeAll { ["Completed", "Cancelled", "Rejected", "Failed"].contains($0.state) }
        persistTransfers()
    }

    var focusedTransfer: FlowShareTransfer? {
        guard let focusedTransferID else { return nil }
        return transfers.first { $0.id == focusedTransferID }
    }

    func dismissSession() {
        focusedTransferID = nil
        sessionTitle = nil
    }

    func cancelFocusedTransfer() async {
        guard let transfer = focusedTransfer, let native else { dismissSession(); return }
        let direction: FlowShareDirection = transfer.direction == .send ? .send : .receive
        _ = try? await native.cancel(transferID: transfer.id, direction: direction)
        updateTransfer(id: transfer.id) { $0.state = "Cancelled" }
        dismissSession()
    }

    private func startPresenceLoop() {
        presenceTask?.cancel()
        presenceTask = Task { [weak self] in
            guard let self else { return }
            defer { self.presenceTask = nil }
            var firstAttempt = true
            while !Task.isCancelled, self.active {
                self.connection = firstAttempt ? .connecting : .reconnecting
                do {
                    try await self.connectOnce()
                    firstAttempt = false
                } catch is CancellationError {
                    return
                } catch FlowShareClientError.licenseRequired {
                    self.connection = .unauthorized
                    self.errorMessage = FlowShareClientError.licenseRequired.localizedDescription
                    return
                } catch {
                    firstAttempt = false
                    self.connection = .reconnecting
                }
                guard !Task.isCancelled, self.active else { return }
                try? await Task.sleep(nanoseconds: 2_000_000_000)
            }
        }
    }

    private func connectOnce() async throws {
        guard let context, let native else { throw FlowShareClientError.licenseRequired }
        let bootstrap = try await native.prepareReceiver()
        let current = Registration(context: context, bootstrap: bootstrap)
        registration = current
        let body: [String: Any] = [
            "deviceId": context.globalDeviceID,
            "platform": "ios",
            "displayName": String(UIDevice.current.name.prefix(120)),
            "capabilities": [
                "sendFile": true, "receiveFile": true, "receiveUrl": false,
                "lanDirect": true, "globalDirect": true
            ],
            "receiverBootstrap": [
                "receiverBootstrapId": bootstrap.receiverBootstrapId,
                "receiverBootstrapPackage": bootstrap.receiverBootstrapPackage,
                "expiresUnixMs": bootstrap.expiresUnixMs
            ]
        ]
        let response = try await post(path: "device/session",
                                      authorization: "Bearer \(context.entitlementJWT)",
                                      body: body)
        guard let credential = response["credential"] as? String,
              let websocketPath = response["websocketPath"] as? String,
              websocketPath.hasPrefix("/") else { throw FlowShareClientError.invalidResponse }
        var request = URLRequest(url: URL(string: "wss://share.flowget.xyz\(websocketPath)")!)
        request.setValue("Device \(credential)", forHTTPHeaderField: "Authorization")
        let task = session.webSocketTask(with: request)
        socket = task
        task.resume()
        connection = .online
        startHeartbeat(expiresUnixMS: bootstrap.expiresUnixMs, socket: task)
        do {
            while active, !Task.isCancelled, socket === task {
                let message = try await task.receive()
                switch message {
                case .string(let text): handleSocketText(text)
                case .data(let data) where data.count <= 64 * 1024:
                    handleSocketData(data)
                default: break
                }
            }
        } catch {
            if socket === task { socket = nil }
            heartbeatTask?.cancel()
            heartbeatTask = nil
            throw error
        }
    }

    private func startHeartbeat(expiresUnixMS: UInt64, socket: URLSessionWebSocketTask) {
        heartbeatTask?.cancel()
        heartbeatTask = Task { [weak self, weak socket] in
            while !Task.isCancelled, let self, let socket, self.active, self.socket === socket {
                try? await Task.sleep(nanoseconds: 25_000_000_000)
                let now = UInt64(Date().timeIntervalSince1970 * 1_000)
                if now + 60_000 >= expiresUnixMS {
                    socket.cancel(with: .goingAway, reason: nil)
                    return
                }
                try? await socket.send(.string("{\"type\":\"heartbeat\",\"protocolVersion\":1}"))
            }
        }
    }

    private func handleSocketText(_ text: String) {
        guard let data = text.data(using: .utf8), data.count <= 64 * 1024 else { return }
        handleSocketData(data)
    }

    private func handleSocketData(_ data: Data) {
        guard let message = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              message.int64("protocolVersion") == 1,
              let type = message["type"] as? String else { return }
        switch type {
        case "device-presence":
            devices = (message["devices"] as? [[String: Any]] ?? []).compactMap(Self.parseDevice)
                .filter { $0.id != context?.globalDeviceID }
        case "device-command":
            Task { await importIncoming(message) }
        case "command-ack":
            guard let commandID = message["commandId"] as? String else { return }
            handleCommandAck(commandID: commandID,
                             status: message["status"] as? String,
                             detail: message["detailCode"] as? String)
        case "command-ack-recorded":
            if let commandID = message["commandId"] as? String { ackReceipts.insert(commandID) }
        default: break
        }
    }

    private func importIncoming(_ message: [String: Any]) async {
        guard let native,
              let registration,
              let payload = message["payload"] as? [String: Any],
              payload["type"] as? String == "send-file",
              let commandID = message["commandId"] as? String,
              let sourceDeviceID = message["sourceDeviceId"] as? String,
              let transferID = payload["nativeTransferId"] as? String,
              let invitation = payload["invitationPackage"] as? String,
              invitation.utf8.count <= 12 * 1024,
              let endpoint = message["nativeSignalingEndpoint"] as? String,
              FlowShareWirePolicy.validSignalingEndpoint(endpoint),
              let fileName = payload["fileName"] as? String,
              FlowShareWirePolicy.validFileName(fileName),
              let fileSize = payload.int64("fileSize"), fileSize > 0, fileSize <= 64 * 1024 * 1024 * 1024,
              let hash = payload["fileSha256"] as? String, FlowShareWirePolicy.validSHA256(hash),
              let expiryMS = message.int64("expiresUnixMs"), expiryMS > Int64(Date().timeIntervalSince1970 * 1_000) else { return }
        if incoming.contains(where: { $0.commandID == commandID }) {
            // Reconnecting is expected after consuming a one-use receiver
            // bootstrap. While the user is still deciding, never acknowledge
            // this as a duplicate: the sender treats duplicate as permission
            // to begin the native transfer.
            return
        }
        if let existing = transfers.first(where: { $0.id == transferID }),
           let acknowledgement = FlowShareWirePolicy.acknowledgementForExistingTransfer(
            state: existing.state,
            isPending: incoming.contains(where: { $0.transferID == transferID })
           ) {
            try? await sendAck(commandID: commandID, status: acknowledgement, detail: "already-processed")
            return
        }
        let request = FlowShareIncomingRequest(
            commandID: commandID,
            sourceDeviceID: sourceDeviceID,
            sourceDisplayName: String((message["sourceDisplayName"] as? String ?? "FlowGet device").prefix(80)),
            transferID: transferID,
            receiverBootstrapID: payload["receiverBootstrapId"] as? String ?? registration.bootstrap.receiverBootstrapId,
            invitationPackage: invitation,
            signalingEndpoint: endpoint,
            fileName: fileName,
            fileSize: fileSize,
            fileSHA256: hash.lowercased(),
            expiresAt: Date(timeIntervalSince1970: TimeInterval(expiryMS) / 1_000),
            friendTransfer: message["friendTransfer"] as? Bool == true,
            friendSessionID: message["friendSessionId"] as? String
        )
        do {
            let status = try await native.importInvitation(request)
            guard status.transferId == transferID else { throw FlowShareClientError.invalidResponse }
            incomingCommandByTransfer[transferID] = commandID
            peerByTransfer[transferID] = request.sourceDisplayName
            upsert(status: status, fileName: fileName, peerName: request.sourceDisplayName)
            let autoAccept = request.friendTransfer && request.friendSessionID.map(acceptedFriendSessions.contains) == true
            if autoAccept { await accept(request) } else { incoming.append(request) }
            // Receiver bootstraps are one-use. Reconnect after import (and, for
            // an accepted friend batch, after its ACK) to advertise a fresh one.
            socket?.cancel(with: .goingAway, reason: nil)
        } catch {
            try? await sendAck(commandID: commandID, status: "failed", detail: "invitation-import-failed")
        }
    }

    private func handleCommandAck(commandID: String, status: String?, detail: String?) {
        switch status {
        case "accepted", "completed", "duplicate":
            if let pending = pendingOutgoing[commandID] {
                startOutgoing(commandID: commandID, pending: pending)
            } else {
                earlyAcceptedCommands.insert(commandID)
            }
        case "delivered":
            if let id = pendingOutgoing[commandID]?.transferID {
                updateTransfer(id: id) { $0.state = "Awaiting acceptance" }
            }
        case "rejected", "expired", "failed":
            if let pending = pendingOutgoing.removeValue(forKey: commandID) {
                markFailed(transferID: pending.transferID, message: detail ?? "Peer rejected the transfer")
                Task { await native?.releaseStagedSource(for: pending.transferID) }
            }
        default: break
        }
    }

    private func startOutgoing(commandID: String, pending: PendingOutgoing) {
        guard startedCommands.insert(commandID).inserted else { return }
        earlyAcceptedCommands.remove(commandID)
        pendingOutgoing.removeValue(forKey: commandID)
        Task { [weak self] in
            guard let self, let native = self.native else { return }
            self.monitorTransfer(id: pending.transferID, direction: .send)
            do {
                self.handleNative(try await native.startSender(
                    transferID: pending.transferID,
                    endpoint: pending.endpoint
                ))
            } catch {
                self.stopMonitoringTransfer(pending.transferID)
                self.startedCommands.remove(commandID)
                self.markFailed(transferID: pending.transferID, message: Self.message(for: error))
                await native.releaseStagedSource(for: pending.transferID)
            }
        }
    }

    private func send(file: URL, target: FlowShareDevice, friend: FriendSession?) async throws -> String {
        guard let native, let registration else { throw FlowShareClientError.notConnected }
        guard target.online,
              target.canReceiveFile,
              let bootstrap = target.receiverBootstrapPackage,
              let bootstrapExpiry = target.receiverBootstrapExpiresAt,
              bootstrapExpiry > Date().addingTimeInterval(15) else { throw FlowShareClientError.targetUnavailable }
        let prepared = try await native.prepareSender(sourceURL: file,
                                                      receiverBootstrapPackage: bootstrap)
        let transferID = prepared.transfer.transferId
        focusedTransferID = transferID
        sessionTitle = friend == nil ? "Connecting to \(target.displayName)" : "Connecting via Friend Code"
        peerByTransfer[transferID] = target.displayName
        upsert(status: prepared.transfer,
               fileName: prepared.displayFilename,
               peerName: target.displayName)
        updateTransfer(id: transferID) { $0.state = "Waiting for peer" }
        let commandID = UUID().uuidString
        let payload: [String: Any] = [
            "type": "send-file",
            "nativeTransferId": transferID,
            "receiverBootstrapId": target.receiverBootstrapID ?? "",
            "invitationPackage": prepared.invitationPackage,
            "fileName": prepared.displayFilename,
            "fileSize": prepared.fileSize,
            "fileSha256": prepared.expectedSha256
        ]
        var body: [String: Any]
        let path: String
        if let friend {
            path = "friend/command"
            body = [
                "sourceDeviceId": registration.context.globalDeviceID,
                "platform": "ios",
                "friendSessionId": friend.id,
                "sessionCredential": friend.credential,
                "commandId": commandID,
                "payload": payload
            ]
        } else {
            path = "device/command"
            body = [
                "sourceDeviceId": registration.context.globalDeviceID,
                "platform": "ios",
                "targetDeviceId": target.id,
                "commandId": commandID,
                "payload": payload
            ]
        }
        do {
            let response = try await post(path: path,
                                          authorization: "Bearer \(registration.context.entitlementJWT)",
                                          body: body)
            guard response["queued"] as? Bool == true,
                  let endpoint = response["nativeSignalingEndpoint"] as? String,
                  FlowShareWirePolicy.validSignalingEndpoint(endpoint) else {
                throw FlowShareClientError.invalidResponse
            }
            let pending = PendingOutgoing(transferID: transferID, endpoint: endpoint)
            pendingOutgoing[commandID] = pending
            if earlyAcceptedCommands.contains(commandID) { startOutgoing(commandID: commandID, pending: pending) }
            return transferID
        } catch {
            _ = try? await native.cancel(transferID: transferID, direction: .send)
            markFailed(transferID: transferID, message: Self.message(for: error))
            throw error
        }
    }

    private func readyDevice(id: String, differentFrom bootstrapID: String?) async throws -> FlowShareDevice {
        let deadline = Date().addingTimeInterval(30)
        while Date() < deadline {
            if let device = devices.first(where: {
                $0.id == id && $0.online && $0.canReceiveFile &&
                $0.receiverBootstrapPackage != nil && $0.receiverBootstrapID != bootstrapID &&
                ($0.receiverBootstrapExpiresAt ?? .distantPast) > Date().addingTimeInterval(15)
            }) { return device }
            try await Task.sleep(nanoseconds: 500_000_000)
        }
        throw FlowShareClientError.targetUnavailable
    }

    private func resolveFriend(code: String) async throws -> FriendSession {
        guard let registration else { throw FlowShareClientError.notConnected }
        let response = try await post(path: "friend/resolve",
                                      authorization: "Bearer \(registration.context.entitlementJWT)",
                                      body: [
                                        "sourceDeviceId": registration.context.globalDeviceID,
                                        "platform": "ios",
                                        "code": code
                                      ])
        guard let id = response["friendSessionId"] as? String,
              let credential = response["sessionCredential"] as? String,
              let expiry = response.int64("expiresUnixMs"),
              Date(timeIntervalSince1970: TimeInterval(expiry) / 1_000) > Date().addingTimeInterval(15),
              let rawTarget = response["targetDevice"] as? [String: Any],
              var target = Self.parseDevice(rawTarget) else { throw FlowShareClientError.invalidResponse }
        target.online = true
        return FriendSession(id: id,
                             credential: credential,
                             expiresAt: Date(timeIntervalSince1970: TimeInterval(expiry) / 1_000),
                             target: target)
    }

    private func resolveFriendWithFreshBootstrap(
        code: String,
        differentFrom previousBootstrapID: String?
    ) async throws -> FriendSession {
        let deadline = Date().addingTimeInterval(20)
        while Date() < deadline {
            if let resolved = try? await resolveFriend(code: code),
               let bootstrapID = resolved.target.receiverBootstrapID,
               bootstrapID != previousBootstrapID {
                return resolved
            }
            try await Task.sleep(nanoseconds: 500_000_000)
        }
        throw FlowShareClientError.targetUnavailable
    }

    private func waitForTerminal(transferID: String) async throws {
        let deadline = Date().addingTimeInterval(15 * 60)
        while Date() < deadline {
            if let transfer = transfers.first(where: { $0.id == transferID }) {
                if transfer.state == "Completed" { return }
                if ["Failed", "Rejected", "Cancelled"].contains(transfer.state) {
                    throw FlowShareClientError.rejected(transfer.errorCode ?? "Transfer did not complete.")
                }
            }
            try await Task.sleep(nanoseconds: 500_000_000)
        }
        throw FlowShareClientError.timedOut
    }

    private func handleNative(_ status: FlowShareTransferStatus) {
        upsert(status: status,
               fileName: transfers.first(where: { $0.id == status.transferId })?.fileName ?? "FlowGet file",
               peerName: peerByTransfer[status.transferId])
        if status.state == .completed || status.state == .cancelled || status.state == .rejected || status.state == .failed {
            stopMonitoringTransfer(status.transferId)
            if status.direction == .send { Task { await native?.releaseStagedSource(for: status.transferId) } }
            if !transfers.contains(where: { ["Connecting", "Connected", "Transferring", "Resuming", "Verifying"].contains($0.state) }) {
                endBackgroundTask()
            }
        } else if status.state == .connecting || status.state == .connected || status.state == .transferring || status.state == .resuming || status.state == .verifying {
            beginBackgroundTaskIfNeeded()
        }
        if status.direction == .receive,
           status.state == .completed,
           let commandID = incomingCommandByTransfer[status.transferId],
           completedAcknowledged.insert(status.transferId).inserted {
            Task { try? await sendAck(commandID: commandID, status: "completed", detail: nil) }
        }
    }

    private func monitorTransfer(id: String, direction: FlowShareDirection) {
        guard transferMonitorTasks[id] == nil else { return }
        transferMonitorTasks[id] = Task { [weak self] in
            while !Task.isCancelled {
                guard let self, let native = self.native else { return }
                do {
                    let status = try await native.transferStatus(transferID: id, direction: direction)
                    self.handleNative(status)
                    if Self.isTerminal(status.state) { return }
                } catch {
                    // Native events may still complete the transfer. A transient
                    // status-read failure must not cancel a healthy connection.
                }
                try? await Task.sleep(nanoseconds: 250_000_000)
            }
        }
    }

    private func stopMonitoringTransfer(_ id: String) {
        transferMonitorTasks.removeValue(forKey: id)?.cancel()
    }

    private static func isTerminal(_ state: FlowShareTransferState) -> Bool {
        state == .completed || state == .cancelled || state == .rejected || state == .failed
    }

    private func upsert(status: FlowShareTransferStatus, fileName: String, peerName: String?) {
        let direction: FlowShareTransfer.Direction = status.direction == .send ? .send : .receive
        let errorCode = status.failure.map { String(describing: $0.code) }
        if let index = transfers.firstIndex(where: { $0.id == status.transferId }) {
            transfers[index].completedBytes = Int64(clamping: status.bytesTransferred)
            transfers[index].totalBytes = Int64(clamping: status.totalBytes)
            transfers[index].bytesPerSecond = Int64(clamping: status.bytesPerSecond)
            transfers[index].state = Self.label(for: status.state)
            transfers[index].errorCode = errorCode
            transfers[index].updatedAt = Date()
        } else {
            transfers.insert(FlowShareTransfer(
                id: status.transferId,
                direction: direction,
                fileName: fileName,
                totalBytes: Int64(clamping: status.totalBytes),
                completedBytes: Int64(clamping: status.bytesTransferred),
                bytesPerSecond: Int64(clamping: status.bytesPerSecond),
                state: Self.label(for: status.state),
                peerName: peerName,
                errorCode: errorCode
            ), at: 0)
        }
        persistTransfers()
    }

    private func updateTransfer(id: String, update: (inout FlowShareTransfer) -> Void) {
        guard let index = transfers.firstIndex(where: { $0.id == id }) else { return }
        update(&transfers[index])
        transfers[index].updatedAt = Date()
        persistTransfers()
    }

    private func markFailed(transferID: String, message: String) {
        updateTransfer(id: transferID) {
            $0.state = "Failed"
            $0.errorCode = message
        }
    }

    private func persistTransfers() {
        Persistence.save(Array(transfers.prefix(250)), name: "flowshare-transfers.json")
    }

    private func beginBackgroundTaskIfNeeded() {
        guard backgroundTask == .invalid else { return }
        backgroundTask = UIApplication.shared.beginBackgroundTask(withName: "FlowShare transfer") { [weak self] in
            Task { @MainActor [weak self] in self?.endBackgroundTask() }
        }
    }

    private func endBackgroundTask() {
        guard backgroundTask != .invalid else { return }
        UIApplication.shared.endBackgroundTask(backgroundTask)
        backgroundTask = .invalid
    }

    private func sendAckConfirmed(commandID: String, status: String) async throws -> Bool {
        ackReceipts.remove(commandID)
        let deadline = Date().addingTimeInterval(15)
        while Date() < deadline {
            if socket == nil || connection != .online {
                try await Task.sleep(nanoseconds: 250_000_000)
                continue
            }
            try await sendAck(commandID: commandID, status: status, detail: nil)
            try await Task.sleep(nanoseconds: 750_000_000)
            if ackReceipts.remove(commandID) != nil { return true }
        }
        return false
    }

    private func sendAck(commandID: String, status: String, detail: String?) async throws {
        guard let socket else { throw FlowShareClientError.notConnected }
        var value: [String: Any] = [
            "type": "command-ack",
            "protocolVersion": 1,
            "commandId": commandID,
            "status": status
        ]
        if let detail { value["detailCode"] = detail }
        let data = try JSONSerialization.data(withJSONObject: value)
        guard let text = String(data: data, encoding: .utf8) else { throw FlowShareClientError.invalidResponse }
        try await socket.send(.string(text))
    }

    private func post(path: String, authorization: String, body: [String: Any]) async throws -> [String: Any] {
        let url = AppConfig.flowShareBaseURL.appendingPathComponent(path)
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.timeoutInterval = 30
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue(authorization, forHTTPHeaderField: "Authorization")
        request.httpBody = try JSONSerialization.data(withJSONObject: body)
        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse,
              http.url?.scheme == AppConfig.flowShareBaseURL.scheme,
              http.url?.host == AppConfig.flowShareBaseURL.host else { throw FlowShareClientError.invalidResponse }
        if http.statusCode == 401 || http.statusCode == 403 { throw FlowShareClientError.licenseRequired }
        guard (200..<300).contains(http.statusCode),
              let value = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            let value = (try? JSONSerialization.jsonObject(with: data) as? [String: Any])
            throw FlowShareClientError.rejected(value?["error"] as? String ?? "FlowShare request failed (HTTP \(http.statusCode)).")
        }
        return value
    }

    private static func parseDevice(_ value: [String: Any]) -> FlowShareDevice? {
        guard let id = value["deviceId"] as? String,
              let name = value["displayName"] as? String,
              let platform = value["platform"] as? String,
              let capabilities = value["capabilities"] as? [String: Any] else { return nil }
        let bootstrap = value["receiverBootstrap"] as? [String: Any]
        let expiry = bootstrap?.int64("expiresUnixMs")
        return FlowShareDevice(
            id: id,
            displayName: String(name.prefix(120)),
            platform: platform,
            online: value["online"] as? Bool == true,
            canSendFile: capabilities["sendFile"] as? Bool == true,
            canReceiveFile: capabilities["receiveFile"] as? Bool == true,
            canReceiveURL: capabilities["receiveUrl"] as? Bool == true,
            receiverBootstrapID: bootstrap?["receiverBootstrapId"] as? String,
            receiverBootstrapPackage: bootstrap?["receiverBootstrapPackage"] as? String,
            receiverBootstrapExpiresAt: expiry.map { Date(timeIntervalSince1970: TimeInterval($0) / 1_000) }
        )
    }

    private static func label(for state: FlowShareTransferState) -> String {
        switch state {
        case .prepared: "Prepared"
        case .incoming: "Incoming"
        case .awaitingAcceptance: "Awaiting acceptance"
        case .waitingForPeer: "Waiting for peer"
        case .connecting: "Connecting"
        case .connected: "Connected"
        case .transferring: "Transferring"
        case .paused: "Paused"
        case .resuming: "Resuming"
        case .verifying: "Verifying"
        case .completed: "Completed"
        case .cancelled: "Cancelled"
        case .rejected: "Rejected"
        case .failed: "Failed"
        }
    }

    private static func message(for error: Error) -> String {
        (error as? LocalizedError)?.errorDescription ?? error.localizedDescription
    }
}

private final class FlowShareNoRedirectDelegate: NSObject, URLSessionTaskDelegate {
    func urlSession(_ session: URLSession,
                    task: URLSessionTask,
                    willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest,
                    completionHandler: @escaping (URLRequest?) -> Void) {
        completionHandler(nil)
    }
}

private extension Dictionary where Key == String, Value == Any {
    func int64(_ key: String) -> Int64? {
        if let value = self[key] as? Int64 { return value }
        if let value = self[key] as? UInt64, value <= UInt64(Int64.max) { return Int64(value) }
        if let value = self[key] as? NSNumber { return value.int64Value }
        return nil
    }
}
