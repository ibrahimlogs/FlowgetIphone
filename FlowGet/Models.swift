import Foundation
import SwiftUI

enum DownloadStatus: String, Codable, CaseIterable, Hashable {
    case queued, probing, preparing, downloading, pausing, paused, retrying
    case verifying, finalizing, completed, failed, cancelled, deleting

    var isRunning: Bool { [.probing, .preparing, .downloading, .pausing, .verifying, .finalizing].contains(self) }
    var isTerminal: Bool { [.completed, .failed, .cancelled].contains(self) }
    var label: String { rawValue.capitalized }
}

enum DownloadSource: String, Codable { case direct, hls, dash, ftp, torrent, flowShare, remotePC }

struct DownloadItem: Identifiable, Codable, Equatable {
    var id = UUID()
    var title: String
    var url: URL
    var status: DownloadStatus = .queued
    var totalBytes: Int64?
    var downloadedBytes: Int64 = 0
    var addedAt = Date()
    var completedAt: Date?
    var source: DownloadSource = .direct
    var localFileName: String?
    var mimeType: String?
    var speedBytesPerSecond: Int64 = 0
    var retryCount = 0
    var errorMessage: String?
    var wifiOnly = false
    var autoStart = true

    var progress: Double {
        guard let totalBytes, totalBytes > 0 else { return 0 }
        return min(1, max(0, Double(downloadedBytes) / Double(totalBytes)))
    }
}

struct ActivityItem: Identifiable, Codable {
    enum Kind: String, Codable { case download, transfer, system }
    var id = UUID()
    var title: String
    var detail: String
    var date = Date()
    var kind: Kind
    var succeeded = true
}

struct FlowGetAccount: Codable, Equatable {
    var id: String
    var name: String
    var email: String
    var emailVerified: Bool
}

struct AuthTokens: Codable {
    var accessToken: String
    var refreshToken: String
    var expiresAt: Date
}

enum ThemeMode: String, Codable, CaseIterable, Identifiable {
    case system, light, dark
    var id: String { rawValue }
    var title: String { rawValue.capitalized }
    var colorScheme: SwiftUI.ColorScheme? {
        switch self { case .system: nil; case .light: .light; case .dark: .dark }
    }
}

struct AppSettings: Codable {
    var downloadDirectory = "On My iPhone/FlowGet"
    var maxConcurrent = 3
    var globalSpeedLimitBytes: Int64 = 0
    var wifiOnly = false
    var autoRetry = true
    var useMobileData = true
    var notifications = true
    var theme: ThemeMode = .system
    var contentBlocking = true
    var aggressiveBlocking = false
    var popupBlocking = true
    var backgroundPlayback = true
    var pictureInPicture = true
}

struct BrowserLink: Identifiable, Codable, Hashable {
    var id = UUID()
    var title: String
    var url: URL
    var visitedAt = Date()
}

struct DownloadSchedule: Identifiable, Codable {
    var id = UUID()
    var title = "Scheduled downloads"
    var hour = 22
    var minute = 0
    var weekdays: Set<Int> = Set(1...7)
    var wifiOnly = true
    var enabled = true
}

struct FlowShareDevice: Identifiable, Codable, Hashable {
    var id: String
    var displayName: String
    var platform: String
    var online: Bool
    var nearby = false
}

struct FlowShareInvite: Codable {
    var sessionID: String
    var code: String
    var expiresAt: Date
}

struct FlowShareTransfer: Identifiable, Codable {
    enum Direction: String, Codable { case send, receive }
    var id = UUID()
    var direction: Direction
    var fileName: String
    var totalBytes: Int64
    var completedBytes: Int64 = 0
    var state = "Prepared"
    var peerName: String?
}

extension Int64 {
    var fileSize: String { ByteCountFormatter.string(fromByteCount: self, countStyle: .file) }
}
