import Foundation

enum URLInput {
    static func downloadURL(from rawValue: String) -> URL? {
        let trimmed = rawValue.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return nil }
        let candidate = trimmed.contains("://") ? trimmed : "https://\(trimmed)"
        guard let url = URL(string: candidate),
              let scheme = url.scheme?.lowercased(),
              ["http", "https"].contains(scheme),
              url.host?.isEmpty == false else { return nil }
        return url
    }

    static func browserURL(from rawValue: String) -> URL? {
        let trimmed = rawValue.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return nil }
        if let url = downloadURL(from: trimmed), trimmed.contains(".") && !trimmed.contains(" ") {
            return url
        }
        var components = URLComponents(string: "https://www.google.com/search")
        components?.queryItems = [URLQueryItem(name: "q", value: trimmed)]
        return components?.url
    }
}
enum DownloadStatePolicy {
    static func canTransition(from: DownloadStatus, to: DownloadStatus) -> Bool {
        if from == to { return true }
        let allowed: [DownloadStatus: Set<DownloadStatus>] = [
            .queued: [.probing, .preparing, .downloading, .paused, .cancelled],
            .probing: [.preparing, .pausing, .retrying, .failed, .cancelled],
            .preparing: [.downloading, .finalizing, .pausing, .retrying, .failed, .cancelled],
            .downloading: [.pausing, .paused, .retrying, .verifying, .completed, .failed, .cancelled],
            .pausing: [.paused, .cancelled],
            .paused: [.queued, .downloading, .cancelled, .deleting],
            .retrying: [.queued, .paused, .failed, .cancelled],
            .verifying: [.finalizing, .failed, .cancelled],
            .finalizing: [.completed, .failed, .cancelled],
            .completed: [.deleting],
            .failed: [.queued, .downloading, .deleting, .cancelled],
            .cancelled: [.queued, .deleting],
            .deleting: []
        ]
        return allowed[from]?.contains(to) == true
    }
}
