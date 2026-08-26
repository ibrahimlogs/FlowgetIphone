import Foundation
import UserNotifications
import Combine

@MainActor
final class DownloadManager: NSObject, ObservableObject {
    @Published private(set) var items: [DownloadItem]
    var onActivity: (@MainActor (ActivityItem) -> Void)?
    private(set) var maxConcurrent = 3
    private(set) var allowsCellularAccess = true
    private(set) var autoRetry = true
    private var taskByID: [UUID: URLSessionDownloadTask] = [:]
    private var idByTask: [Int: UUID] = [:]
    private var progressSample: [UUID: (bytes: Int64, date: Date)] = [:]
    private lazy var session: URLSession = {
        let config = URLSessionConfiguration.background(withIdentifier: "com.flowget.ios.downloads")
        config.isDiscretionary = false
        config.sessionSendsLaunchEvents = true
        config.allowsCellularAccess = true
        config.httpMaximumConnectionsPerHost = 4
        return URLSession(configuration: config, delegate: self, delegateQueue: nil)
    }()

    override init() {
        items = Persistence.load([DownloadItem].self, name: "downloads.json", fallback: [])
        super.init()
        _ = session
        restoreBackgroundTasks()
    }

    func add(url: URL, title: String? = nil, wifiOnly: Bool = false, autoStart: Bool = true) {
        var item = DownloadItem(title: title?.nonEmpty ?? url.lastPathComponent.nonEmpty ?? url.host ?? "Download", url: url)
        item.wifiOnly = wifiOnly
        item.autoStart = autoStart
        items.insert(item, at: 0)
        persist()
        onActivity?(ActivityItem(title: "Download added", detail: item.title, kind: .download))
        if autoStart { start(item.id) }
    }

    func apply(settings: AppSettings) {
        maxConcurrent = min(10, max(1, settings.maxConcurrent))
        allowsCellularAccess = settings.useMobileData
        autoRetry = settings.autoRetry
        startNextQueuedIfPossible()
    }

    func startQueuedDownloads() {
        startNextQueuedIfPossible()
    }

    func start(_ id: UUID) {
        guard let index = items.firstIndex(where: { $0.id == id }) else { return }
        let item = items[index]
        guard [DownloadSource.direct, .hls, .dash].contains(item.source) else {
            items[index].status = .failed
            items[index].errorMessage = "This source requires the native iOS transfer engine."
            persist(); return
        }
        guard !item.status.isRunning else { return }
        guard taskByID.count < maxConcurrent else {
            items[index].status = .queued
            persist()
            return
        }
        let resumeURL = Self.resumeFolder.appendingPathComponent("\(id.uuidString).resume")
        let task: URLSessionDownloadTask
        if let resumeData = try? Data(contentsOf: resumeURL), !resumeData.isEmpty {
            task = session.downloadTask(withResumeData: resumeData)
            try? FileManager.default.removeItem(at: resumeURL)
        } else {
            var request = URLRequest(url: item.url)
            request.allowsCellularAccess = allowsCellularAccess && !item.wifiOnly
            task = session.downloadTask(with: request)
        }
        task.taskDescription = id.uuidString
        taskByID[id] = task
        idByTask[task.taskIdentifier] = id
        items[index].status = .downloading
        items[index].errorMessage = nil
        progressSample[id] = (items[index].downloadedBytes, Date())
        persist()
        task.resume()
    }

    func pause(_ id: UUID) {
        let resumeURL = Self.resumeFolder.appendingPathComponent("\(id.uuidString).resume")
        taskByID[id]?.cancel(byProducingResumeData: { data in
            guard let data else { return }
            try? data.write(to: resumeURL, options: [.atomic, .completeFileProtection])
        })
        update(id) { $0.status = .paused; $0.speedBytesPerSecond = 0 }
        taskByID[id] = nil
        idByTask = idByTask.filter { $0.value != id }
        progressSample[id] = nil
        startNextQueuedIfPossible()
    }

    func remove(_ id: UUID) {
        taskByID[id]?.cancel()
        if let item = items.first(where: { $0.id == id }), let file = item.localFileName {
            try? FileManager.default.removeItem(at: Self.downloadFolder.appendingPathComponent(file))
        }
        items.removeAll { $0.id == id }
        taskByID[id] = nil
        idByTask = idByTask.filter { $0.value != id }
        progressSample[id] = nil
        try? FileManager.default.removeItem(at: Self.resumeFolder.appendingPathComponent("\(id.uuidString).resume"))
        persist()
    }

    func localURL(for item: DownloadItem) -> URL? {
        item.localFileName.map { Self.downloadFolder.appendingPathComponent($0) }
    }

    private func update(_ id: UUID, change: (inout DownloadItem) -> Void) {
        guard let index = items.firstIndex(where: { $0.id == id }) else { return }
        change(&items[index]); persist()
    }
    private func persist() { Persistence.save(items, name: "downloads.json") }

    private func finishTask(_ id: UUID) {
        taskByID[id] = nil
        idByTask = idByTask.filter { $0.value != id }
        progressSample[id] = nil
        startNextQueuedIfPossible()
    }

    private func startNextQueuedIfPossible() {
        while taskByID.count < maxConcurrent,
              let next = items.first(where: { $0.status == .queued && $0.autoStart }) {
            start(next.id)
        }
    }

    private func restoreBackgroundTasks() {
        session.getAllTasks { tasks in
            Task { @MainActor in
                for task in tasks {
                    guard let rawID = task.taskDescription, let id = UUID(uuidString: rawID),
                          let downloadTask = task as? URLSessionDownloadTask else { continue }
                    self.taskByID[id] = downloadTask
                    self.idByTask[task.taskIdentifier] = id
                    self.update(id) { item in
                        item.status = task.state == .suspended ? .paused : .downloading
                    }
                }
                self.startNextQueuedIfPossible()
            }
        }
    }

    static var downloadFolder: URL {
        let documents = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        let folder = documents.appendingPathComponent("FlowGet", isDirectory: true)
        try? FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        return folder
    }

    static var resumeFolder: URL {
        let caches = FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask)[0]
        let folder = caches.appendingPathComponent("FlowGet/Resume", isDirectory: true)
        try? FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        return folder
    }
}

extension DownloadManager: URLSessionDownloadDelegate {
    nonisolated func urlSession(_ session: URLSession, downloadTask: URLSessionDownloadTask,
                               didWriteData bytesWritten: Int64, totalBytesWritten: Int64,
                               totalBytesExpectedToWrite: Int64) {
        let taskID = downloadTask.taskIdentifier
        Task { @MainActor in
            guard let id = self.idByTask[taskID] ?? downloadTask.taskDescription.flatMap(UUID.init(uuidString:)) else { return }
            self.update(id) { item in
                item.status = .downloading
                item.downloadedBytes = totalBytesWritten
                item.totalBytes = totalBytesExpectedToWrite > 0 ? totalBytesExpectedToWrite : nil
                let now = Date()
                if let previous = self.progressSample[id] {
                    let elapsed = now.timeIntervalSince(previous.date)
                    if elapsed >= 0.35 {
                        item.speedBytesPerSecond = max(0, Int64(Double(totalBytesWritten - previous.bytes) / elapsed))
                        self.progressSample[id] = (totalBytesWritten, now)
                    }
                } else {
                    self.progressSample[id] = (totalBytesWritten, now)
                }
            }
        }
    }

    nonisolated func urlSession(_ session: URLSession, downloadTask: URLSessionDownloadTask,
                               didFinishDownloadingTo location: URL) {
        let taskID = downloadTask.taskIdentifier
        let suggested = downloadTask.response?.suggestedFilename
        Task { @MainActor in
            guard let id = self.idByTask[taskID] ?? downloadTask.taskDescription.flatMap(UUID.init(uuidString:)),
                  let index = self.items.firstIndex(where: { $0.id == id }) else { return }
            let safeName = (suggested?.nonEmpty ?? self.items[index].title).replacingOccurrences(of: "/", with: "-")
            let uniqueName = "\(id.uuidString.prefix(8))-\(safeName)"
            let destination = Self.downloadFolder.appendingPathComponent(uniqueName)
            do {
                try? FileManager.default.removeItem(at: destination)
                try FileManager.default.moveItem(at: location, to: destination)
                self.items[index].status = .completed
                self.items[index].completedAt = Date()
                self.items[index].localFileName = uniqueName
                try? FileManager.default.removeItem(at: Self.resumeFolder.appendingPathComponent("\(id.uuidString).resume"))
                let diskSize = try? destination.resourceValues(forKeys: [.fileSizeKey]).fileSize
                self.items[index].downloadedBytes = self.items[index].totalBytes ?? diskSize.map(Int64.init) ?? 0
                self.onActivity?(ActivityItem(title: "Download completed", detail: self.items[index].title, kind: .download))
                let content = UNMutableNotificationContent()
                content.title = "Download completed"
                content.body = self.items[index].title
                content.sound = .default
                UNUserNotificationCenter.current().add(UNNotificationRequest(identifier: id.uuidString, content: content, trigger: nil))
            } catch {
                self.items[index].status = .failed
                self.items[index].errorMessage = error.localizedDescription
            }
            self.persist()
            self.finishTask(id)
        }
    }

    nonisolated func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        guard let error else { return }
        let taskID = task.taskIdentifier
        Task { @MainActor in
            guard let id = self.idByTask[taskID] ?? task.taskDescription.flatMap(UUID.init(uuidString:)),
                  let index = self.items.firstIndex(where: { $0.id == id }), self.items[index].status != .paused else { return }
            if self.autoRetry && self.items[index].retryCount < 3 {
                self.items[index].retryCount += 1
                self.items[index].status = .retrying
                self.items[index].errorMessage = "Retrying after a network interruption."
                self.finishTask(id)
                let delay = UInt64(self.items[index].retryCount * 2) * 1_000_000_000
                try? await Task.sleep(nanoseconds: delay)
                guard self.items.indices.contains(index), self.items[index].id == id,
                      self.items[index].status == .retrying else { return }
                self.items[index].status = .queued
                self.persist()
                self.startNextQueuedIfPossible()
                return
            }
            self.items[index].status = .failed
            self.items[index].speedBytesPerSecond = 0
            self.items[index].errorMessage = error.localizedDescription
            self.persist()
            self.finishTask(id)
        }
    }

    nonisolated func urlSessionDidFinishEvents(forBackgroundURLSession session: URLSession) {
        DispatchQueue.main.async {
            FlowGetAppDelegate.backgroundSessionCompletion?()
            FlowGetAppDelegate.backgroundSessionCompletion = nil
        }
    }
}

private extension String {
    var nonEmpty: String? { isEmpty ? nil : self }
}
