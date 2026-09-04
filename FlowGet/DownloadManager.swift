import Foundation
import UserNotifications
import Combine
import WebKit

@MainActor
final class DownloadManager: NSObject, ObservableObject {
    @Published private(set) var items: [DownloadItem]
    var onActivity: (@MainActor (ActivityItem) -> Void)?
    private(set) var maxConcurrent = 3
    private(set) var allowsCellularAccess = true
    private(set) var autoRetry = true
    private var taskByID: [UUID: URLSessionDataTask] = [:]
    private var idByTask: [Int: UUID] = [:]
    nonisolated(unsafe) private var sinkByTask: [Int: DownloadFileSink] = [:]
    nonisolated private let sinkLock = NSLock()
    private var requestByID: [UUID: URLRequest] = [:]
    private var progressSample: [UUID: (bytes: Int64, date: Date)] = [:]
    private struct BrowserDownloadContext {
        let id: UUID
        let sourceURL: URL
        var destination: URL?
        var suggestedName: String
        var mimeType: String?

        init(id: UUID, sourceURL: URL, suggestedName: String) {
            self.id = id
            self.sourceURL = sourceURL
            self.suggestedName = suggestedName
        }
    }
    private var browserDownloads: [ObjectIdentifier: WKDownload] = [:]
    private var browserWebViews: [ObjectIdentifier: WKWebView] = [:]
    private var browserDownloadContexts: [ObjectIdentifier: BrowserDownloadContext] = [:]
    private var browserProgressObservations: [ObjectIdentifier: NSKeyValueObservation] = [:]
    private let sessionConfiguration: URLSessionConfiguration
    private lazy var session: URLSession = {
        // The manager lives for the lifetime of AppStore, so a regular session
        // continues across SwiftUI tab/view replacement without delegating file
        // ownership to the background-session daemon.
        let config = sessionConfiguration
        config.allowsCellularAccess = true
        config.waitsForConnectivity = true
        config.timeoutIntervalForResource = 7 * 24 * 60 * 60
        config.httpMaximumConnectionsPerHost = 4
        return URLSession(configuration: config, delegate: self, delegateQueue: nil)
    }()

    init(configuration: URLSessionConfiguration = .default, initialItems: [DownloadItem]? = nil) {
        sessionConfiguration = configuration
        items = initialItems ?? Persistence.load([DownloadItem].self, name: "downloads.json", fallback: [])
        super.init()
        _ = session
        restoreBackgroundTasks()
    }

    @discardableResult
    func add(url: URL, title: String? = nil, wifiOnly: Bool = false, autoStart: Bool = true) -> UUID? {
        add(request: Self.directRequest(for: url), title: title, wifiOnly: wifiOnly, autoStart: autoStart)
    }

    @discardableResult
    func add(request: URLRequest, title: String? = nil, wifiOnly: Bool = false, autoStart: Bool = true) -> UUID? {
        guard let url = request.url,
              let scheme = url.scheme?.lowercased(),
              ["http", "https"].contains(scheme) else { return nil }
        var request = request
        request.cachePolicy = .reloadIgnoringLocalCacheData
        request.timeoutInterval = 60
        if request.value(forHTTPHeaderField: "Accept") == nil {
            request.setValue("*/*", forHTTPHeaderField: "Accept")
        }
        if request.value(forHTTPHeaderField: "User-Agent") == nil {
            request.setValue(Self.downloadUserAgent, forHTTPHeaderField: "User-Agent")
        }
        var item = DownloadItem(title: title?.nonEmpty ?? url.lastPathComponent.nonEmpty ?? url.host ?? "Download", url: url)
        item.wifiOnly = wifiOnly
        item.autoStart = autoStart
        items.insert(item, at: 0)
        requestByID[item.id] = request
        persist()
        onActivity?(ActivityItem(title: "Download added", detail: item.title, kind: .download))
        if autoStart { start(item.id) }
        return item.id
    }

    func beginBrowserDownload(id: UUID, sourceURL: URL, title: String) {
        guard !items.contains(where: { $0.id == id }) else { return }
        var item = DownloadItem(title: title.nonEmpty ?? sourceURL.lastPathComponent.nonEmpty ?? "Browser download",
                                url: sourceURL)
        item.id = id
        item.status = .downloading
        item.autoStart = false
        items.insert(item, at: 0)
        persist()
        onActivity?(ActivityItem(title: "Browser download started", detail: item.title, kind: .download))
    }

    func adoptBrowserDownload(_ download: WKDownload, sourceURL: URL, webView: WKWebView) {
        let key = ObjectIdentifier(download)
        guard browserDownloads[key] == nil else { return }
        let id = UUID()
        let title = sourceURL.lastPathComponent.nonEmpty ?? sourceURL.host ?? "Browser download"
        browserDownloads[key] = download
        browserWebViews[key] = webView
        browserDownloadContexts[key] = BrowserDownloadContext(
            id: id,
            sourceURL: sourceURL,
            suggestedName: title
        )
        beginBrowserDownload(id: id, sourceURL: sourceURL, title: title)
        download.delegate = self
        browserProgressObservations[key] = download.progress.observe(
            \.fractionCompleted,
            options: [.new]
        ) { [weak self, weak download] progress, _ in
            DispatchQueue.main.async {
                guard let self, let download,
                      let active = self.browserDownloadContexts[ObjectIdentifier(download)] else { return }
                let total = progress.totalUnitCount > 0 ? progress.totalUnitCount : nil
                self.updateBrowserDownload(
                    id: active.id,
                    completedBytes: progress.completedUnitCount,
                    totalBytes: total
                )
            }
        }
    }

    func completeBrowserDownload(id: UUID, temporaryURL: URL, suggestedName: String, mimeType: String?) {
        defer { progressSample[id] = nil }
        guard let index = items.firstIndex(where: { $0.id == id }) else {
            try? FileManager.default.removeItem(at: temporaryURL)
            return
        }
        let safeName = Self.safeFileName(suggestedName.nonEmpty ?? items[index].title)
        let uniqueName = "\(id.uuidString.prefix(8))-\(safeName)"
        let destination = Self.downloadFolder.appendingPathComponent(uniqueName)
        do {
            if temporaryURL.standardizedFileURL != destination.standardizedFileURL {
                try? FileManager.default.removeItem(at: destination)
                try FileManager.default.moveItem(at: temporaryURL, to: destination)
            }
            try? FileManager.default.setAttributes(
                [.protectionKey: FileProtectionType.completeUntilFirstUserAuthentication],
                ofItemAtPath: destination.path
            )
            let diskSize = try destination.resourceValues(forKeys: [.fileSizeKey]).fileSize ?? 0
            items[index].status = .completed
            items[index].completedAt = Date()
            items[index].localFileName = uniqueName
            items[index].mimeType = mimeType
            items[index].downloadedBytes = Int64(diskSize)
            items[index].totalBytes = Int64(diskSize)
            items[index].speedBytesPerSecond = 0
            items[index].errorMessage = nil
            onActivity?(ActivityItem(title: "Download completed", detail: items[index].title, kind: .download))
        } catch {
            items[index].status = .failed
            items[index].errorMessage = Self.userFacingMessage(for: error)
        }
        persist()
    }

    func updateBrowserDownload(id: UUID, completedBytes: Int64, totalBytes: Int64?) {
        guard let index = items.firstIndex(where: { $0.id == id }), items[index].status == .downloading else { return }
        let now = Date()
        if let previous = progressSample[id] {
            let elapsed = now.timeIntervalSince(previous.date)
            let finished = totalBytes.map { completedBytes >= $0 } ?? false
            guard elapsed >= 0.35 || finished else { return }
            items[index].speedBytesPerSecond = max(0, Int64(Double(completedBytes - previous.bytes) / max(elapsed, 0.001)))
        }
        items[index].downloadedBytes = max(0, completedBytes)
        items[index].totalBytes = totalBytes.flatMap { $0 > 0 ? $0 : nil }
        progressSample[id] = (completedBytes, now)
        persist()
    }

    func failBrowserDownload(id: UUID?, message: String) {
        guard let id, let index = items.firstIndex(where: { $0.id == id }) else { return }
        items[index].status = .failed
        items[index].speedBytesPerSecond = 0
        items[index].errorMessage = message
        progressSample[id] = nil
        persist()
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
        var request = requestByID[id] ?? Self.directRequest(for: item.url)
        request.allowsCellularAccess = allowsCellularAccess && !item.wifiOnly
        let partial = Self.partialFolder.appendingPathComponent("\(id.uuidString).partial")
        if let size = (try? partial.resourceValues(forKeys: [.fileSizeKey]).fileSize).map(Int64.init), size > 0 {
            request.setValue("bytes=\(size)-", forHTTPHeaderField: "Range")
        }
        let task = session.dataTask(with: request)
        task.taskDescription = id.uuidString
        taskByID[id] = task
        idByTask[task.taskIdentifier] = id
        setSink(DownloadFileSink(id: id), for: task.taskIdentifier)
        items[index].status = .downloading
        items[index].errorMessage = nil
        progressSample[id] = (items[index].downloadedBytes, Date())
        persist()
        task.resume()
    }

    func pause(_ id: UUID) {
        taskByID[id]?.cancel()
        update(id) { $0.status = .paused; $0.speedBytesPerSecond = 0 }
        taskByID[id] = nil
        idByTask = idByTask.filter { $0.value != id }
        progressSample[id] = nil
        startNextQueuedIfPossible()
    }

    func remove(_ id: UUID) {
        if let task = taskByID[id] {
            sink(for: task.taskIdentifier)?.discard()
            setSink(nil, for: task.taskIdentifier)
            task.cancel()
        }
        if let key = browserDownloadContexts.first(where: { $0.value.id == id })?.key {
            browserDownloads[key]?.cancel(nil)
            releaseBrowserDownload(key)
        }
        if let item = items.first(where: { $0.id == id }), let file = item.localFileName {
            try? FileManager.default.removeItem(at: Self.downloadFolder.appendingPathComponent(file))
        }
        items.removeAll { $0.id == id }
        taskByID[id] = nil
        idByTask = idByTask.filter { $0.value != id }
        progressSample[id] = nil
        requestByID[id] = nil
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

    private func acceptCommit(_ commit: DownloadCommit, id: UUID, mimeType: String?) {
        guard let index = items.firstIndex(where: { $0.id == id }) else {
            try? FileManager.default.removeItem(at: commit.url)
            return
        }
        // A late completion/error callback is idempotent and cannot demote a commit.
        guard items[index].status != .completed else { return }
        items[index].status = .completed
        items[index].completedAt = Date()
        items[index].localFileName = commit.fileName
        items[index].mimeType = mimeType
        items[index].downloadedBytes = commit.byteCount
        items[index].totalBytes = commit.byteCount
        items[index].speedBytesPerSecond = 0
        items[index].errorMessage = nil
        requestByID[id] = nil
        onActivity?(ActivityItem(title: "Download completed", detail: items[index].title, kind: .download))
        let content = UNMutableNotificationContent()
        content.title = "Download completed"
        content.body = items[index].title
        content.sound = .default
        UNUserNotificationCenter.current().add(
            UNNotificationRequest(identifier: id.uuidString, content: content, trigger: nil)
        )
        persist()
        finishTask(id)
    }

    private func failTask(id: UUID, error: Error) {
        guard let index = items.firstIndex(where: { $0.id == id }), items[index].status != .completed else { return }
        items[index].status = .failed
        items[index].speedBytesPerSecond = 0
        items[index].errorMessage = Self.userFacingMessage(for: error)
        requestByID[id] = nil
        persist()
        finishTask(id)
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
                          let dataTask = task as? URLSessionDataTask else { continue }
                    self.taskByID[id] = dataTask
                    self.idByTask[task.taskIdentifier] = id
                    self.setSink(DownloadFileSink(id: id), for: task.taskIdentifier)
                    self.update(id) { item in
                        item.status = task.state == .suspended ? .paused : .downloading
                    }
                }
                self.startNextQueuedIfPossible()
            }
        }
    }

    nonisolated static var downloadFolder: URL {
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

    nonisolated static var partialFolder: URL {
        let caches = FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask)[0]
        let folder = caches.appendingPathComponent("FlowGet/Partial", isDirectory: true)
        try? FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        return folder
    }

    nonisolated private func setSink(_ sink: DownloadFileSink?, for taskID: Int) {
        sinkLock.lock(); defer { sinkLock.unlock() }
        sinkByTask[taskID] = sink
    }

    nonisolated private func sink(for taskID: Int) -> DownloadFileSink? {
        sinkLock.lock(); defer { sinkLock.unlock() }
        return sinkByTask[taskID]
    }

    nonisolated static func log(_ error: Error, source: URL?, destination: URL?) {
        let value = error as NSError
        let sourcePath = source?.path ?? "nil"
        let destinationPath = destination?.path ?? "nil"
        print("FlowGet download error domain=\(value.domain) code=\(value.code) description=\(value.localizedDescription) userInfo=\(value.userInfo) source=\(sourcePath) destination=\(destinationPath)")
    }

    static func directRequest(for url: URL) -> URLRequest {
        var request = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: 60)
        request.setValue("*/*", forHTTPHeaderField: "Accept")
        request.setValue(downloadUserAgent, forHTTPHeaderField: "User-Agent")
        return request
    }

    private static let downloadUserAgent = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 FlowGet/\(AppConfig.version)"
}

extension DownloadManager: URLSessionDataDelegate {
    nonisolated func urlSession(_ session: URLSession, dataTask: URLSessionDataTask,
                               didReceive response: URLResponse,
                               completionHandler: @escaping (URLSession.ResponseDisposition) -> Void) {
        guard let sink = sink(for: dataTask.taskIdentifier) else {
            completionHandler(.cancel)
            return
        }
        if let http = response as? HTTPURLResponse, !(200..<300).contains(http.statusCode) {
            completionHandler(.cancel)
            return
        }
        do {
            let http = response as? HTTPURLResponse
            let append = http?.statusCode == 206
            let existing = try sink.open(append: append)
            let expected = response.expectedContentLength > 0 ? existing + response.expectedContentLength : nil
            let taskID = dataTask.taskIdentifier
            let rawID = dataTask.taskDescription
            let mimeType = response.mimeType
            Task { @MainActor in
                guard let id = self.idByTask[taskID] ?? rawID.flatMap(UUID.init(uuidString:)),
                      let index = self.items.firstIndex(where: { $0.id == id }),
                      self.items[index].status != .completed else { return }
                self.items[index].mimeType = mimeType
                self.items[index].downloadedBytes = existing
                self.items[index].totalBytes = expected
                self.persist()
            }
            completionHandler(.allow)
        } catch {
            Self.log(error, source: nil, destination: Self.partialFolder)
            completionHandler(.cancel)
        }
    }

    nonisolated func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive data: Data) {
        let taskID = dataTask.taskIdentifier
        let rawID = dataTask.taskDescription
        do {
            guard let completed = try sink(for: taskID)?.write(data) else { return }
            Task { @MainActor in
                guard let id = self.idByTask[taskID] ?? rawID.flatMap(UUID.init(uuidString:)),
                      let index = self.items.firstIndex(where: { $0.id == id }),
                      self.items[index].status == .downloading else { return }
                let now = Date()
                if let previous = self.progressSample[id] {
                    let elapsed = now.timeIntervalSince(previous.date)
                    if elapsed >= 0.2 {
                        self.items[index].speedBytesPerSecond = max(0, Int64(Double(completed - previous.bytes) / elapsed))
                        self.progressSample[id] = (completed, now)
                    }
                } else {
                    self.progressSample[id] = (completed, now)
                }
                self.items[index].downloadedBytes = completed
            }
        } catch {
            Self.log(error, source: nil, destination: Self.partialFolder)
            dataTask.cancel()
        }
    }

    nonisolated func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        let taskID = task.taskIdentifier
        let rawID = task.taskDescription
        let suggestedName = task.response?.suggestedFilename?.nonEmpty ?? "download"
        let mimeType = task.response?.mimeType
        guard let id = rawID.flatMap(UUID.init(uuidString:)), let sink = sink(for: taskID) else { return }
        setSink(nil, for: taskID)

        if error == nil {
            do {
                let committed = try sink.commit(id: id, suggestedName: suggestedName)
                Task { @MainActor in self.acceptCommit(committed, id: id, mimeType: mimeType) }
            } catch {
                Self.log(error, source: Self.partialFolder.appendingPathComponent("\(id.uuidString).partial"),
                         destination: Self.downloadFolder)
                Task { @MainActor in self.failTask(id: id, error: error) }
            }
            return
        }

        guard let error else { return }
        sink.closeForResume()
        Self.log(error, source: Self.partialFolder.appendingPathComponent("\(id.uuidString).partial"),
                 destination: Self.downloadFolder)
        Task { @MainActor in
            guard let id = self.idByTask[taskID] ?? rawID.flatMap(UUID.init(uuidString:)),
                  let index = self.items.firstIndex(where: { $0.id == id }), self.items[index].status != .paused else { return }
            let finalExists = self.items[index].localFileName.map {
                FileManager.default.fileExists(atPath: Self.downloadFolder.appendingPathComponent($0).path)
            } ?? false
            guard DownloadOutcomePolicy.canApplyFailure(current: self.items[index].status, finalFileExists: finalExists) else { return }
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
            self.items[index].errorMessage = Self.userFacingMessage(for: error)
            self.requestByID[id] = nil
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

extension DownloadManager: WKDownloadDelegate {
    func download(_ download: WKDownload,
                  decideDestinationUsing response: URLResponse,
                  suggestedFilename: String,
                  completionHandler: @escaping (URL?) -> Void) {
        let key = ObjectIdentifier(download)
        guard var active = browserDownloadContexts[key] else {
            completionHandler(nil)
            return
        }
        let safeName = Self.safeFileName(suggestedFilename)
        let folder = Self.downloadFolder
        do {
            try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
            let destination = folder.appendingPathComponent(
                Self.finalFileName(id: active.id, suggestedName: safeName)
            )
            try? FileManager.default.removeItem(at: destination)
            active.destination = destination
            active.suggestedName = safeName
            active.mimeType = response.mimeType
            browserDownloadContexts[key] = active
            if let index = items.firstIndex(where: { $0.id == active.id }) {
                items[index].title = safeName
                items[index].mimeType = response.mimeType
                persist()
            }
            completionHandler(destination)
        } catch {
            releaseBrowserDownload(key)
            failBrowserDownload(id: active.id, message: Self.userFacingMessage(for: error))
            completionHandler(nil)
        }
    }

    func downloadDidFinish(_ download: WKDownload) {
        let key = ObjectIdentifier(download)
        guard let active = browserDownloadContexts[key],
              let destination = active.destination else {
            releaseBrowserDownload(key)
            return
        }
        releaseBrowserDownload(key, removeDestination: false)
        completeBrowserDownload(
            id: active.id,
            temporaryURL: destination,
            suggestedName: active.suggestedName,
            mimeType: active.mimeType
        )
    }

    func download(_ download: WKDownload, didFailWithError error: Error, resumeData: Data?) {
        let key = ObjectIdentifier(download)
        let active = browserDownloadContexts[key]
        releaseBrowserDownload(key)
        failBrowserDownload(id: active?.id, message: Self.userFacingMessage(for: error))
    }

    private func releaseBrowserDownload(_ key: ObjectIdentifier, removeDestination: Bool = true) {
        browserProgressObservations.removeValue(forKey: key)?.invalidate()
        browserDownloads.removeValue(forKey: key)
        browserWebViews.removeValue(forKey: key)
        if let active = browserDownloadContexts.removeValue(forKey: key),
           removeDestination,
           let destination = active.destination {
            try? FileManager.default.removeItem(at: destination)
        }
    }
}

extension DownloadManager {
    nonisolated static func finalFileName(id: UUID, suggestedName: String) -> String {
        "\(id.uuidString.prefix(8))-\(safeFileName(suggestedName))"
    }
}

private extension DownloadManager {
    nonisolated static func safeFileName(_ value: String) -> String {
        let invalid = CharacterSet.controlCharacters.union(CharacterSet(charactersIn: "/\\:"))
        let cleaned = value.unicodeScalars.map { invalid.contains($0) ? "-" : String($0) }.joined()
            .trimmingCharacters(in: .whitespacesAndNewlines)
        return String((cleaned.nonEmpty ?? "download").prefix(180))
    }

    static func userFacingMessage(for error: Error) -> String {
        let value = error as NSError
        guard value.domain == NSURLErrorDomain else { return error.localizedDescription }
        switch value.code {
        case NSURLErrorAppTransportSecurityRequiresSecureConnection:
            return "This HTTP server was blocked by iOS transport security. Update FlowGet and try again."
        case NSURLErrorUserAuthenticationRequired:
            return "The download requires authentication. Open it in the FlowGet browser and try again."
        case NSURLErrorTimedOut:
            return "The server stopped responding. Tap Resume to try again."
        case NSURLErrorCannotFindHost, NSURLErrorCannotConnectToHost, NSURLErrorNetworkConnectionLost:
            return "FlowGet could not reach the download server. Check the connection and tap Resume."
        default:
            return error.localizedDescription
        }
    }
}

private extension String {
    var nonEmpty: String? { isEmpty ? nil : self }
}
