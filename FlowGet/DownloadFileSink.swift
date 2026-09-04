import Foundation

struct DownloadCommit: Sendable {
    let url: URL
    let fileName: String
    let byteCount: Int64
}

/// Owns bytes from the first response callback through the final atomic rename.
/// URLSession never owns the file, so there is no callback-scoped CFNetwork URL.
final class DownloadFileSink: @unchecked Sendable {
    private let lock = NSLock()
    private let partialURL: URL
    private var handle: FileHandle?
    private var byteCount: Int64 = 0
    private var terminal = false

    init(id: UUID, folder: URL = DownloadManager.partialFolder) {
        partialURL = folder.appendingPathComponent("\(id.uuidString).partial")
    }

    func open(append: Bool) throws -> Int64 {
        try lock.withLock {
            guard !terminal else { throw CocoaError(.fileWriteUnknown) }
            try FileManager.default.createDirectory(
                at: partialURL.deletingLastPathComponent(),
                withIntermediateDirectories: true
            )
            if !FileManager.default.fileExists(atPath: partialURL.path) {
                guard FileManager.default.createFile(atPath: partialURL.path, contents: nil) else {
                    throw CocoaError(.fileWriteUnknown)
                }
            }
            let file = try FileHandle(forWritingTo: partialURL)
            if append {
                byteCount = Int64(try file.seekToEnd())
            } else {
                try file.truncate(atOffset: 0)
                byteCount = 0
            }
            handle = file
            return byteCount
        }
    }

    func write(_ data: Data) throws -> Int64 {
        try lock.withLock {
            guard !terminal, let handle else { throw CocoaError(.fileWriteUnknown) }
            try handle.write(contentsOf: data)
            byteCount += Int64(data.count)
            return byteCount
        }
    }

    func closeForResume() {
        lock.withLock {
            try? handle?.synchronize()
            try? handle?.close()
            handle = nil
        }
    }

    func commit(id: UUID, suggestedName: String, destinationFolder: URL = DownloadManager.downloadFolder) throws -> DownloadCommit {
        try lock.withLock {
            guard !terminal else { throw CocoaError(.fileWriteUnknown) }
            try handle?.synchronize()
            try handle?.close()
            handle = nil
            try FileManager.default.createDirectory(at: destinationFolder, withIntermediateDirectories: true)
            let fileName = DownloadManager.finalFileName(id: id, suggestedName: suggestedName)
            let destination = destinationFolder.appendingPathComponent(fileName)
            try? FileManager.default.removeItem(at: destination)
            try FileManager.default.moveItem(at: partialURL, to: destination)
            try? FileManager.default.setAttributes(
                [.protectionKey: FileProtectionType.completeUntilFirstUserAuthentication],
                ofItemAtPath: destination.path
            )
            terminal = true
            let size = try destination.resourceValues(forKeys: [.fileSizeKey]).fileSize ?? 0
            return DownloadCommit(url: destination, fileName: fileName, byteCount: Int64(size))
        }
    }

    func discard() {
        lock.withLock {
            guard !terminal else { return }
            try? handle?.close()
            handle = nil
            try? FileManager.default.removeItem(at: partialURL)
            terminal = true
        }
    }
}

private extension NSLock {
    func withLock<T>(_ body: () throws -> T) rethrows -> T {
        lock()
        defer { unlock() }
        return try body()
    }
}
