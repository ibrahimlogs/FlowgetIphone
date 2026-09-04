import XCTest
@testable import FlowGet

final class BrowserDownloadTests: XCTestCase {
    func testAttachmentResponseIsDownloaded() throws {
        let url = try XCTUnwrap(URL(string: "https://example.com/export"))
        XCTAssertTrue(BrowserDownloadSupport.shouldDownload(
            url: url,
            mimeType: "application/octet-stream",
            contentDisposition: "attachment; filename=report.bin",
            canShowMIMEType: true
        ))
    }

    func testNormalHTMLNavigationIsNotDownloaded() throws {
        let url = try XCTUnwrap(URL(string: "https://example.com/article"))
        XCTAssertFalse(BrowserDownloadSupport.shouldDownload(
            url: url,
            mimeType: "text/html",
            contentDisposition: nil,
            canShowMIMEType: true
        ))
    }

    func testDirectFileExtensionIsDownloaded() throws {
        let url = try XCTUnwrap(URL(string: "https://example.com/files/archive.zip?token=short-lived"))
        XCTAssertTrue(BrowserDownloadSupport.shouldDownload(
            url: url,
            mimeType: "application/zip",
            contentDisposition: nil,
            canShowMIMEType: true
        ))
    }

    @MainActor
    func testManualDownloadRequestUsesBroadAcceptAndBrowserCompatibleUserAgent() throws {
        let url = try XCTUnwrap(URL(string: "https://example.com/archive.zip"))
        let request = DownloadManager.directRequest(for: url)
        XCTAssertEqual(request.value(forHTTPHeaderField: "Accept"), "*/*")
        XCTAssertTrue(request.value(forHTTPHeaderField: "User-Agent")?.contains("FlowGet/") == true)
        XCTAssertEqual(request.cachePolicy, .reloadIgnoringLocalCacheData)
    }

    func testURLSessionTemporaryFileIsSecuredBeforeDelegateReturns() throws {
        let source = FileManager.default.temporaryDirectory
            .appendingPathComponent("flowget-test-\(UUID().uuidString)")
        let payload = Data("FlowGet".utf8)
        try payload.write(to: source)

        let staged = try DownloadManager.stageTemporaryDownload(source)
        defer { try? FileManager.default.removeItem(at: staged) }

        XCTAssertFalse(FileManager.default.fileExists(atPath: source.path))
        XCTAssertEqual(try Data(contentsOf: staged), payload)
    }

    func testURLSessionTemporaryFileCanBeCommittedDirectlyToFinalFolder() throws {
        let source = FileManager.default.temporaryDirectory
            .appendingPathComponent("flowget-source-\(UUID().uuidString)")
        let destinationFolder = FileManager.default.temporaryDirectory
            .appendingPathComponent("flowget-final-\(UUID().uuidString)", isDirectory: true)
        let payload = Data(repeating: 0x5A, count: 4096)
        try payload.write(to: source)
        defer {
            try? FileManager.default.removeItem(at: source)
            try? FileManager.default.removeItem(at: destinationFolder)
        }

        let secured = try DownloadManager.secureTemporaryDownload(
            source,
            id: UUID(uuidString: "11111111-2222-3333-4444-555555555555")!,
            suggestedName: "10Mb.dat",
            destinationFolder: destinationFolder
        )

        XCTAssertFalse(FileManager.default.fileExists(atPath: source.path))
        XCTAssertEqual(secured.fileName, "11111111-10Mb.dat")
        XCTAssertEqual(secured.byteCount, Int64(payload.count))
        XCTAssertEqual(try Data(contentsOf: secured.url), payload)

        let duplicateCallback = try DownloadManager.secureTemporaryDownload(
            source,
            id: UUID(uuidString: "11111111-2222-3333-4444-555555555555")!,
            suggestedName: "10Mb.dat",
            destinationFolder: destinationFolder
        )
        XCTAssertEqual(duplicateCallback.url, secured.url)
        XCTAssertEqual(duplicateCallback.byteCount, secured.byteCount)
    }
}
