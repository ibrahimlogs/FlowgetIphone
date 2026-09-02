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
}
