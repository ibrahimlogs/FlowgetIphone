import XCTest
@testable import FlowGet

final class DownloadManagerIntegrationTests: XCTestCase {
    @MainActor
    func testDirectTenMegabyteDownloadCommitsAndPublishesProgress() async throws {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [TenMegabyteURLProtocol.self]
        let manager = DownloadManager(configuration: configuration, initialItems: [])
        let url = try XCTUnwrap(URL(string: "https://flowget.test/10MB.bin"))
        let id = try XCTUnwrap(manager.add(url: url))
        var observedIntermediateProgress = false

        for _ in 0..<500 {
            try await Task.sleep(for: .milliseconds(10))
            let item = try XCTUnwrap(manager.items.first(where: { $0.id == id }))
            if item.downloadedBytes > 0 && item.status == .downloading {
                observedIntermediateProgress = true
            }
            if item.status.isTerminal { break }
        }

        let item = try XCTUnwrap(manager.items.first(where: { $0.id == id }))
        XCTAssertEqual(item.status, .completed, item.errorMessage ?? "")
        XCTAssertEqual(item.downloadedBytes, 10 * 1_024 * 1_024)
        XCTAssertTrue(observedIntermediateProgress)
        let finalURL = try XCTUnwrap(manager.localURL(for: item))
        XCTAssertTrue(FileManager.default.fileExists(atPath: finalURL.path))
        XCTAssertEqual(try finalURL.resourceValues(forKeys: [.fileSizeKey]).fileSize, 10 * 1_024 * 1_024)
        manager.remove(id)
    }
}

private final class TenMegabyteURLProtocol: URLProtocol, @unchecked Sendable {
    override class func canInit(with request: URLRequest) -> Bool { request.url?.host == "flowget.test" }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        let response = HTTPURLResponse(
            url: request.url!,
            statusCode: 200,
            httpVersion: "HTTP/1.1",
            headerFields: [
                "Content-Length": "10485760",
                "Content-Disposition": "attachment; filename=10MB.bin",
                "Content-Type": "application/octet-stream"
            ]
        )!
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        let chunk = Data(repeating: 0x3c, count: 64 * 1_024)
        for _ in 0..<160 {
            client?.urlProtocol(self, didLoad: chunk)
            Thread.sleep(forTimeInterval: 0.002)
        }
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {}
}
