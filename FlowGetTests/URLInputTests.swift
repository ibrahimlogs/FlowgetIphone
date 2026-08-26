import XCTest
@testable import FlowGet

final class URLInputTests: XCTestCase {
    func testDownloadURLAddsHTTPS() {
        XCTAssertEqual(URLInput.downloadURL(from: "example.com/file.zip")?.absoluteString,
                       "https://example.com/file.zip")
    }

    func testDownloadURLRejectsUnsafeSchemesAndMissingHost() {
        XCTAssertNil(URLInput.downloadURL(from: "javascript:alert(1)"))
        XCTAssertNil(URLInput.downloadURL(from: "file:///private/data"))
        XCTAssertNil(URLInput.downloadURL(from: "https://"))
    }

    func testBrowserInputBuildsEncodedSearch() throws {
        let url = try XCTUnwrap(URLInput.browserURL(from: "swift background download"))
        XCTAssertEqual(url.host, "www.google.com")
        XCTAssertEqual(URLComponents(url: url, resolvingAgainstBaseURL: false)?.queryItems?.first?.value,
                       "swift background download")
    }
}
