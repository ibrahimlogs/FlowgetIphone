import XCTest
@testable import FlowGet

final class DownloadFileSinkTests: XCTestCase {
    private var root: URL!

    override func setUpWithError() throws {
        root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: root)
    }

    func testSuccessfulFinalFileCommit() throws {
        let id = UUID()
        let sink = DownloadFileSink(id: id, folder: root.appendingPathComponent("partial"))
        XCTAssertEqual(try sink.open(append: false), 0)
        XCTAssertEqual(try sink.write(Data(repeating: 0x5a, count: 10 * 1_024 * 1_024)), 10 * 1_024 * 1_024)

        let commit = try sink.commit(id: id, suggestedName: "test.bin", destinationFolder: root.appendingPathComponent("final"))

        XCTAssertTrue(FileManager.default.fileExists(atPath: commit.url.path))
        XCTAssertEqual(commit.byteCount, 10 * 1_024 * 1_024)
        XCTAssertEqual(try Data(contentsOf: commit.url).count, 10 * 1_024 * 1_024)
    }

    func testDuplicateCompletionCannotRemoveCommittedFile() throws {
        let id = UUID()
        let sink = DownloadFileSink(id: id, folder: root.appendingPathComponent("partial"))
        _ = try sink.open(append: false)
        _ = try sink.write(Data("payload".utf8))
        let first = try sink.commit(id: id, suggestedName: "file.txt", destinationFolder: root.appendingPathComponent("final"))

        XCTAssertThrowsError(try sink.commit(id: id, suggestedName: "file.txt", destinationFolder: root.appendingPathComponent("final")))
        sink.discard() // models a late error callback
        XCTAssertEqual(try String(contentsOf: first.url, encoding: .utf8), "payload")
    }

    func testViewOwnerDestructionDoesNotAffectTransferSink() throws {
        final class BrowserOwner {}
        weak var weakOwner: BrowserOwner?
        let id = UUID()
        let sink = DownloadFileSink(id: id, folder: root.appendingPathComponent("partial"))
        _ = try sink.open(append: false)
        autoreleasepool {
            let owner = BrowserOwner()
            weakOwner = owner
        }
        XCTAssertNil(weakOwner)

        _ = try sink.write(Data("still downloading".utf8))
        let commit = try sink.commit(id: id, suggestedName: "after-tab.txt", destinationFolder: root.appendingPathComponent("final"))
        XCTAssertTrue(FileManager.default.fileExists(atPath: commit.url.path))
    }

    func testOneBrowserAcceptanceCreatesOneSinkAndCommit() throws {
        let id = UUID()
        let sink = DownloadFileSink(id: id, folder: root.appendingPathComponent("partial"))
        _ = try sink.open(append: false)
        _ = try sink.write(Data("one click".utf8))
        let commit = try sink.commit(id: id, suggestedName: "browser.txt", destinationFolder: root.appendingPathComponent("final"))

        let files = try FileManager.default.contentsOfDirectory(at: commit.url.deletingLastPathComponent(), includingPropertiesForKeys: nil)
        XCTAssertEqual(files, [commit.url])
    }
}
