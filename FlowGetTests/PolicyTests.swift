import XCTest
@testable import FlowGet

final class PolicyTests: XCTestCase {
    func testDownloadStatePolicy() {
        XCTAssertTrue(DownloadStatePolicy.canTransition(from: .queued, to: .downloading))
        XCTAssertTrue(DownloadStatePolicy.canTransition(from: .downloading, to: .paused))
        XCTAssertFalse(DownloadStatePolicy.canTransition(from: .completed, to: .downloading))
    }

    func testProgressIsClamped() throws {
        let item = DownloadItem(title: "file", url: try XCTUnwrap(URL(string: "https://example.com/file")),
                                totalBytes: 100, downloadedBytes: 130)
        XCTAssertEqual(item.progress, 1)
    }

    func testNextScheduleIsInTheFuture() throws {
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = try XCTUnwrap(TimeZone(secondsFromGMT: 0))
        let now = try XCTUnwrap(calendar.date(from: DateComponents(year: 2026, month: 8, day: 26, hour: 12)))
        let schedule = DownloadSchedule(hour: 13, minute: 30, weekdays: Set(1...7))
        let next = BackgroundScheduler.nextRunDate(for: [schedule], now: now, calendar: calendar)
        XCTAssertEqual(next, calendar.date(from: DateComponents(year: 2026, month: 8, day: 26, hour: 13, minute: 30)))
    }
}
