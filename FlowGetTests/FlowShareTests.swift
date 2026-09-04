import XCTest
@testable import FlowGet

final class FlowShareTests: XCTestCase {
    func testFriendCodeNormalizationMatchesAndroidContract() {
        XCTAssertEqual(FlowShareWirePolicy.normalizeFriendCode("ab12-cd34 ef56"), "AB12CD34EF56")
    }

    func testUnsafeFileNamesAreRejected() {
        XCTAssertTrue(FlowShareWirePolicy.validFileName("movie.mp4"))
        XCTAssertFalse(FlowShareWirePolicy.validFileName("../movie.mp4"))
        XCTAssertFalse(FlowShareWirePolicy.validFileName("folder\\movie.mp4"))
        XCTAssertFalse(FlowShareWirePolicy.validFileName("bad\nname"))
    }

    func testHashAndSignalingEndpointAreStrict() {
        XCTAssertTrue(FlowShareWirePolicy.validSHA256(String(repeating: "a", count: 64)))
        XCTAssertFalse(FlowShareWirePolicy.validSHA256(String(repeating: "z", count: 64)))
        XCTAssertTrue(FlowShareWirePolicy.validSignalingEndpoint("wss://share.flowget.xyz/ws?shareId=1"))
        XCTAssertFalse(FlowShareWirePolicy.validSignalingEndpoint("https://share.flowget.xyz/ws"))
        XCTAssertFalse(FlowShareWirePolicy.validSignalingEndpoint("wss://example.com/ws"))
    }

    func testPendingIncomingCommandIsNeverAcknowledgedAsDuplicate() {
        XCTAssertNil(FlowShareWirePolicy.acknowledgementForExistingTransfer(
            state: "Awaiting acceptance",
            isPending: true
        ))
        XCTAssertEqual(FlowShareWirePolicy.acknowledgementForExistingTransfer(
            state: "Completed",
            isPending: false
        ), "completed")
        XCTAssertEqual(FlowShareWirePolicy.acknowledgementForExistingTransfer(
            state: "Transferring",
            isPending: false
        ), "accepted")
    }
}
