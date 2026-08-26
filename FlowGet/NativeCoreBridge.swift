import Foundation

/// Integration boundary for the authoritative shared Rust transfer engine.
/// The iOS XCFramework is intentionally not replaced by a second Swift wire protocol.
enum NativeCoreBridge {
    static let protocolVersion = 3
    static let moduleName = "FlowGetNativeCore"
    static let isLinked = false

    static let unavailableMessage =
        "Build the shared FlowGet Rust core for arm64-apple-ios and arm64-apple-ios-sim, " +
        "package it as FlowGetNativeCore.xcframework, then implement this adapter against its generated Swift bindings."
}
