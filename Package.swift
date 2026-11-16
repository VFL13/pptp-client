// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "PPTPClient",
    platforms: [.macOS("26.0")],
    products: [
        .library(name: "PPTPCore", targets: ["PPTPCore"]),
        .library(name: "PPTPRuntime", targets: ["PPTPRuntime"]),
        .executable(name: "pptp-client", targets: ["PPTPClient"]),
        .executable(name: "PPTPClientApp", targets: ["PPTPClientApp"]),
        .executable(name: "pptp-helper", targets: ["PPTPHelper"]),
    ],
    targets: [
        .target(name: "PPTPCore"),
        .target(name: "CMacSupport"),
        .target(name: "PPTPRuntime", dependencies: ["PPTPCore", "CMacSupport"]),
        .target(name: "PPTPAppSupport", dependencies: ["PPTPCore", "PPTPRuntime"]),
        .executableTarget(name: "PPTPClient", dependencies: ["PPTPCore", "PPTPRuntime", "CMacSupport"]),
        .executableTarget(name: "PPTPHelper", dependencies: ["PPTPRuntime", "PPTPAppSupport"]),
        .executableTarget(name: "PPTPClientApp", dependencies: ["PPTPAppSupport"]),
        .testTarget(name: "PPTPCoreTests", dependencies: ["PPTPCore"]),
        .testTarget(name: "PPTPAppTests", dependencies: ["PPTPAppSupport"]),
    ]
)
