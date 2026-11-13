// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "PPTPClient",
    platforms: [.macOS(.v13)],
    products: [
        .library(name: "PPTPCore", targets: ["PPTPCore"]),
        .executable(name: "pptp-client", targets: ["PPTPClient"]),
    ],
    targets: [
        .target(name: "PPTPCore"),
        .target(name: "CMacSupport"),
        .executableTarget(name: "PPTPClient", dependencies: ["PPTPCore", "CMacSupport"]),
        .testTarget(name: "PPTPCoreTests", dependencies: ["PPTPCore"]),
    ]
)
