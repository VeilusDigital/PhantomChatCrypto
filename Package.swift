// swift-tools-version: 6.2
import PackageDescription

let package = Package(
    name: "PhantomChatCrypto",
    platforms: [.iOS(.v17), .macOS(.v14)],
    products: [
        .library(name: "PhantomChatCrypto", targets: ["PhantomChatCrypto"]),
    ],
    targets: [
        .target(
            name: "PhantomChatCrypto",
            swiftSettings: [
                // Match the app's module isolation so the extracted code is
                // byte-for-byte identical (the files use `nonisolated`).
                .defaultIsolation(MainActor.self)
            ]
        ),
        .testTarget(
            name: "PhantomChatCryptoTests",
            dependencies: ["PhantomChatCrypto"]
        ),
    ]
)
