// swift-tools-version: 5.8

import PackageDescription

let settings: [SwiftSetting] = [
	.enableExperimentalFeature("StrictConcurrency")
]

let package = Package(
	name: "OAuthenticator",
	platforms: [.macOS(.v10_15), .iOS(.v13), .tvOS(.v13), .watchOS("6.2")],
	products: [
		.library(name: "OAuthenticator", targets: ["OAuthenticator"]),
        .library(name: "OAuthenticatorOpenAPI", targets: ["OAuthenticatorOpenAPI"]),
	],
	dependencies: [
        .package(url: "https://github.com/apple/swift-openapi-runtime.git", from: "1.0.0"),
	],
	targets: [
		.target(name: "OAuthenticator", dependencies: [], swiftSettings: settings),
		.testTarget(name: "OAuthenticatorTests", dependencies: ["OAuthenticator"], swiftSettings: settings),
        .target(
            name: "OAuthenticatorOpenAPI",
            dependencies: [
                .product(name: "OpenAPIRuntime", package: "swift-openapi-runtime"),
                .target(name: "OAuthenticator")
            ],
            swiftSettings: settings
        )
	]
)
