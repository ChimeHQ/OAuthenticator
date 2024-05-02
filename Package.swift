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
	],
	dependencies: [
	],
	targets: [
		.target(name: "OAuthenticator",
				dependencies: [],
				resources: [.process("PrivacyInfo.xcprivacy")],
				swiftSettings: settings),
		.testTarget(name: "OAuthenticatorTests", dependencies: ["OAuthenticator"], swiftSettings: settings),
	]
)
