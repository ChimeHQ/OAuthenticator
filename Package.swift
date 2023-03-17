// swift-tools-version: 5.5

import PackageDescription

let package = Package(
	name: "OAuthenticator",
	platforms: [.macOS(.v10_15), .iOS(.v13), .tvOS(.v13), .watchOS("6.2")],
	products: [
		.library(name: "OAuthenticator", targets: ["OAuthenticator"]),
	],
	dependencies: [
	],
	targets: [
		.target(name: "OAuthenticator", dependencies: []),
		.testTarget(name: "OAuthenticatorTests", dependencies: ["OAuthenticator"]),
	]
)
