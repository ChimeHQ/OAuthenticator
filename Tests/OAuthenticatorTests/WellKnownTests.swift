import XCTest

@testable import OAuthenticator

final class WellKnownTests: XCTestCase {
	func testServerMetadataLoad() async throws {
		let loadUrlExp = expectation(description: "load url")

		let mockLoader: URLResponseProvider = { request in
			XCTAssertEqual(request.value(forHTTPHeaderField: "Accept"), "application/json")
			loadUrlExp.fulfill()

			let content = """
				{"issuer": "https://server-metadata.test", "authorization_endpoint": "https://server-metadata.test/oauth/authorize", "token_endpoint": "https://server-metadata.test/oauth/token"}
				"""

			let data = try XCTUnwrap(content.data(using: .utf8))

			return (
				data,
				URLResponse(
					url: request.url!,
					mimeType: nil, expectedContentLength: data.count, textEncodingName: "utf-8")
			)
		}

		let url = URL(string: "https://server-metadata.test/")!
		let response = try await ServerMetadata.load(
			for: url.host!,
			provider: mockLoader
		)

		await fulfillment(of: [loadUrlExp], timeout: 1.0, enforceOrder: true)

		XCTAssertEqual(response.issuer, "https://server-metadata.test")
		XCTAssertEqual(response.authorizationEndpoint, "https://server-metadata.test/oauth/authorize")
		XCTAssertEqual(response.tokenEndpoint, "https://server-metadata.test/oauth/token")
	}

	func testClientMetadataLoad() async throws {
		let loadUrlExp = expectation(description: "load url")

		let mockLoader: URLResponseProvider = { request in
			XCTAssertEqual(request.value(forHTTPHeaderField: "Accept"), "application/json")
			loadUrlExp.fulfill()

			let content = """
				{"client_id": "https://client-metadata.test/oauth-client-metadata.json", "scope": "atproto", "redirect_uris": ["https://client-metadata.test/oauth/callback"]}
				"""

			let data = try XCTUnwrap(content.data(using: .utf8))

			return (
				data,
				URLResponse(
					url: request.url!,
					mimeType: nil, expectedContentLength: data.count, textEncodingName: "utf-8")
			)
		}

		let url = URL(string: "https://client-metadata.test/oauth-client-metadata.json")!
		let response = try await ClientMetadata.load(
			for: url.absoluteString,
			provider: mockLoader
		)

		await fulfillment(of: [loadUrlExp], timeout: 1.0, enforceOrder: true)

		XCTAssertEqual(response.clientId, "https://client-metadata.test/oauth-client-metadata.json")
		XCTAssertEqual(response.scope, "atproto")
		XCTAssertEqual(response.redirectURIs.isEmpty, false)
		XCTAssertEqual(response.redirectURIs.first, "https://client-metadata.test/oauth/callback")
	}

	func testProtectedResourceMetadataLoad() async throws {
		let loadUrlExp = expectation(description: "load url")

		let mockLoader: URLResponseProvider = { request in
			XCTAssertEqual(request.value(forHTTPHeaderField: "Accept"), "application/json")
			loadUrlExp.fulfill()

			let content = """
				{"resource": "https://protected-resource-metadata.test"}
				"""

			let data = try XCTUnwrap(content.data(using: .utf8))

			return (
				data,
				URLResponse(
					url: request.url!,
					mimeType: nil, expectedContentLength: data.count, textEncodingName: "utf-8")
			)
		}

		let url = URL(string: "https://protected-resource-metadata.test/")!
		let response = try await ProtectedResourceMetadata.load(
			for: url.host!,
			provider: mockLoader
		)

		await fulfillment(of: [loadUrlExp], timeout: 1.0, enforceOrder: true)

		XCTAssertEqual(response.resource, "https://protected-resource-metadata.test")
	}

	func testProtectedResourceMetadataDecode() throws {
		// Response from: https://puffball.us-east.host.bsky.network/.well-known/oauth-protected-resource/
		let content = """
			{"resource":"https://puffball.us-east.host.bsky.network","authorization_servers":["https://bsky.social"],"scopes_supported":[],"bearer_methods_supported":["header"],"resource_documentation":"https://atproto.com"}
			"""
		let data = try XCTUnwrap(content.data(using: .utf8))
		let response = try XCTUnwrap(ProtectedResourceMetadata.loadJson(data: data))

		XCTAssertEqual(response.resource, "https://puffball.us-east.host.bsky.network")
		let authorizationServers = try XCTUnwrap(response.authorizationServers)
		XCTAssertEqual(authorizationServers.isEmpty, false)
		XCTAssertEqual(authorizationServers.first, "https://bsky.social")

		let scopesSupported = try XCTUnwrap(response.scopesSupported)
		XCTAssertEqual(scopesSupported.isEmpty, true)

		let bearerMethodsSupported = try XCTUnwrap(response.bearerMethodsSupported)
		XCTAssertEqual(bearerMethodsSupported.isEmpty, false)
		XCTAssertEqual(bearerMethodsSupported.first, "header")

		XCTAssertEqual(response.resourceDocumentation, "https://atproto.com")

		// Missing fields
		XCTAssertNil(response.authorizationDetailsTypesSupported)
		XCTAssertNil(response.jwksUri)
		XCTAssertNil(response.dpopBoundAccessTokensRequired)
		XCTAssertNil(response.dpopSigningAlgValuesSupported)
		XCTAssertNil(response.resourceName)
		XCTAssertNil(response.resourcePolicyUri)
		XCTAssertNil(response.resourceTosUri)
		XCTAssertNil(response.signedMetadata)
		XCTAssertNil(response.tlsClientCertificateBoundAccessTokens)
	}
}
