import XCTest

@testable import OAuthenticator

final class WellKnownTests: XCTestCase {
	func testServerMetadataLoad() async throws {
		let loadUrlExp = expectation(description: "load url")

		let mockLoader: URLResponseProvider = { request in
			XCTAssertEqual(request.value(forHTTPHeaderField: "Accept"), "application/json")
			loadUrlExp.fulfill()

			// This is a more minimal Authorization Server Metadata that should be valid,
			// but throws an error due to: https://github.com/ChimeHQ/OAuthenticator/issues/37
			//
			// let content = """
			// 	{"issuer": "https://server-metadata.test", "authorization_endpoint": "https://server-metadata.test/oauth/authorize", "token_endpoint": "https://server-metadata.test/oauth/token"}
			// 	"""

			// Response from https://bsky.social/.well-known/oauth-authorization-server
			let content = """
				{"issuer":"https://server-metadata.test","request_parameter_supported":true,"request_uri_parameter_supported":true,"require_request_uri_registration":true,"scopes_supported":["atproto","transition:email","transition:generic","transition:chat.bsky"],"subject_types_supported":["public"],"response_types_supported":["code"],"response_modes_supported":["query","fragment","form_post"],"grant_types_supported":["authorization_code","refresh_token"],"code_challenge_methods_supported":["S256"],"ui_locales_supported":["en-US"],"display_values_supported":["page","popup","touch"],"request_object_signing_alg_values_supported":["RS256","RS384","RS512","PS256","PS384","PS512","ES256","ES256K","ES384","ES512","none"],"authorization_response_iss_parameter_supported":true,"request_object_encryption_alg_values_supported":[],"request_object_encryption_enc_values_supported":[],"jwks_uri":"https://server-metadata.test/oauth/jwks","authorization_endpoint":"https://server-metadata.test/oauth/authorize","token_endpoint":"https://server-metadata.test/oauth/token","token_endpoint_auth_methods_supported":["none","private_key_jwt"],"token_endpoint_auth_signing_alg_values_supported":["RS256","RS384","RS512","PS256","PS384","PS512","ES256","ES256K","ES384","ES512"],"revocation_endpoint":"https://server-metadata.test/oauth/revoke","pushed_authorization_request_endpoint":"https://server-metadata.test/oauth/par","require_pushed_authorization_requests":true,"dpop_signing_alg_values_supported":["RS256","RS384","RS512","PS256","PS384","PS512","ES256","ES256K","ES384","ES512"],"client_id_metadata_document_supported":true}
				"""

			let data = try XCTUnwrap(content.data(using: .utf8))

			return (
				data,
				URLResponse(
					url: request.url!,
					mimeType: "application/json",
					expectedContentLength: data.count,
					textEncodingName: "utf-8"
				)
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
				{"client_id": "https://client-metadata.test/oauth-client-metadata.json", "scope": "atproto", "redirect_uris": ["https://client-metadata.test/oauth/callback"], "dpop_bound_access_tokens": true}
				"""

			let data = try XCTUnwrap(content.data(using: .utf8))

			return (
				data,
				URLResponse(
					url: request.url!,
					mimeType: "application/json",
					expectedContentLength: data.count,
					textEncodingName: "utf-8"
				)
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
					mimeType: "application/json",
					expectedContentLength: data.count,
					textEncodingName: "utf-8"
				)
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
