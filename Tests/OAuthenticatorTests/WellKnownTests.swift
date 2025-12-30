import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
import Testing

@testable import OAuthenticator

struct WellKnownTests {
	@Test
	func serverMetadataLoad() async throws {
		let mockLoader: URLResponseProvider = { request in
			#expect(request.value(forHTTPHeaderField: "Accept") == "application/json")

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

			let data = try #require(content.data(using: .utf8))

			return (
				data,
				HTTPURLResponse(
					url: request.url!,
					statusCode: 200,
					httpVersion: nil,
					headerFields: ["Content-Type": "application/json"]
				)!
			)
		}

		let url = URL(string: "https://server-metadata.test/")!
		let response = try await ServerMetadata.load(
			for: url.host!,
			provider: mockLoader
		)

		#expect(response.issuer == "https://server-metadata.test")
		#expect(response.authorizationEndpoint == "https://server-metadata.test/oauth/authorize")
		#expect(response.tokenEndpoint == "https://server-metadata.test/oauth/token")
	}

	@Test
	func clientMetadataLoad() async throws {
		let mockLoader: URLResponseProvider = { request in
			#expect(request.value(forHTTPHeaderField: "Accept") == "application/json")

			let content = """
				{"client_id": "https://client-metadata.test/oauth-client-metadata.json", "scope": "atproto", "redirect_uris": ["https://client-metadata.test/oauth/callback"], "dpop_bound_access_tokens": true}
				"""

			let data = try #require(content.data(using: .utf8))

			return (
				data,
				HTTPURLResponse(
					url: request.url!,
					statusCode: 200,
					httpVersion: nil,
					headerFields: ["Content-Type": "application/json"]
				)!
			)
		}

		let url = URL(string: "https://client-metadata.test/oauth-client-metadata.json")!
		let response = try await ClientMetadata.load(
			for: url.absoluteString,
			provider: mockLoader
		)

		#expect(response.clientId == "https://client-metadata.test/oauth-client-metadata.json")
		#expect(response.scope == "atproto")
		#expect(response.redirectURIs.isEmpty == false)
		#expect(response.redirectURIs.first == "https://client-metadata.test/oauth/callback")
	}

	@Test
	func protectedResourceMetadataLoad() async throws {
		let mockLoader: URLResponseProvider = { request in
			#expect(request.value(forHTTPHeaderField: "Accept") == "application/json")

			let content = """
				{"resource": "https://protected-resource-metadata.test"}
				"""

			let data = try #require(content.data(using: .utf8))

			return (
				data,
				HTTPURLResponse(
					url: request.url!,
					statusCode: 200,
					httpVersion: nil,
					headerFields: ["Content-Type": "application/json"]
				)!
			)
		}

		let url = URL(string: "https://protected-resource-metadata.test/")!
		let response = try await ProtectedResourceMetadata.load(
			for: url.host!,
			provider: mockLoader
		)

		#expect(response.resource == "https://protected-resource-metadata.test")
	}

	@Test
	func protectedResourceMetadataDecode() throws {
		// Response from: https://puffball.us-east.host.bsky.network/.well-known/oauth-protected-resource/
		let content = """
			{"resource":"https://puffball.us-east.host.bsky.network","authorization_servers":["https://bsky.social"],"scopes_supported":[],"bearer_methods_supported":["header"],"resource_documentation":"https://atproto.com"}
			"""
		let data = try #require(content.data(using: .utf8))
		let response = try ProtectedResourceMetadata.loadJson(data: data)

		#expect(response.resource == "https://puffball.us-east.host.bsky.network")
		let authorizationServers = try #require(response.authorizationServers)
		#expect(authorizationServers.isEmpty == false)
		#expect(authorizationServers.first == "https://bsky.social")

		let scopesSupported = try #require(response.scopesSupported)
		#expect(scopesSupported.isEmpty)

		let bearerMethodsSupported = try #require(response.bearerMethodsSupported)
		#expect(bearerMethodsSupported.isEmpty == false)
		#expect(bearerMethodsSupported.first == "header")

		#expect(response.resourceDocumentation == "https://atproto.com")

		// Missing fields
		#expect(response.authorizationDetailsTypesSupported == nil)
		#expect(response.jwksUri == nil)
		#expect(response.dpopBoundAccessTokensRequired == nil)
		#expect(response.dpopSigningAlgValuesSupported == nil)
		#expect(response.resourceName == nil)
		#expect(response.resourcePolicyUri == nil)
		#expect(response.resourceTosUri == nil)
		#expect(response.signedMetadata == nil)
		#expect(response.tlsClientCertificateBoundAccessTokens == nil)
	}
}
