import Foundation
import Testing

import OAuthenticator

struct BlueskyTests {
	@Test
	func tokenHandling() async throws {
		let metadataContent = """
			{"issuer":"https://server-metadata.test","request_parameter_supported":true,"request_uri_parameter_supported":true,"require_request_uri_registration":true,"scopes_supported":["atproto","transition:email","transition:generic","transition:chat.bsky"],"subject_types_supported":["public"],"response_types_supported":["code"],"response_modes_supported":["query","fragment","form_post"],"grant_types_supported":["authorization_code","refresh_token"],"code_challenge_methods_supported":["S256"],"ui_locales_supported":["en-US"],"display_values_supported":["page","popup","touch"],"request_object_signing_alg_values_supported":["RS256","RS384","RS512","PS256","PS384","PS512","ES256","ES256K","ES384","ES512","none"],"authorization_response_iss_parameter_supported":true,"request_object_encryption_alg_values_supported":[],"request_object_encryption_enc_values_supported":[],"jwks_uri":"https://server-metadata.test/oauth/jwks","authorization_endpoint":"https://server-metadata.test/oauth/authorize","token_endpoint":"https://server-metadata.test/oauth/token","token_endpoint_auth_methods_supported":["none","private_key_jwt"],"token_endpoint_auth_signing_alg_values_supported":["RS256","RS384","RS512","PS256","PS384","PS512","ES256","ES256K","ES384","ES512"],"revocation_endpoint":"https://server-metadata.test/oauth/revoke","pushed_authorization_request_endpoint":"https://server-metadata.test/oauth/par","require_pushed_authorization_requests":true,"dpop_signing_alg_values_supported":["RS256","RS384","RS512","PS256","PS384","PS512","ES256","ES256K","ES384","ES512"],"client_id_metadata_document_supported":true}
			"""

		let data = try #require(metadataContent.data(using: .utf8))

		let metadata = try JSONDecoder().decode(ServerMetadata.self, from: data)
		let handling = Bluesky.tokenHandling(
			account: "placeholder",
			server: metadata,
			jwtGenerator: { _ in "" }
		)

		let provider: URLResponseProvider = { request in
			let response = HTTPURLResponse(
				url: request.url!,
				statusCode: 200,
				httpVersion: "1.1",
				headerFields: [
					"Content-Type": "application/json"
				]
			)!

			let payload = """
{"access_token":"1", "sub":"2", "scope":"3", "token_type":"DPoP","expires_in":120}
"""

			return (Data(payload.utf8), response)
		}

		let verifier = PKCEVerifier()
		let params = TokenHandling.LoginProviderParameters(
			authorizationURL: URL(string: "https://server-metadata.test/oauth/authorize")!,
			credentials: AppCredentials(
				clientId: "a",
				clientPassword: "b",
				scopes: [],
				callbackURL: URL(string: "app.test://callback")!,
			),
			redirectURL: URL(string: "app.test://callback?code=123&state=state&iss=this_is_incorrect")!,
			responseProvider: provider,
			stateToken: "state",
			pcke: verifier
		)

		await #expect(throws: AuthenticatorError.issuingServerMismatch("this_is_incorrect", "https://server-metadata.test")) {
			try await handling.loginProvider(params)
		}
	}
}
