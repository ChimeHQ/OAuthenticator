import Foundation
import Testing

import OAuthenticator

struct ExamplePayload: Codable, Hashable, Sendable {
	let value: String
}

struct DPoPSignerTests {
    @Test
	func basicSignature() throws {
		let signer = DPoPSigner()

		var request = URLRequest(url: URL(string: "https://example.com")!)

		try signer.authenticateRequest(
			&request,
			using: { _ in "my_fake_jwt" },
			token: "token",
			tokenHash: "token_hash",
			issuer: "issuer"
		)

		let headers = try #require(request.allHTTPHeaderFields)
		let authorization = try #require(headers["Authorization"])

		#expect(authorization == "DPoP token")

		let dpop = try #require(headers["DPoP"])

		#expect(dpop == "my_fake_jwt")
    }
}
