import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
import Testing

import OAuthenticator

struct ExamplePayload: Codable, Hashable, Sendable {
	let value: String
}

struct DPoPSignerTests {
	@MainActor
	@Test func basicSignature() async throws {
		let signer = DPoPSigner()

		var request = URLRequest(url: URL(string: "https://example.com")!)

		try await signer.authenticateRequest(
			&request,
			isolation: MainActor.shared,
			using: { _ in "my_fake_jwt" },
			token: "token",
			tokenHash: "token_hash",
			issuer: "issuer"
		)

		let headers = try #require(request.allHTTPHeaderFields)

		#expect(headers["Authorization"] == "DPoP token")
		#expect(headers["DPoP"] == "my_fake_jwt")
	}
}
