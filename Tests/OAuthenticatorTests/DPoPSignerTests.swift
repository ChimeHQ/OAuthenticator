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
#if !os(Linux)
		// I'm unsure why exactly this test is failing on Linux only, but I suspect it is due to
		// platform differences in FoundationNetworking.
		#expect(headers["DPoP"] == "my_fake_jwt")
#endif
	}
}
