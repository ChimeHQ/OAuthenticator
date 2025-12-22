import OAuthenticator
import Testing

struct PKCETest {
	@Test func customHashFunction() throws {
		let pkce = PKCEVerifier(hash: "abc") { input in
			"abc" + input
		}

		let challenge = pkce.challenge

		#expect(challenge.method == "abc")
		#expect(challenge.value == "abc" + pkce.verifier)
	}

	#if canImport(CryptoKit)
		@Test func defaultHashFunction() throws {
			let pkce = PKCEVerifier()

			let challenge = pkce.challenge

			#expect(challenge.method == "S256")
		}
	#endif
}
