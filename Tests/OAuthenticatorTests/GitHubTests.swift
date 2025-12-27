import Foundation
import Testing

@testable import OAuthenticator

struct GitHubTests {
	@Test
	func testAppResponseDecode() throws {
		let content = """
{"access_token": "abc", "expires_in": 5, "refresh_token": "def", "refresh_token_expires_in": 5, "scope": "", "token_type": "bearer"}
"""
		let data = try #require(content.data(using: .utf8))
		let response = try JSONDecoder().decode(GitHub.AppAuthResponse.self, from: data)

		#expect(response.accessToken == "abc")

		let login = response.login
		#expect(login.accessToken.value == "abc")
	}
}
