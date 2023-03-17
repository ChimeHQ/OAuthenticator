import XCTest
@testable import OAuthenticator

final class GitHubTests: XCTestCase {
	func testAppResponseDecode() throws {
		let content = """
{"access_token": "abc", "expires_in": 5, "refresh_token": "def", "refresh_token_expires_in": 5, "scope": "", "token_type": "bearer"}
"""
		let data = try XCTUnwrap(content.data(using: .utf8))
		let response = try JSONDecoder().decode(GitHub.AppAuthResponse.self, from: data)

		XCTAssertEqual(response.accessToken, "abc")

		let login = response.login
		XCTAssertEqual(login.accessToken.value, "abc")
	}
}
