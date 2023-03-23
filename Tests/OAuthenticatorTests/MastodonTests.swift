import XCTest
@testable import OAuthenticator

final class MastodonTests: XCTestCase {
	func testAppResponseDecode() throws {
		// From https://docs.joinmastodon.org/entities/Token/
		let content = """
{"access_token": "ZA-Yj3aBD8U8Cm7lKUp-lm9O9BmDgdhHzDeqsY8tlL0", "token_type": "bearer", "scope": "read write follow push", "created_at": 1573979017}
"""
		let data = try XCTUnwrap(content.data(using: .utf8))
		let response = try JSONDecoder().decode(Mastodon.AppAuthResponse.self, from: data)

		XCTAssertEqual(response.accessToken, "ZA-Yj3aBD8U8Cm7lKUp-lm9O9BmDgdhHzDeqsY8tlL0")

		let login = response.login
		XCTAssertEqual(login.accessToken.value, "ZA-Yj3aBD8U8Cm7lKUp-lm9O9BmDgdhHzDeqsY8tlL0")
	}
}
