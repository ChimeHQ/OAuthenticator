//
//  GoogleTests.swift
//
import XCTest
import OSLog
@testable import OAuthenticator

final class GoogleTests: XCTestCase {
    private func compatFulfillment(of expectations: [XCTestExpectation], timeout: TimeInterval, enforceOrder: Bool) async {
#if compiler(>=5.8)
        await fulfillment(of: expectations, timeout: timeout, enforceOrder: enforceOrder)
#else
        await Task {
            wait(for: expectations, timeout: timeout, enforceOrder: enforceOrder)
        }.value
#endif
    }
    
    func testOAuthResponseDecode() throws {
        let content = """
{"access_token": "abc", "expires_in": 3, "refresh_token": "def", "scope": "https://gmail.scope", "token_type": "bearer"}
"""
        let data = try XCTUnwrap(content.data(using: .utf8))
        let response = try JSONDecoder().decode(GoogleAPI.OAuthResponse.self, from: data)
        
        XCTAssertEqual(response.accessToken, "abc")
        
        let login = response.login
        XCTAssertEqual(login.accessToken.value, "abc")
        
        // Sleep until access token expires
        sleep(5)
        XCTAssert(!login.accessToken.valid)
    }
}
