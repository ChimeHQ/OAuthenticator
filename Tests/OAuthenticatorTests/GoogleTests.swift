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
    
    func testSuppliedParameters() throws {
        let googleParameters = GoogleAPI.GoogleAPIParameters(includeGrantedScopes: true, loginHint: "john@doe.com")
        
        XCTAssertNotNil(googleParameters.loginHint)
        XCTAssertTrue(googleParameters.includeGrantedScopes)
        
        let callback = URL(string: "callback://google_api")
        XCTAssertNotNil(callback)
        
        let creds = AppCredentials(clientId: "client_id", clientPassword: "client_pwd", scopes: ["scope1", "scope2"], callbackURL: callback!)
        let tokenHandling = GoogleAPI.googleAPITokenHandling(with: googleParameters)
        let config = Authenticator<Data>.Configuration(
            appCredentials: creds,
            tokenHandling: tokenHandling,
            userAuthenticator: Authenticator<Data>.failingUserAuthenticator
        )

        // Validate URL is properly constructed
        let googleURLProvider = try config.tokenHandling.authorizationURLProvider(creds)
        
        let urlComponent = URLComponents(url: googleURLProvider, resolvingAgainstBaseURL: true)
        XCTAssertNotNil(urlComponent)
        XCTAssertEqual(urlComponent!.scheme, GoogleAPI.scheme)
        
        // Validate query items inclusion and value
        XCTAssertNotNil(urlComponent!.queryItems)
        XCTAssertTrue(urlComponent!.queryItems!.contains(where: { $0.name == GoogleAPI.includeGrantedScopeKey }))
        XCTAssertTrue(urlComponent!.queryItems!.contains(where: { $0.name == GoogleAPI.loginHint }))
        XCTAssertTrue(urlComponent!.queryItems!.contains(where: { $0.value == String(true) }))
        XCTAssertTrue(urlComponent!.queryItems!.contains(where: { $0.value == "john@doe.com" }))
    }
    
    func testDefaultParameters() throws {
        let googleParameters = GoogleAPI.GoogleAPIParameters()
        
        XCTAssertNil(googleParameters.loginHint)
        XCTAssertTrue(googleParameters.includeGrantedScopes)
        
        let callback = URL(string: "callback://google_api")
        XCTAssertNotNil(callback)

        let creds = AppCredentials(clientId: "client_id", clientPassword: "client_pwd", scopes: ["scope1", "scope2"], callbackURL: callback!)
        let tokenHandling = GoogleAPI.googleAPITokenHandling(with: googleParameters)
        let config = Authenticator<Data>.Configuration(
            appCredentials: creds,
            tokenHandling: tokenHandling,
            userAuthenticator: Authenticator<Data>.failingUserAuthenticator
        )

        // Validate URL is properly constructed
        let googleURLProvider = try config.tokenHandling.authorizationURLProvider(creds)
        
        let urlComponent = URLComponents(url: googleURLProvider, resolvingAgainstBaseURL: true)
        XCTAssertNotNil(urlComponent)
        XCTAssertEqual(urlComponent!.scheme, GoogleAPI.scheme)

        // Validate query items inclusion and value
        XCTAssertNotNil(urlComponent!.queryItems)
        XCTAssertTrue(urlComponent!.queryItems!.contains(where: { $0.name == GoogleAPI.includeGrantedScopeKey }))
        XCTAssertFalse(urlComponent!.queryItems!.contains(where: { $0.name == GoogleAPI.loginHint }))
        XCTAssertTrue(urlComponent!.queryItems!.contains(where: { $0.value == String(true) }))
    }

}
