import Foundation
import Testing

@testable import OAuthenticator

struct GoogleTests {
	@Test
    func testOAuthResponseDecode() throws {
        let content = """
{"access_token": "abc", "expires_in": 3, "refresh_token": "def", "scope": "https://gmail.scope", "token_type": "bearer"}
"""
		let data = try #require(content.data(using: .utf8))
        let response = try JSONDecoder().decode(GoogleAPI.OAuthResponse.self, from: data)
        
		#expect(response.accessToken == "abc")

        let login = response.login
		#expect(login.accessToken.value == "abc")

        // Sleep until access token expires
        sleep(5)
		#expect(!login.accessToken.valid)
    }
    
    func testSuppliedParameters() async throws {
        let googleParameters = GoogleAPI.GoogleAPIParameters(includeGrantedScopes: true, loginHint: "john@doe.com")
        
		#expect(googleParameters.loginHint != nil)
		#expect(googleParameters.includeGrantedScopes)

		let callback = try #require(URL(string: "callback://google_api"))

        let creds = AppCredentials(clientId: "client_id", clientPassword: "client_pwd", scopes: ["scope1", "scope2"], callbackURL: callback)
        let tokenHandling = GoogleAPI.googleAPITokenHandling(with: googleParameters)
        let config = Authenticator.Configuration(
            appCredentials: creds,
            tokenHandling: tokenHandling,
            userAuthenticator: Authenticator.failingUserAuthenticator
        )
		let provider: URLResponseProvider = { _ in throw AuthenticatorError.httpResponseExpected }

        // Validate URL is properly constructed
		let params = TokenHandling.AuthorizationURLParameters(
			credentials: creds,
			pcke: nil,
			parRequestURI: nil,
			stateToken: "unused",
			responseProvider: provider
		)
        let googleURLProvider = try await config.tokenHandling.authorizationURLProvider(params)

        let urlComponent = URLComponents(url: googleURLProvider, resolvingAgainstBaseURL: true)
		#expect(urlComponent?.scheme == GoogleAPI.scheme)

        // Validate query items inclusion and value
		#expect(urlComponent!.queryItems!.contains(where: { $0.name == GoogleAPI.includeGrantedScopeKey }))
		#expect(urlComponent!.queryItems!.contains(where: { $0.name == GoogleAPI.loginHint }))
		#expect(urlComponent!.queryItems!.contains(where: { $0.value == String(true) }))
		#expect(urlComponent!.queryItems!.contains(where: { $0.value == "john@doe.com" }))
    }
    
    func testDefaultParameters() async throws {
        let googleParameters = GoogleAPI.GoogleAPIParameters()
        
		#expect(googleParameters.loginHint == nil)
		#expect(googleParameters.includeGrantedScopes)

		let callback = try #require(URL(string: "callback://google_api"))

        let creds = AppCredentials(clientId: "client_id", clientPassword: "client_pwd", scopes: ["scope1", "scope2"], callbackURL: callback)
        let tokenHandling = GoogleAPI.googleAPITokenHandling(with: googleParameters)
        let config = Authenticator.Configuration(
            appCredentials: creds,
            tokenHandling: tokenHandling,
            userAuthenticator: Authenticator.failingUserAuthenticator
        )
		let provider: URLResponseProvider = { _ in throw AuthenticatorError.httpResponseExpected }

        // Validate URL is properly constructed
		let params = TokenHandling.AuthorizationURLParameters(
			credentials: creds,
			pcke: nil,
			parRequestURI: nil,
			stateToken: "unused",
			responseProvider: provider
		)
        let googleURLProvider = try await config.tokenHandling.authorizationURLProvider(params)

        let urlComponent = URLComponents(url: googleURLProvider, resolvingAgainstBaseURL: true)
		#expect(urlComponent?.scheme == GoogleAPI.scheme)

        // Validate query items inclusion and value
		#expect(urlComponent!.queryItems!.contains(where: { $0.name == GoogleAPI.includeGrantedScopeKey }))
		#expect(urlComponent!.queryItems!.contains(where: { $0.name == GoogleAPI.loginHint }) == false)
		#expect(urlComponent!.queryItems!.contains(where: { $0.value == String(true) }))
    }
}
