import XCTest
import OAuthenticator

enum AuthenticatorTestsError: Error {
	case disabled
}

final class MockURLResponseProvider: @unchecked Sendable {
	var responses: [Result<(Data, URLResponse), Error>] = []
	private(set) var requests: [URLRequest] = []
	private let lock = NSLock()

	init() {
	}

	func response(for request: URLRequest) throws -> (Data, URLResponse) {
		try lock.withLock {
			requests.append(request)

			return try responses.removeFirst().get()
		}
	}

	var responseProvider: URLResponseProvider {
		return { try self.response(for: $0) }
	}
}

final class AuthenticatorTests: XCTestCase {
	private static let mockCredentials = AppCredentials(
		clientId: "abc",
		clientPassword: "def",
		scopes: ["123"],
		callbackURL: URL(string: "my://callback")!
	)

	@Sendable
	private static func disabledUserAuthenticator(url: URL, user: String) throws -> URL {
		throw AuthenticatorTestsError.disabled
	}

	@Sendable
	private static func disabledAuthorizationURLProvider(credentials: AppCredentials) throws -> URL {
		throw AuthenticatorTestsError.disabled
	}

	@Sendable
	private static func disabledLoginProvider(
		url: URL,
		credentials: AppCredentials,
		otherURL: URL,
		responseProvider: URLResponseProvider
	) throws -> Login{
		throw AuthenticatorTestsError.disabled
	}

	@MainActor
	func testInitialLogin() async throws {
		let authedLoadExp = expectation(description: "load url")

		let mockLoader: URLResponseProvider = { request in
			XCTAssertEqual(request.value(forHTTPHeaderField: "Authorization"), "Bearer TOKEN")
			authedLoadExp.fulfill()

			return ("hello".data(using: .utf8)!, URLResponse())
		}

		let userAuthExp = expectation(description: "user auth")
		let mockUserAuthenticator: Authenticator.UserAuthenticator = { url, scheme in
			userAuthExp.fulfill()
			XCTAssertEqual(url, URL(string: "my://auth?client_id=abc")!)
			XCTAssertEqual(scheme, "my")

			return URL(string: "my://login")!
		}

		let urlProvider: TokenHandling.AuthorizationURLProvider = { creds in
			return URL(string: "my://auth?client_id=\(creds.clientId)")!
		}

		let loginProvider: TokenHandling.LoginProvider = { url, creds, tokenUrl, _ in
			XCTAssertEqual(url, URL(string: "my://login")!)

			return Login(token: "TOKEN")
		}

		let tokenHandling = TokenHandling(authorizationURLProvider: urlProvider,
										  loginProvider: loginProvider,
										  responseStatusProvider: TokenHandling.allResponsesValid)

		let retrieveTokenExp = expectation(description: "get token")
		let storeTokenExp = expectation(description: "save token")

		let storage = LoginStorage {
			retrieveTokenExp.fulfill()

			return nil
		} storeLogin: {
			XCTAssertEqual($0, Login(token: "TOKEN"))

			storeTokenExp.fulfill()
		}

		let config = Authenticator<Data>.Configuration(
			appCredentials: Self.mockCredentials,
			loginStorage: storage,
//			loginStorage: nil,
			tokenHandling: tokenHandling,
//			tokenHandling: TokenHandling(
//				authorizationURLProvider: { _ in
//					throw AuthenticatorTestsError.disabled
//				},
//				loginProvider: { _, _, _, _ in
//					throw AuthenticatorTestsError.disabled
//				}
//			),
			userAuthenticator: mockUserAuthenticator
		)

		let auth = Authenticator(config: config, urlLoader: mockLoader)

		let (_, _) = try await auth.response(for: URLRequest(url: URL(string: "https://example.com")!))

		await fulfillment(of: [retrieveTokenExp, userAuthExp, storeTokenExp, authedLoadExp], timeout: 1.0, enforceOrder: true)
	}

	@MainActor
	func testExistingLogin() async throws {
		let authedLoadExp = expectation(description: "load url")

		let mockLoader: URLResponseProvider = { request in
			XCTAssertEqual(request.value(forHTTPHeaderField: "Authorization"), "Bearer TOKEN")
			authedLoadExp.fulfill()

			return ("hello".data(using: .utf8)!, URLResponse())
		}

		let tokenHandling = TokenHandling(authorizationURLProvider: Self.disabledAuthorizationURLProvider,
										  loginProvider: Self.disabledLoginProvider,
										  responseStatusProvider: TokenHandling.allResponsesValid)

		let retrieveTokenExp = expectation(description: "get token")
		let storage = LoginStorage {
			retrieveTokenExp.fulfill()

			return Login(token: "TOKEN")
		} storeLogin: { _ in
			XCTFail()
		}

		let config = Authenticator<Data>.Configuration(appCredentials: Self.mockCredentials,
													   loginStorage: storage,
													   tokenHandling: tokenHandling,
													   userAuthenticator: Self.disabledUserAuthenticator)

		let auth = Authenticator(config: config, urlLoader: mockLoader)

		let (_, _) = try await auth.response(for: URLRequest(url: URL(string: "https://example.com")!))

		await fulfillment(of: [retrieveTokenExp, authedLoadExp], timeout: 1.0, enforceOrder: true)
	}

	@MainActor
	func testExpiredTokenRefresh() async throws {
		let authedLoadExp = expectation(description: "load url")

		let mockLoader: URLResponseProvider = { request in
			XCTAssertEqual(request.value(forHTTPHeaderField: "Authorization"), "Bearer REFRESHED")
			authedLoadExp.fulfill()

			return ("hello".data(using: .utf8)!, URLResponse())
		}

		let refreshExp = expectation(description: "refresh")
		let refreshProvider: TokenHandling.RefreshProvider = { login, _, _ in
			XCTAssertEqual(login.accessToken.value, "EXPIRED")
			XCTAssertEqual(login.refreshToken?.value, "REFRESH")

			refreshExp.fulfill()

			return Login(token: "REFRESHED")
		}

		let tokenHandling = TokenHandling(authorizationURLProvider: Self.disabledAuthorizationURLProvider,
										  loginProvider: Self.disabledLoginProvider,
										  refreshProvider: refreshProvider,
										  responseStatusProvider: TokenHandling.allResponsesValid)

		let retrieveTokenExp = expectation(description: "get token")
		let storeTokenExp = expectation(description: "save token")

		let storage = LoginStorage {
			retrieveTokenExp.fulfill()

			return Login(accessToken: Token(value: "EXPIRED", expiry: .distantPast),
						 refreshToken: Token(value: "REFRESH"))
		} storeLogin: { login in
			storeTokenExp.fulfill()

			XCTAssertEqual(login.accessToken.value, "REFRESHED")
		}

		let config = Authenticator<Data>.Configuration(appCredentials: Self.mockCredentials,
													   loginStorage: storage,
													   tokenHandling: tokenHandling,
													   userAuthenticator: Self.disabledUserAuthenticator)

		let auth = Authenticator(config: config, urlLoader: mockLoader)

		let (_, _) = try await auth.response(for: URLRequest(url: URL(string: "https://example.com")!))

		await fulfillment(of: [retrieveTokenExp, refreshExp, storeTokenExp, authedLoadExp], timeout: 1.0, enforceOrder: true)
	}

	@MainActor
	func testManualAuthentication() async throws {
		let urlProvider: TokenHandling.AuthorizationURLProvider = { creds in
			return URL(string: "my://auth?client_id=\(creds.clientId)")!
		}

		let loginProvider: TokenHandling.LoginProvider = { url, creds, tokenUrl, _ in
			XCTAssertEqual(url, URL(string: "my://login")!)

			return Login(token: "TOKEN")
		}

		let tokenHandling = TokenHandling(authorizationURLProvider: urlProvider,
										  loginProvider: loginProvider,
										  responseStatusProvider: TokenHandling.allResponsesValid)

		let userAuthExp = expectation(description: "user auth")
		let mockUserAuthenticator: Authenticator.UserAuthenticator = { url, scheme in
			userAuthExp.fulfill()

			return URL(string: "my://login")!
		}

		let config = Authenticator<Data>.Configuration(appCredentials: Self.mockCredentials,
													   tokenHandling: tokenHandling,
													   mode: .manualOnly,
													   userAuthenticator: mockUserAuthenticator)

		let loadExp = expectation(description: "load url")
		let mockLoader: URLResponseProvider = { request in
			loadExp.fulfill()

			return ("hello".data(using: .utf8)!, URLResponse())
		}

		let auth = Authenticator(config: config, urlLoader: mockLoader)

		do {
			let (_, _) = try await auth.response(for: URLRequest(url: URL(string: "https://example.com")!))

			XCTFail()
		} catch AuthenticatorError.manualAuthenticationRequired {

		} catch {
			XCTFail()
		}

		// now we explicitly authenticate, and things should work
		try await auth.authenticate()

		let (_, _) = try await auth.response(for: URLRequest(url: URL(string: "https://example.com")!))
		
		await fulfillment(of: [userAuthExp, loadExp], timeout: 1.0, enforceOrder: true)
	}

    func testManualAuthenticationWithSuccessResult() async throws {
        let urlProvider: TokenHandling.AuthorizationURLProvider = { creds in
            return URL(string: "my://auth?client_id=\(creds.clientId)")!
        }

        let loginProvider: TokenHandling.LoginProvider = { url, creds, tokenUrl, _ in
            XCTAssertEqual(url, URL(string: "my://login")!)

            return Login(token: "TOKEN")
        }

        let tokenHandling = TokenHandling(authorizationURLProvider: urlProvider,
                                          loginProvider: loginProvider,
                                          responseStatusProvider: TokenHandling.allResponsesValid)

        let userAuthExp = expectation(description: "user auth")
        let mockUserAuthenticator: Authenticator.UserAuthenticator = { url, scheme in
            userAuthExp.fulfill()

            return URL(string: "my://login")!
        }
        
        // This is the callback to obtain authentication results
        var authenticatedLogin: Login?
        let authenticationCallback: Authenticator.AuthenticationStatusHandler = { result in
            switch result {
                case .failure(_):
                     XCTFail()
                case .success(let login):
                    authenticatedLogin = login
            }
        }
        
        // Configure Authenticator with result callback
		let config = Authenticator<Data>.Configuration(appCredentials: Self.mockCredentials,
													   tokenHandling: tokenHandling,
													   mode: .manualOnly,
													   userAuthenticator: mockUserAuthenticator,
													   authenticationStatusHandler: authenticationCallback)

        let loadExp = expectation(description: "load url")
        let mockLoader: URLResponseProvider = { request in
            loadExp.fulfill()

            return ("hello".data(using: .utf8)!, URLResponse())
        }

        let auth = Authenticator(config: config, urlLoader: mockLoader)
        // Explicitly authenticate and grab Login information after
        try await auth.authenticate()
        
        // Ensure our authenticatedLogin objet is available and contains the proper Token
        XCTAssertNotNil(authenticatedLogin)
        XCTAssertEqual(authenticatedLogin!, Login(token:"TOKEN"))

        let (_, _) = try await auth.response(for: URLRequest(url: URL(string: "https://example.com")!))
        
		await fulfillment(of: [userAuthExp, loadExp], timeout: 1.0, enforceOrder: true)
    }

    // Test AuthenticationResultHandler with a failed UserAuthenticator
    func testManualAuthenticationWithFailedResult() async throws {
        let urlProvider: TokenHandling.AuthorizationURLProvider = { creds in
            return URL(string: "my://auth?client_id=\(creds.clientId)")!
        }

        let loginProvider: TokenHandling.LoginProvider = { url, creds, tokenUrl, _ in
            XCTAssertEqual(url, URL(string: "my://login")!)

            return Login(token: "TOKEN")
        }

        let tokenHandling = TokenHandling(authorizationURLProvider: urlProvider,
                                          loginProvider: loginProvider,
                                          responseStatusProvider: TokenHandling.allResponsesValid)

        // This is the callback to obtain authentication results
        var authenticatedLogin: Login?
        let failureAuth = expectation(description: "auth failure")
        let authenticationCallback: Authenticator.AuthenticationStatusHandler = { result in
            switch result {
                case .failure(_):
                    failureAuth.fulfill()
                    authenticatedLogin = nil
                case .success(_):
                    XCTFail()
            }
        }
        
        // Configure Authenticator with result callback
		let config = Authenticator<Data>.Configuration(appCredentials: Self.mockCredentials,
													   tokenHandling: tokenHandling,
													   mode: .manualOnly,
													   userAuthenticator: Authenticator<Data>.failingUserAuthenticator,
													   authenticationStatusHandler: authenticationCallback)
        
        let auth = Authenticator(config: config, urlLoader: nil)
        do {
            // Explicitly authenticate and grab Login information after
            try await auth.authenticate()
            
            // Ensure our authenticatedLogin objet is *not* available
            XCTAssertNil(authenticatedLogin)
        }
        catch let error as AuthenticatorError {
            XCTAssertEqual(error, AuthenticatorError.failingAuthenticatorUsed)
        }
        catch {
            throw error
        }

		await fulfillment(of: [failureAuth], timeout: 1.0, enforceOrder: true)
    }

	func testUnauthorizedRequestRefreshes() async throws {
		let requestedURL = URL(string: "https://example.com")!

		let mockLoader = MockURLResponseProvider()
		let mockData = "hello".data(using: .utf8)!

		mockLoader.responses = [
			.success((Data(), HTTPURLResponse(url: requestedURL, statusCode: 401, httpVersion: nil, headerFields: nil)!)),
			.success((mockData, HTTPURLResponse(url: requestedURL, statusCode: 200, httpVersion: nil, headerFields: nil)!)),
		]

		let refreshProvider: TokenHandling.RefreshProvider = { login, _, _ in
			return Login(token: "REFRESHED")
		}

		let tokenHandling = TokenHandling(authorizationURLProvider: Self.disabledAuthorizationURLProvider,
										  loginProvider: Self.disabledLoginProvider,
										  refreshProvider: refreshProvider)

		let storage = LoginStorage {
			// ensure we actually try this one
			return Login(accessToken: Token(value: "EXPIRED", expiry: .distantFuture),
						 refreshToken: Token(value: "REFRESH"))
		} storeLogin: { login in
			XCTAssertEqual(login.accessToken.value, "REFRESHED")
		}

		let config = Authenticator<Data>.Configuration(appCredentials: Self.mockCredentials,
													   loginStorage: storage,
													   tokenHandling: tokenHandling,
													   userAuthenticator: Self.disabledUserAuthenticator)

		let auth = Authenticator(config: config, urlLoader: mockLoader.responseProvider)

		let (data, _) = try await auth.response(for: URLRequest(url: requestedURL))

		XCTAssertEqual(data, mockData)
		XCTAssertEqual(mockLoader.requests.count, 2)
		XCTAssertEqual(mockLoader.requests[0].allHTTPHeaderFields!["Authorization"], "Bearer EXPIRED")
		XCTAssertEqual(mockLoader.requests[1].allHTTPHeaderFields!["Authorization"], "Bearer REFRESHED")
	}

	actor RequestContainer {
		private(set) var sentRequests: [URLRequest] = []

		func addRequest(_ request: URLRequest) {
			self.sentRequests.append(request)
		}
	}

	@MainActor
    func testTokenExpiredAfterUseRefresh() async throws {
		var sentRequests: [URLRequest] = []

        let mockLoader: URLResponseProvider = { @MainActor request in
			sentRequests.append(request)
            return ("hello".data(using: .utf8)!, URLResponse())
        }

        var refreshedLogins: [Login] = []
        let refreshProvider: TokenHandling.RefreshProvider = { @MainActor login, _, _ in
			refreshedLogins.append(login)

            return Login(token: "REFRESHED")
        }

        let tokenHandling = TokenHandling(
            authorizationURLProvider: Self.disabledAuthorizationURLProvider,
            loginProvider: Self.disabledLoginProvider,
            refreshProvider: refreshProvider,
            responseStatusProvider: TokenHandling.allResponsesValid
        )

        let storedLogin = Login(
            accessToken: Token(value: "EXPIRE SOON", expiry: Date().addingTimeInterval(1)),
            refreshToken: Token(value: "REFRESH")
        )
        var loadLoginCount = 0
        var savedLogins: [Login] = []
		let storage = LoginStorage { @MainActor in
			loadLoginCount += 1

            return storedLogin
        } storeLogin: { @MainActor login in
            savedLogins.append(login)
        }

		let config = Authenticator<Data>.Configuration(appCredentials: Self.mockCredentials,
													   loginStorage: storage,
													   tokenHandling: tokenHandling,
													   userAuthenticator: Self.disabledUserAuthenticator)

        let auth = Authenticator(config: config, urlLoader: mockLoader)

        let (_, _) = try await auth.response(for: URLRequest(url: URL(string: "https://example.com")!))
		let sentRequestsOne = sentRequests

        XCTAssertEqual(sentRequestsOne.count, 1, "First request should be sent")
        XCTAssertEqual(sentRequestsOne.first?.value(forHTTPHeaderField: "Authorization"), "Bearer EXPIRE SOON", "Non expired token should be used for first request")
        XCTAssertTrue(refreshedLogins.isEmpty, "Token should not be refreshed after first request")
        XCTAssertEqual(loadLoginCount, 1, "Login should be loaded from storage once")
        XCTAssertTrue(savedLogins.isEmpty, "Login storage should not be updated after first request")

        // Let the token expire
		try await Task.sleep(nanoseconds: 1 * NSEC_PER_SEC)

        let (_, _) = try await auth.response(for: URLRequest(url: URL(string: "https://example.com")!))
		let sentRequestsTwo = sentRequests

        XCTAssertEqual(refreshedLogins.count, 1, "Token should be refreshed")
        XCTAssertEqual(refreshedLogins.first?.accessToken.value, "EXPIRE SOON", "Expired token should be passed to refresh call")
        XCTAssertEqual(refreshedLogins.first?.refreshToken?.value, "REFRESH", "Refresh token should be passed to refresh call")
        XCTAssertEqual(loadLoginCount, 2, "New login should be loaded from storage")
        XCTAssertEqual(sentRequestsTwo.count, 2, "Second request should be sent")
        let secondRequest = sentRequestsTwo.dropFirst().first
        XCTAssertEqual(secondRequest?.value(forHTTPHeaderField: "Authorization"), "Bearer REFRESHED", "Refreshed token should be used for second request")
        XCTAssertEqual(savedLogins.first?.accessToken.value, "REFRESHED", "Refreshed token should be saved to storage")

        let (_, _) = try await auth.response(for: URLRequest(url: URL(string: "https://example.com")!))
		let sentRequestsThree = sentRequests

        XCTAssertEqual(refreshedLogins.count, 1, "No additional refreshes should happen")
        XCTAssertEqual(loadLoginCount, 2, "No additional login loads should happen")
        XCTAssertEqual(sentRequestsThree.count, 3, "Third request should be sent")
        let thirdRequest = sentRequestsThree.dropFirst(2).first
        XCTAssertEqual(thirdRequest?.value(forHTTPHeaderField: "Authorization"), "Bearer REFRESHED", "Refreshed token should be used for third request")
        XCTAssertEqual(savedLogins.count, 1, "No additional logins should be saved to storage")
    }
}
