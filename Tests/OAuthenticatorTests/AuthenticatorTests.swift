import XCTest
@testable import OAuthenticator

enum AuthenticatorTestsError: Error {
	case disabled
}

final class AuthenticatorTests: XCTestCase {
	private static let mockCredentials = AppCredentials(clientId: "abc",
														clientPassword: "def",
														scopes: ["123"],
														callbackURL: URL(string: "my://callback")!)

	private static let disabledUserAuthenticator: Authenticator.UserAuthenticator = { _, _ in
		throw AuthenticatorTestsError.disabled
	}

	private static let disabledAuthorizationURLProvider: TokenHandling.AuthorizationURLProvider = { _ in
		throw AuthenticatorTestsError.disabled
	}

	private static let disabledLoginProvider: TokenHandling.LoginProvider = { _, _, _, _ in
		throw AuthenticatorTestsError.disabled
	}

	func testInitialLogin() async throws {
		let authedLoadExp = expectation(description: "load url")

		let mockLoader: URLResponseProvider = { request in
			XCTAssertEqual(request.value(forHTTPHeaderField: "Authorization"), "bearer TOKEN")
			authedLoadExp.fulfill()

			return ("hello".data(using: .utf8)!, URLResponse())
		}

		let webAuthExp = expectation(description: "web auth")
		let mockWebAuthenticator: Authenticator.UserAuthenticator = { url, scheme in
			webAuthExp.fulfill()
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
										  loginProvider: loginProvider)

		let retrieveTokenExp = expectation(description: "get token")
		let storeTokenExp = expectation(description: "save token")

		let storage = LoginStorage {
			retrieveTokenExp.fulfill()

			return nil
		} storeLogin: {
			XCTAssertEqual($0, Login(token: "TOKEN"))

			storeTokenExp.fulfill()
		}

		let config = Authenticator.Configuration(appCredentials: Self.mockCredentials,
												 loginStorage: storage,
												 tokenHandling: tokenHandling,
												 userAuthenticator: mockWebAuthenticator)

		let auth = await Authenticator(config: config, urlLoader: mockLoader)

		let (_, _) = try await auth.response(for: URLRequest(url: URL(string: "https://example.com")!))

		await fulfillment(of: [retrieveTokenExp, webAuthExp, storeTokenExp, authedLoadExp], enforceOrder: true)
	}

	func testExistingLogin() async throws {
		let authedLoadExp = expectation(description: "load url")

		let mockLoader: URLResponseProvider = { request in
			XCTAssertEqual(request.value(forHTTPHeaderField: "Authorization"), "bearer TOKEN")
			authedLoadExp.fulfill()

			return ("hello".data(using: .utf8)!, URLResponse())
		}

		let tokenHandling = TokenHandling(authorizationURLProvider: Self.disabledAuthorizationURLProvider,
										  loginProvider: Self.disabledLoginProvider)

		let retrieveTokenExp = expectation(description: "get token")
		let storage = LoginStorage {
			retrieveTokenExp.fulfill()

			return Login(token: "TOKEN")
		} storeLogin: { _ in
			XCTFail()
		}

		let config = Authenticator.Configuration(appCredentials: Self.mockCredentials,
												 loginStorage: storage,
												 tokenHandling: tokenHandling,
												 userAuthenticator: Self.disabledUserAuthenticator)

		let auth = await Authenticator(config: config, urlLoader: mockLoader)

		let (_, _) = try await auth.response(for: URLRequest(url: URL(string: "https://example.com")!))

		await fulfillment(of: [retrieveTokenExp, authedLoadExp], enforceOrder: true)
	}

	func testExpiredTokenRefresh() async throws {
		let authedLoadExp = expectation(description: "load url")

		let mockLoader: URLResponseProvider = { request in
			XCTAssertEqual(request.value(forHTTPHeaderField: "Authorization"), "bearer REFRESHED")
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
										  refreshProvider: refreshProvider)

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

		let config = Authenticator.Configuration(appCredentials: Self.mockCredentials,
												 loginStorage: storage,
												 tokenHandling: tokenHandling,
												 userAuthenticator: Self.disabledUserAuthenticator)

		let auth = await Authenticator(config: config, urlLoader: mockLoader)

		let (_, _) = try await auth.response(for: URLRequest(url: URL(string: "https://example.com")!))

		await fulfillment(of: [retrieveTokenExp, refreshExp, storeTokenExp, authedLoadExp], enforceOrder: true)
	}
}
