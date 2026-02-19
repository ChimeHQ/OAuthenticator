import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
import Testing

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

	static let dummyResponse: (Data, URLResponse) = (
		"hello".data(using: .utf8)!,
		URLResponse(url: URL(string: "https://test.com")!, mimeType: nil, expectedContentLength: 5, textEncodingName: nil)
	)
}

struct AuthenticatorTests {
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
	private static func disabledAuthorizationURLProvider(parameters: TokenHandling.AuthorizationURLParameters) throws -> URL {
		throw AuthenticatorTestsError.disabled
	}

	@Sendable
	private static func disabledLoginProvider(parameters: TokenHandling.LoginProviderParameters) throws -> Login {
		throw AuthenticatorTestsError.disabled
	}

	@Test
	func testInitialLogin() async throws {
		let (stream, continuation) = AsyncStream<String>.makeStream()

		let mockLoader: URLResponseProvider = { request in
			#expect(request.value(forHTTPHeaderField: "Authorization") == "Bearer TOKEN")

			continuation.yield("request")

			return MockURLResponseProvider.dummyResponse
		}

		let mockUserAuthenticator: Authenticator.UserAuthenticator = { url, scheme in
			continuation.yield("auth")

			#expect(url == URL(string: "my://auth?client_id=abc")!)
			#expect(scheme == "my")

			return URL(string: "my://login")!
		}

		let urlProvider: TokenHandling.AuthorizationURLProvider = { params in
			return URL(string: "my://auth?client_id=\(params.credentials.clientId)")!
		}

		let loginProvider: TokenHandling.LoginProvider = { params in
			#expect(params.redirectURL == URL(string: "my://login")!)

			return Login(token: "TOKEN")
		}

		let tokenHandling = TokenHandling(
			authorizationURLProvider: urlProvider,
			loginProvider: loginProvider,
			responseStatusProvider: TokenHandling.allResponsesValid
		)

		let storage = LoginStorage {
			continuation.yield("load")

			return nil
		} storeLogin: {
			#expect($0 == Login(token: "TOKEN"))

			continuation.yield("store")
		} clearLogin: {
			Issue.record("token should not be cleared")
		}

		let config = Authenticator.Configuration(
			appCredentials: Self.mockCredentials,
			loginStorage: storage,
			tokenHandling: tokenHandling,
			userAuthenticator: mockUserAuthenticator
		)

		let auth = Authenticator(config: config, urlLoader: mockLoader)

		let (_, _) = try await auth.response(for: URLRequest(url: URL(string: "https://example.com")!))

		let events = try await stream.collect(finishing: continuation)
		#expect(events == ["load", "auth", "store", "request"])
	}

	@Test
	func testExistingLogin() async throws {
		let (stream, continuation) = AsyncStream<String>.makeStream()

		let mockLoader: URLResponseProvider = { request in
			#expect(request.value(forHTTPHeaderField: "Authorization") == "Bearer TOKEN")
			continuation.yield("request")

			return MockURLResponseProvider.dummyResponse
		}

		let tokenHandling = TokenHandling(
			authorizationURLProvider: Self.disabledAuthorizationURLProvider,
			loginProvider: Self.disabledLoginProvider,
			responseStatusProvider: TokenHandling.allResponsesValid
		)

		let storage = LoginStorage {
			continuation.yield("load")

			return Login(token: "TOKEN")
		} storeLogin: { _ in
			Issue.record("token should not be stored")
		} clearLogin: {
			Issue.record("token should not be cleared")
		}

		let config = Authenticator.Configuration(
			appCredentials: Self.mockCredentials,
			loginStorage: storage,
			tokenHandling: tokenHandling,
			userAuthenticator: Self.disabledUserAuthenticator
		)

		let auth = Authenticator(config: config, urlLoader: mockLoader)

		let (_, _) = try await auth.response(for: URLRequest(url: URL(string: "https://example.com")!))

		let events = try await stream.collect(finishing: continuation)
		#expect(events == ["load", "request"])
	}

	@Test
	func expiredTokenRefresh() async throws {
		let (stream, continuation) = AsyncStream<String>.makeStream()

		let mockLoader: URLResponseProvider = { request in
			#expect(request.value(forHTTPHeaderField: "Authorization") == "Bearer REFRESHED")
			continuation.yield("request")

			return MockURLResponseProvider.dummyResponse
		}

		let refreshProvider: TokenHandling.RefreshProvider = { login, _, _ in
			#expect(login.accessToken.value == "EXPIRED")
			#expect(login.refreshToken?.value == "REFRESH")

			continuation.yield("refresh")

			return Login(token: "REFRESHED")
		}

		let tokenHandling = TokenHandling(
			authorizationURLProvider: Self.disabledAuthorizationURLProvider,
			loginProvider: Self.disabledLoginProvider,
			refreshProvider: refreshProvider,
			responseStatusProvider: TokenHandling.allResponsesValid
		)

		let storage = LoginStorage {
			continuation.yield("load")

			return Login(
				accessToken: Token(value: "EXPIRED", expiry: .distantPast),
				refreshToken: Token(value: "REFRESH")
			)
		} storeLogin: { login in
			continuation.yield("store")

			#expect(login.accessToken.value == "REFRESHED")
		} clearLogin: {
			Issue.record("token should not be cleared")
		}

		let config = Authenticator.Configuration(
			appCredentials: Self.mockCredentials,
			loginStorage: storage,
			tokenHandling: tokenHandling,
			userAuthenticator: Self.disabledUserAuthenticator
		)

		let auth = Authenticator(config: config, urlLoader: mockLoader)

		let (_, _) = try await auth.response(for: URLRequest(url: URL(string: "https://example.com")!))

		let events = try await stream.collect(finishing: continuation)
		#expect(events == ["load", "refresh", "store", "request"])
	}

	@Test
	func expiredTokenRefreshFailing() async throws {
		let (stream, continuation) = AsyncStream<String>.makeStream()
		let mockLoader: URLResponseProvider = { request in
			// We should never load the resource, since we failed to refresh the session:
			Issue.record("load should not occcur")

			return MockURLResponseProvider.dummyResponse
		}

		let refreshProvider: TokenHandling.RefreshProvider = { login, _, _ in
			continuation.yield("refresh")

			#expect(login.accessToken.value == "EXPIRED")
			#expect(login.refreshToken?.value == "REFRESH")

			// Fail the refresh attempt, e.g., the refresh token has expired:
			throw AuthenticatorError.refreshNotPossible
		}

		let tokenHandling = TokenHandling(
			authorizationURLProvider: Self.disabledAuthorizationURLProvider,
			loginProvider: Self.disabledLoginProvider,
			refreshProvider: refreshProvider,
			responseStatusProvider: TokenHandling.allResponsesValid
		)

		let storage = LoginStorage {
			continuation.yield("load")

			return Login(
				accessToken: Token(value: "EXPIRED", expiry: .distantPast),
				refreshToken: Token(value: "REFRESH")
			)
		} storeLogin: { login in
			Issue.record("token should not be stored")
		} clearLogin: {
			continuation.yield("clear")
		}

		let config = Authenticator.Configuration(
			appCredentials: Self.mockCredentials,
			loginStorage: storage,
			tokenHandling: tokenHandling,
			userAuthenticator: Self.disabledUserAuthenticator
		)

		let auth = Authenticator(config: config, urlLoader: mockLoader)

		await #expect(throws: AuthenticatorError.refreshNotPossible) {
			let (_, _) = try await auth.response(for: URLRequest(url: URL(string: "https://example.com")!))
		}

		let events = try await stream.collect(finishing: continuation)
		#expect(events == ["load", "refresh", "clear"])
	}

	@Test
	func manualAuthentication() async throws {
		let (stream, continuation) = AsyncStream<String>.makeStream()

		let urlProvider: TokenHandling.AuthorizationURLProvider = { parameters in
			return URL(string: "my://auth?client_id=\(parameters.credentials.clientId)")!
		}

		let loginProvider: TokenHandling.LoginProvider = { parameters in
			#expect(parameters.redirectURL == URL(string: "my://login")!)

			return Login(token: "TOKEN")
		}

		let tokenHandling = TokenHandling(
			authorizationURLProvider: urlProvider,
			loginProvider: loginProvider,
			responseStatusProvider: TokenHandling.allResponsesValid
		)

		let mockUserAuthenticator: Authenticator.UserAuthenticator = { url, scheme in
			continuation.yield("auth")

			return URL(string: "my://login")!
		}

		let config = Authenticator.Configuration(
			appCredentials: Self.mockCredentials,
			tokenHandling: tokenHandling,
			mode: .manualOnly,
			userAuthenticator: mockUserAuthenticator
		)

		let mockLoader: URLResponseProvider = { request in
			continuation.yield("request")

			return MockURLResponseProvider.dummyResponse
		}

		let auth = Authenticator(config: config, urlLoader: mockLoader)

		await #expect(throws: AuthenticatorError.manualAuthenticationRequired) {
			let (_, _) = try await auth.response(for: URLRequest(url: URL(string: "https://example.com")!))
		}

		// now we explicitly authenticate, and things should work
		try await auth.authenticate()

		let (_, _) = try await auth.response(for: URLRequest(url: URL(string: "https://example.com")!))

		let events = try await stream.collect(finishing: continuation)
		#expect(events == ["auth", "request"])
	}

	@Test
	func manualAuthenticationWithSuccessResult() async throws {
		let (stream, continuation) = AsyncStream<String>.makeStream()

		let urlProvider: TokenHandling.AuthorizationURLProvider = { params in
			return URL(string: "my://auth?client_id=\(params.credentials.clientId)")!
		}

		let loginProvider: TokenHandling.LoginProvider = { params in
			#expect(params.redirectURL == URL(string: "my://login")!)

			return Login(token: "TOKEN")
		}

		let tokenHandling = TokenHandling(
			authorizationURLProvider: urlProvider,
			loginProvider: loginProvider,
			responseStatusProvider: TokenHandling.allResponsesValid
		)

		let mockUserAuthenticator: Authenticator.UserAuthenticator = { url, scheme in
			continuation.yield("auth")

			return URL(string: "my://login")!
		}

		// Configure Authenticator with result callback
		let config = Authenticator.Configuration(
			appCredentials: Self.mockCredentials,
			tokenHandling: tokenHandling,
			mode: .manualOnly,
			userAuthenticator: mockUserAuthenticator
		)

		let mockLoader: URLResponseProvider = { request in
			continuation.yield("request")

			return MockURLResponseProvider.dummyResponse
		}

		let auth = Authenticator(config: config, urlLoader: mockLoader)
		// Explicitly authenticate and grab Login information after
		let login = try await auth.authenticate()

		// Ensure our authenticatedLogin objet is available and contains the proper Token
		#expect(login == Login(token:"TOKEN"))

		let (_, _) = try await auth.response(for: URLRequest(url: URL(string: "https://example.com")!))

		let events = try await stream.collect(finishing: continuation)
		#expect(events == ["auth", "request"])
	}

	// Test AuthenticationResultHandler with a failed UserAuthenticator
	@Test
	func manualAuthenticationWithFailedResult() async throws {
		let (stream, continuation) = AsyncStream<String>.makeStream()

		let urlProvider: TokenHandling.AuthorizationURLProvider = { params in
			return URL(string: "my://auth?client_id=\(params.credentials.clientId)")!
		}

		let loginProvider: TokenHandling.LoginProvider = { params in
			#expect(params.redirectURL == URL(string: "my://login")!)

			return Login(token: "TOKEN")
		}

		let tokenHandling = TokenHandling(
			authorizationURLProvider: urlProvider,
			loginProvider: loginProvider,
			responseStatusProvider: TokenHandling.allResponsesValid
		)

		let authenticationCallback: Authenticator.AuthenticationStatusHandler = { result in
			switch result {
			case .failure(_):
				continuation.yield("status failure")
			case .success(_):
				#expect(Bool(false))
			}
		}

		// Configure Authenticator with result callback
		let config = Authenticator.Configuration(
			appCredentials: Self.mockCredentials,
			tokenHandling: tokenHandling,
			mode: .manualOnly,
			userAuthenticator: Authenticator.failingUserAuthenticator,
			authenticationStatusHandler: authenticationCallback
		)

		let auth = Authenticator(config: config, urlLoader: nil)
		await #expect(throws: AuthenticatorError.failingAuthenticatorUsed) {
			// Explicitly authenticate
			try await auth.authenticate()
		}

		let events = try await stream.collect(finishing: continuation)
		#expect(events == ["status failure"])
	}

	@Test
	func unauthorizedRequestRefreshes() async throws {
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

		let tokenHandling = TokenHandling(
			authorizationURLProvider: Self.disabledAuthorizationURLProvider,
			loginProvider: Self.disabledLoginProvider,
			refreshProvider: refreshProvider
		)

		let storage = LoginStorage {
			// ensure we actually try this one
			return Login(
				accessToken: Token(value: "EXPIRED", expiry: .distantFuture),
				refreshToken: Token(value: "REFRESH")
			)
		} storeLogin: { login in
			#expect(login.accessToken.value == "REFRESHED")
		} clearLogin: {
			Issue.record("token should not be cleared")
		}

		let config = Authenticator.Configuration(
			appCredentials: Self.mockCredentials,
			loginStorage: storage,
			tokenHandling: tokenHandling,
			userAuthenticator: Self.disabledUserAuthenticator
		)

		let auth = Authenticator(config: config, urlLoader: mockLoader.responseProvider)

		let (data, _) = try await auth.response(for: URLRequest(url: requestedURL))

		#expect(data == mockData)
		#expect(mockLoader.requests.count == 2)
		#expect(mockLoader.requests[0].allHTTPHeaderFields!["Authorization"] == "Bearer EXPIRED")
		#expect(mockLoader.requests[1].allHTTPHeaderFields!["Authorization"] == "Bearer REFRESHED")
	}

	@available(macOS 13.0, macCatalyst 16.0, iOS 16.0, watchOS 9.0, tvOS 16.0, *)
	@Test
	func tokenExpiredAfterUseRefresh() async throws {
		let (stream, continuation) = AsyncStream<String>.makeStream()

		let mockLoader: URLResponseProvider = { @MainActor request in
			continuation.yield("request")
			continuation.yield(request.value(forHTTPHeaderField: "Authorization") ?? "<none>")

			return MockURLResponseProvider.dummyResponse
		}

		let refreshProvider: TokenHandling.RefreshProvider = { login, _, _ in
			continuation.yield("refresh")
			continuation.yield(login.refreshToken?.value ?? "<none>")

			return Login(token: "REFRESHED")
		}

		let tokenHandling = TokenHandling(
			authorizationURLProvider: Self.disabledAuthorizationURLProvider,
			loginProvider: Self.disabledLoginProvider,
			refreshProvider: refreshProvider,
			responseStatusProvider: TokenHandling.allResponsesValid
		)

		let storedLogin = Login(
			accessToken: Token(value: "EXPIRE SOON", expiry: Date().addingTimeInterval(5)),
			refreshToken: Token(value: "REFRESH")
		)

		let storage = LoginStorage {
			continuation.yield("login load")

			return storedLogin
		} storeLogin: { login in
			continuation.yield("login save")
			continuation.yield(login.accessToken.value)
		} clearLogin: {
			Issue.record("token should not be cleared")
		}

		let config = Authenticator.Configuration(
			appCredentials: Self.mockCredentials,
			loginStorage: storage,
			tokenHandling: tokenHandling,
			userAuthenticator: Self.disabledUserAuthenticator
		)

		let auth = Authenticator(config: config, urlLoader: mockLoader)

		let (_, _) = try await auth.response(for: URLRequest(url: URL(string: "https://example.com")!))
		continuation.checkpoint()

		let events1 = try await stream.collectToCheckpoint()
		let expected1 = [
			"login load",
			"request",
			"Bearer EXPIRE SOON",
			"checkpoint"
		]
		#expect(events1 == expected1)

		// Let the token expire
		try await Task.sleep(for: .seconds(5))

		let (_, _) = try await auth.response(for: URLRequest(url: URL(string: "https://example.com")!))
		continuation.checkpoint()

		let events2 = try await stream.collectToCheckpoint()
		let expected2 = [
			"login load",
			"refresh",
			"REFRESH",
			"login save",
			"REFRESHED",
			"request",
			"Bearer REFRESHED",
			"checkpoint",
		]
		#expect(events2 == expected2)

		let (_, _) = try await auth.response(for: URLRequest(url: URL(string: "https://example.com")!))

		let events3 = try await stream.collect(finishing: continuation)
		let expected3 = [
			"request",
			"Bearer REFRESHED",
		]
		#expect(events3 == expected3)
	}
}
