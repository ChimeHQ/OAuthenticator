import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
import Testing

import OAuthenticator

enum AuthenticatorTestsError: Error {
	case disabled
}

extension AsyncSequence {
	func collect() async throws -> [Element] {
		try await reduce(into: [Element]()) { $0.append($1) }
	}
}

extension AsyncStream {
	func collect(finishing continuation: Self.Continuation) async throws -> [Element] {
		continuation.finish()

		return try await collect()
	}
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
		let (stream, continutation) = AsyncStream<Int>.makeStream()

		let mockLoader: URLResponseProvider = { request in
			#expect(request.value(forHTTPHeaderField: "Authorization") == "Bearer TOKEN")

			continutation.yield(4)

			return MockURLResponseProvider.dummyResponse
		}

		let mockUserAuthenticator: Authenticator.UserAuthenticator = { url, scheme in
			continutation.yield(2)

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
			continutation.yield(1)

			return nil
		} storeLogin: {
			#expect($0 == Login(token: "TOKEN"))

			continutation.yield(3)
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

		let events = try await stream.collect(finishing: continutation)
		#expect(events == [1, 2, 3, 4])
	}

	@Test
	func testExistingLogin() async throws {
		let (stream, continutation) = AsyncStream<Int>.makeStream()

		let mockLoader: URLResponseProvider = { request in
			#expect(request.value(forHTTPHeaderField: "Authorization") == "Bearer TOKEN")
			continutation.yield(2)

			return MockURLResponseProvider.dummyResponse
		}

		let tokenHandling = TokenHandling(
			authorizationURLProvider: Self.disabledAuthorizationURLProvider,
			loginProvider: Self.disabledLoginProvider,
			responseStatusProvider: TokenHandling.allResponsesValid
		)

		let storage = LoginStorage {
			continutation.yield(1)

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

		let events = try await stream.collect(finishing: continutation)
		#expect(events == [1, 2])
	}

	@Test
	func expiredTokenRefresh() async throws {
		let (stream, continutation) = AsyncStream<Int>.makeStream()

		let mockLoader: URLResponseProvider = { request in
			#expect(request.value(forHTTPHeaderField: "Authorization") == "Bearer REFRESHED")
			continutation.yield(4)

			return MockURLResponseProvider.dummyResponse
		}

		let refreshProvider: TokenHandling.RefreshProvider = { login, _, _ in
			#expect(login.accessToken.value == "EXPIRED")
			#expect(login.refreshToken?.value == "REFRESH")

			continutation.yield(2)

			return Login(token: "REFRESHED")
		}

		let tokenHandling = TokenHandling(
			authorizationURLProvider: Self.disabledAuthorizationURLProvider,
			loginProvider: Self.disabledLoginProvider,
			refreshProvider: refreshProvider,
			responseStatusProvider: TokenHandling.allResponsesValid
		)

		let storage = LoginStorage {
			continutation.yield(1)

			return Login(
				accessToken: Token(value: "EXPIRED", expiry: .distantPast),
				refreshToken: Token(value: "REFRESH")
			)
		} storeLogin: { login in
			continutation.yield(3)

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

		let events = try await stream.collect(finishing: continutation)
		#expect(events == [1, 2, 3, 4])
	}

	@Test
	func expiredTokenRefreshFailing() async throws {
		let (stream, continutation) = AsyncStream<Int>.makeStream()
		let mockLoader: URLResponseProvider = { request in
			// We should never load the resource, since we failed to refresh the session:
			Issue.record("load should not occcur")

			return MockURLResponseProvider.dummyResponse
		}

		let refreshProvider: TokenHandling.RefreshProvider = { login, _, _ in
			continutation.yield(2)

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
			continutation.yield(1)

			return Login(
				accessToken: Token(value: "EXPIRED", expiry: .distantPast),
				refreshToken: Token(value: "REFRESH")
			)
		} storeLogin: { login in
			Issue.record("token should not be stored")
		} clearLogin: {
			continutation.yield(3)
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

		let events = try await stream.collect(finishing: continutation)
		#expect(events == [1, 2, 3])
	}

	@Test
	func manualAuthentication() async throws {
		let (stream, continutation) = AsyncStream<Int>.makeStream()

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
			continutation.yield(1)

			return URL(string: "my://login")!
		}

		let config = Authenticator.Configuration(
			appCredentials: Self.mockCredentials,
			tokenHandling: tokenHandling,
			mode: .manualOnly,
			userAuthenticator: mockUserAuthenticator
		)

		let mockLoader: URLResponseProvider = { request in
			continutation.yield(2)

			return MockURLResponseProvider.dummyResponse
		}

		let auth = Authenticator(config: config, urlLoader: mockLoader)

		await #expect(throws: AuthenticatorError.manualAuthenticationRequired) {
			let (_, _) = try await auth.response(for: URLRequest(url: URL(string: "https://example.com")!))
		}

		// now we explicitly authenticate, and things should work
		try await auth.authenticate()

		let (_, _) = try await auth.response(for: URLRequest(url: URL(string: "https://example.com")!))

		let events = try await stream.collect(finishing: continutation)
		#expect(events == [1, 2])
	}

	@Test
	func manualAuthenticationWithSuccessResult() async throws {
		let (stream, continutation) = AsyncStream<Int>.makeStream()

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
			continutation.yield(1)

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
			continutation.yield(2)

			return MockURLResponseProvider.dummyResponse
		}

		let auth = Authenticator(config: config, urlLoader: mockLoader)
		// Explicitly authenticate and grab Login information after
		let login = try await auth.authenticate()

		// Ensure our authenticatedLogin objet is available and contains the proper Token
		#expect(login == Login(token:"TOKEN"))

		let (_, _) = try await auth.response(for: URLRequest(url: URL(string: "https://example.com")!))

		let events = try await stream.collect(finishing: continutation)
		#expect(events == [1, 2])
	}

	// Test AuthenticationResultHandler with a failed UserAuthenticator
	@Test
	func manualAuthenticationWithFailedResult() async throws {
		let (stream, continutation) = AsyncStream<Int>.makeStream()

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

		let authenticationCallback: Authenticator.AuthenticationStatusHandler = { @MainActor result in
			switch result {
			case .failure(_):
				continutation.yield(1)
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

		let events = try await stream.collect(finishing: continutation)
		#expect(events == [1])
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
	@MainActor
	@Test
	func tokenExpiredAfterUseRefresh() async throws {
		var sentRequests: [URLRequest] = []

		let mockLoader: URLResponseProvider = { @MainActor request in
			sentRequests.append(request)
			return MockURLResponseProvider.dummyResponse
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
			accessToken: Token(value: "EXPIRE SOON", expiry: Date().addingTimeInterval(10)),
			refreshToken: Token(value: "REFRESH")
		)
		var loadLoginCount = 0
		var savedLogins: [Login] = []
		let storage = LoginStorage { @MainActor in
			loadLoginCount += 1

			return storedLogin
		} storeLogin: { @MainActor login in
			savedLogins.append(login)
		} clearLogin: {
			Issue.record("token should not be cleared")
		}

		let config = Authenticator.Configuration(appCredentials: Self.mockCredentials,
												 loginStorage: storage,
												 tokenHandling: tokenHandling,
												 userAuthenticator: Self.disabledUserAuthenticator)

		let auth = Authenticator(config: config, urlLoader: mockLoader)

		let (_, _) = try await auth.response(for: URLRequest(url: URL(string: "https://example.com")!))
		let sentRequestsOne = sentRequests

		#expect(sentRequestsOne.count == 1, "First request should be sent")
		#expect(sentRequestsOne.first?.value(forHTTPHeaderField: "Authorization") == "Bearer EXPIRE SOON", "Non expired token should be used for first request")
		#expect(refreshedLogins.isEmpty, "Token should not be refreshed after first request")
		#expect(loadLoginCount == 1, "Login should be loaded from storage once")
		#expect(savedLogins.isEmpty, "Login storage should not be updated after first request")

		// Let the token expire
		try await Task.sleep(for: .seconds(10))

		let (_, _) = try await auth.response(for: URLRequest(url: URL(string: "https://example.com")!))
		let sentRequestsTwo = sentRequests

		#expect(refreshedLogins.count == 1, "Token should be refreshed")
		#expect(refreshedLogins.first?.accessToken.value == "EXPIRE SOON", "Expired token should be passed to refresh call")
		#expect(refreshedLogins.first?.refreshToken?.value == "REFRESH", "Refresh token should be passed to refresh call")
		#expect(loadLoginCount == 2, "New login should be loaded from storage")
		#expect(sentRequestsTwo.count == 2, "Second request should be sent")
		let secondRequest = sentRequestsTwo.dropFirst().first
		#expect(secondRequest?.value(forHTTPHeaderField: "Authorization") == "Bearer REFRESHED", "Refreshed token should be used for second request")
		#expect(savedLogins.first?.accessToken.value == "REFRESHED", "Refreshed token should be saved to storage")

		let (_, _) = try await auth.response(for: URLRequest(url: URL(string: "https://example.com")!))
		let sentRequestsThree = sentRequests

		#expect(refreshedLogins.count == 1, "No additional refreshes should happen")
		#expect(loadLoginCount == 2, "No additional login loads should happen")
		#expect(sentRequestsThree.count == 3, "Third request should be sent")
		let thirdRequest = sentRequestsThree.dropFirst(2).first
		#expect(thirdRequest?.value(forHTTPHeaderField: "Authorization") == "Bearer REFRESHED", "Refreshed token should be used for third request")
		#expect(savedLogins.count == 1, "No additional logins should be saved to storage")
	}
}
