import Foundation

/// Function that can execute a `URLRequest`.
///
/// This is used to abstract the actual networking system from the underlying authentication
/// mechanism.
public typealias URLResponseProvider = @Sendable (URLRequest) async throws -> (Data, URLResponse)
public typealias URLUserDataProvider<UserDataType: Sendable> = @Sendable (URLRequest) async throws -> (UserDataType, URLResponse)

public struct Token: Codable, Hashable, Sendable {
	public let value: String
	public let expiry: Date?

	public init(value: String, expiry: Date? = nil) {
		self.value = value
		self.expiry = expiry
	}

	public init(value: String, expiresIn seconds: Int) {
		self.value = value
		self.expiry = Date(timeIntervalSinceNow: TimeInterval(seconds))
	}

	public var valid: Bool {
		guard let date = expiry else { return true }

		return date.timeIntervalSinceNow > 0
	}
}

public struct Login: Codable, Hashable, Sendable {
	public var accessToken: Token
	public var refreshToken: Token?
    
    // User authorized scopes
    public var scopes: String?
    
    public init(accessToken: Token, refreshToken: Token? = nil, scopes: String? = nil) {
		self.accessToken = accessToken
		self.refreshToken = refreshToken
        self.scopes = scopes
	}

	public init(token: String, validUntilDate: Date? = nil) {
		self.init(accessToken: Token(value: token, expiry: validUntilDate))
	}
}

public struct AppCredentials: Hashable, Sendable {
	public var clientId: String
	public var clientPassword: String
	public var scopes: [String]
	public var callbackURL: URL

	public init(clientId: String, clientPassword: String, scopes: [String], callbackURL: URL) {
		self.clientId = clientId
		self.clientPassword = clientPassword
		self.scopes = scopes
		self.callbackURL = callbackURL
	}

	public var scopeString: String {
		return scopes.joined(separator: " ")
	}

	public var callbackURLScheme: String {
		get throws {
			guard let scheme = callbackURL.scheme else {
				throw AuthenticatorError.missingScheme
			}

			return scheme
		}
	}
}

public struct LoginStorage {
	public typealias RetrieveLogin = @Sendable () async throws -> Login?
	public typealias StoreLogin = @Sendable (Login) async throws -> Void

	public let retrieveLogin: RetrieveLogin
	public let storeLogin: StoreLogin

	public init(retrieveLogin: @escaping RetrieveLogin, storeLogin: @escaping StoreLogin) {
		self.retrieveLogin = retrieveLogin
		self.storeLogin = storeLogin
	}
}

public struct TokenHandling {
	public enum ResponseStatus: Hashable, Sendable {
		case valid
		case refresh
		case authorize
		case refreshOrAuthorize
	}

	public typealias AuthorizationURLProvider = @Sendable (AppCredentials) throws -> URL
	public typealias LoginProvider = @Sendable (URL, AppCredentials, URL, URLResponseProvider) async throws -> Login
	public typealias RefreshProvider = @Sendable (Login, AppCredentials, URLResponseProvider) async throws -> Login
	public typealias ResponseStatusProvider = @Sendable ((any Sendable, URLResponse)) throws -> ResponseStatus

	public let authorizationURLProvider: AuthorizationURLProvider
	public let loginProvider: LoginProvider
	public let refreshProvider: RefreshProvider?
	public let responseStatusProvider: ResponseStatusProvider

	public init(authorizationURLProvider: @escaping AuthorizationURLProvider,
				loginProvider: @escaping LoginProvider,
				refreshProvider: RefreshProvider? = nil,
				responseStatusProvider: @escaping ResponseStatusProvider = Self.refreshOrAuthorizeWhenUnauthorized) {
		self.authorizationURLProvider = authorizationURLProvider
		self.loginProvider = loginProvider
		self.refreshProvider = refreshProvider
		self.responseStatusProvider = responseStatusProvider
	}

	@Sendable
	public static func allResponsesValid<UserDataType: Sendable>(result: (UserDataType, URLResponse)) throws -> ResponseStatus {
		return .valid
	}

	@Sendable
	public static func refreshOrAuthorizeWhenUnauthorized<UserDataType: Sendable>(result: (UserDataType, URLResponse)) throws -> ResponseStatus {
		guard let response = result.1 as? HTTPURLResponse else {
			throw AuthenticatorError.httpResponseExpected
		}

		if response.statusCode == 401 {
			return .refresh
		}

		return .valid
	}
}
