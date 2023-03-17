import Foundation
import AuthenticationServices

public enum AuthenticatorError: Error {
	case missingScheme
	case missingLoginCode
	case missingTokenURL
	case missingAuthorizationURL
	case refreshUnsupported
	case tokenInvalid
}

public typealias URLResponseProvider = (URLRequest) async throws -> (Data, URLResponse)

@MainActor
public final class Authenticator {
	public typealias UserAuthenticator = (URL, String) async throws -> URL

	public struct Configuration {
		public let appCredentials: AppCredentials

		public let loginStorage: LoginStorage?
		public let tokenHandling: TokenHandling
		public let userAuthenticator: UserAuthenticator

		public init(appCredentials: AppCredentials,
					loginStorage: LoginStorage? = nil,
					tokenHandling: TokenHandling,
					userAuthenticator: @escaping UserAuthenticator = ASWebAuthenticationSession.webAuthenticator) {
			self.appCredentials = appCredentials
			self.loginStorage = loginStorage
			self.tokenHandling = tokenHandling
			self.userAuthenticator = userAuthenticator
		}
	}

	let config: Configuration
	let urlLoader: URLResponseProvider
	private var activeTokenTask: Task<Login, Error>?
	private var localLogin: Login?

	public init(config: Configuration, urlLoader loader: URLResponseProvider? = nil) {
		self.config = config

		self.urlLoader = loader ?? URLSession.defaultProvider
	}

	public static let defaultResponseProvider: URLResponseProvider = {
		let session = URLSession(configuration: .default)

		return session.responseProvider
	}()

	public func response(for request: URLRequest) async throws -> (Data, URLResponse) {
		let login = try await activeLogin()

		let (data, response) = try await authedResponse(for: request, login: login)

		// check for needed refresh here too

		return (data, response)
	}

	private func authedResponse(for request: URLRequest, login: Login) async throws -> (Data, URLResponse) {
		var authedRequest = request
		let token = login.accessToken.value

		authedRequest.setValue("bearer \(token)", forHTTPHeaderField: "Authorization")

		return try await urlLoader(authedRequest)
	}
}

extension Authenticator {
	private func retrieveLogin() async throws -> Login? {
		guard let storage = config.loginStorage else {
			return localLogin
		}

		return try await storage.retrieveLogin()
	}

	private func storeLogin(_ login: Login) async throws {
		guard let storage = config.loginStorage else {
			self.localLogin = login
			return
		}

		try await storage.storeLogin(login)
	}
}

extension Authenticator {
	private func makeLoginTask() -> Task<Login, Error> {
		return Task {
			guard let login = try await retrieveLogin() else {
				return try await authenticate()
			}

			if login.accessToken.valid {
				return login
			}

			if let refreshedLogin = try await refresh(with: login) {
				return refreshedLogin
			}

			return try await authenticate()
		}
	}

	public func activeLogin() async throws -> Login {
		let task = activeTokenTask ?? makeLoginTask()

		self.activeTokenTask = task

		let login: Login

		do {
			login = try await task.value
		} catch {
			// clear this value on error, but only if has not changed
			if task == self.activeTokenTask {
				self.activeTokenTask = nil
			}

			throw error
		}

		guard login.accessToken.valid else {
			throw AuthenticatorError.tokenInvalid
		}

		return login
	}

	private func authenticate() async throws -> Login {
		let codeURL = try config.tokenHandling.authorizationURLProvider(config.appCredentials)
		let scheme = try config.appCredentials.callbackURLScheme

		let	url = try await config.userAuthenticator(codeURL, scheme)
		let login = try await config.tokenHandling.loginProvider(url, config.appCredentials, codeURL, urlLoader)

		try await storeLogin(login)

		return login
	}

	private func refresh(with login: Login) async throws -> Login? {
		guard let refreshProvider = config.tokenHandling.refreshProvider else {
			return nil
		}

		guard let refreshToken = login.refreshToken else {
			return nil
		}

		guard refreshToken.valid else {
			return nil
		}

		let login = try await refreshProvider(login, config.appCredentials, urlLoader)

		try await storeLogin(login)

		return login
	}
}
