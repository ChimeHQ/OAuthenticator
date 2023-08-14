import Foundation
import AuthenticationServices

public enum AuthenticatorError: Error {
	case missingScheme
	case missingAuthorizationCode
	case missingTokenURL
	case missingAuthorizationURL
	case refreshUnsupported
	case tokenInvalid
	case manualAuthenticationRequired
	case httpResponseExpected
	case unauthorizedRefreshFailed
	case missingRedirectURI
    case missingRefreshToken
    case missingScope
}

/// Manage state required to executed authenticated URLRequests.
public final class Authenticator {
	public typealias UserAuthenticator = (URL, String) async throws -> URL

	public enum UserAuthenticationMode: Hashable, Sendable {
		/// User authentication will be triggered on-demand.
		case automatic

		/// User authentication will only occur via an explicit call to `authenticate()`.
		///
		/// This is handy for controlling when users are prompted. It also makes it possible to handle situations where kicking a user out to the web is impossible.
		case manualOnly
	}

	public struct Configuration {
		public let appCredentials: AppCredentials

		public let loginStorage: LoginStorage?
		public let tokenHandling: TokenHandling
		public let userAuthenticator: UserAuthenticator
		public let mode: UserAuthenticationMode

		@available(tvOS 16.0, macCatalyst 13.0, *)
		public init(appCredentials: AppCredentials,
					loginStorage: LoginStorage? = nil,
					tokenHandling: TokenHandling,
					mode: UserAuthenticationMode = .automatic) {
			self.appCredentials = appCredentials
			self.loginStorage = loginStorage
			self.tokenHandling = tokenHandling
			self.mode = mode
			self.userAuthenticator = ASWebAuthenticationSession.userAuthenticator
		}

		public init(appCredentials: AppCredentials,
					loginStorage: LoginStorage? = nil,
					tokenHandling: TokenHandling,
					mode: UserAuthenticationMode = .automatic,
					userAuthenticator: @escaping UserAuthenticator) {
			self.appCredentials = appCredentials
			self.loginStorage = loginStorage
			self.tokenHandling = tokenHandling
			self.mode = mode
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

	/// A default `URLSession`-backed `URLResponseProvider`.
	public static let defaultResponseProvider: URLResponseProvider = {
		let session = URLSession(configuration: .default)

		return session.responseProvider
	}()

	/// Add authentication for `request`, execute it, and return its result.
	public func response(for request: URLRequest) async throws -> (Data, URLResponse) {
		let login = try await loginTaskResult(manual: false)

		let result = try await authedResponse(for: request, login: login)

		let action = try config.tokenHandling.responseStatusProvider(result)

		switch action {
		case .authorize:
			let newLogin = try await loginFromTask(task: Task {
				return try await performUserAuthentication(manual: false)
			})

			return try await authedResponse(for: request, login: newLogin)
		case .refresh:
			let newLogin = try await loginFromTask(task: Task {
				guard let value = try await refresh(with: login) else {
					throw AuthenticatorError.unauthorizedRefreshFailed
				}

				return value
			})

			return try await authedResponse(for: request, login: newLogin)
		case .refreshOrAuthorize:
			let newLogin = try await loginFromTask(task: Task {
				if let value = try await refresh(with: login) {
					return value
				}

				return try await performUserAuthentication(manual: false)
			})

			return try await authedResponse(for: request, login: newLogin)
		case .valid:
			return result
		}
	}

	private func authedResponse(for request: URLRequest, login: Login) async throws -> (Data, URLResponse) {
		var authedRequest = request
		let token = login.accessToken.value

		authedRequest.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")

		return try await urlLoader(authedRequest)
	}

	/// Manually perform user authentication, if required.
	public func authenticate() async throws {
		let _ = try await loginTaskResult(manual: true)
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
	private func makeLoginTask(manual: Bool) -> Task<Login, Error> {
		return Task {
			guard let login = try await retrieveLogin() else {
				return try await performUserAuthentication(manual: manual)
			}

			if login.accessToken.valid {
				return login
			}

			if let refreshedLogin = try await refresh(with: login) {
				return refreshedLogin
			}

			return try await performUserAuthentication(manual: manual)
		}
	}

	private func loginTaskResult(manual: Bool) async throws -> Login {
		let task = activeTokenTask ?? makeLoginTask(manual: manual)

		return try await loginFromTask(task: task)
	}

	private func loginFromTask(task: Task<Login, Error>) async throws -> Login {
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

	private func performUserAuthentication(manual: Bool) async throws -> Login {
		if manual == false && config.mode == .manualOnly {
			throw AuthenticatorError.manualAuthenticationRequired
		}

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
