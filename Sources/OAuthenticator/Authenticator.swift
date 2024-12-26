import Foundation
import AuthenticationServices

public enum AuthenticatorError: Error, Hashable {
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
	case failingAuthenticatorUsed
	case dpopTokenExpected(String)
	case parRequestURIMissing
	case stateTokenMismatch(String, String)
}

/// Manage state required to executed authenticated URLRequests.
public actor Authenticator {
	public typealias UserAuthenticator = @Sendable (URL, String) async throws -> URL
    public typealias AuthenticationStatusHandler = (Result<Login, AuthenticatorError>) -> Void
    
	/// A `UserAuthenticator` that always fails. Useful as a placeholder
	/// for testing and for doing manual authentication with an external
	/// instance not available at configuration-creation time.
	@Sendable
	public static func failingUserAuthenticator(_ url: URL, _ user: String) throws -> URL {
		throw AuthenticatorError.failingAuthenticatorUsed
	}

	public enum UserAuthenticationMode: Hashable, Sendable {
		/// User authentication will be triggered on-demand.
		case automatic

		/// User authentication will only occur via an explicit call to `authenticate()`.
		///
		/// This is handy for controlling when users are prompted. It also makes it possible to handle situations where kicking a user out to the web is impossible.
		case manualOnly
	}

	struct PARResponse: Codable, Hashable, Sendable {
		public let requestURI: String
		public let expiresIn: Int

		enum CodingKeys: String, CodingKey {
			case requestURI = "request_uri"
			case expiresIn = "expires_in"
		}

		var expiry: Date {
			Date(timeIntervalSinceNow: Double(expiresIn))
		}
	}

	public struct Configuration {
		public let appCredentials: AppCredentials

		public let loginStorage: LoginStorage?
		public let tokenHandling: TokenHandling
		public let userAuthenticator: UserAuthenticator
		public let mode: UserAuthenticationMode

        // Specify an authenticationResult closure to obtain result and grantedScope
        public let authenticationStatusHandler: AuthenticationStatusHandler?

		@available(tvOS 16.0, macCatalyst 13.0, *)
		public init(
			appCredentials: AppCredentials,
			loginStorage: LoginStorage? = nil,
			tokenHandling: TokenHandling,
			mode: UserAuthenticationMode = .automatic,
			authenticationStatusHandler: AuthenticationStatusHandler? = nil
		) {
			self.appCredentials = appCredentials
			self.loginStorage = loginStorage
			self.tokenHandling = tokenHandling
			self.mode = mode

			// It *should* be possible to use just a reference to
			// ASWebAuthenticationSession.userAuthenticator directly here
			// with GlobalActorIsolatedTypesUsability, but it isn't working
			self.userAuthenticator = { try await ASWebAuthenticationSession.userAuthenticator(url: $0, scheme: $1) }
            self.authenticationStatusHandler = authenticationStatusHandler
		}

		public init(
			appCredentials: AppCredentials,
			loginStorage: LoginStorage? = nil,
			tokenHandling: TokenHandling,
			mode: UserAuthenticationMode = .automatic,
			userAuthenticator: @escaping UserAuthenticator,
			authenticationStatusHandler: AuthenticationStatusHandler? = nil
		) {
			self.appCredentials = appCredentials
			self.loginStorage = loginStorage
			self.tokenHandling = tokenHandling
			self.mode = mode
			self.userAuthenticator = userAuthenticator
            self.authenticationStatusHandler = authenticationStatusHandler
		}
	}

	let config: Configuration

	let urlLoader: URLResponseProvider
	private var activeTokenTask: Task<Login, Error>?
	private var localLogin: Login?
	private let pkce = PKCEVerifier()
	private var dpop = DPoPSigner()
	private let stateToken = UUID().uuidString

	public init(config: Configuration, urlLoader loader: URLResponseProvider? = nil) {
		self.config = config

		self.urlLoader = loader ?? URLSession.defaultProvider
	}

	/// A default `URLSession`-backed `URLResponseProvider`.
	@available(*, deprecated, message: "Please move to URLSession.defaultProvider")
	@MainActor
	public static let defaultResponseProvider: URLResponseProvider = {
		let session = URLSession(configuration: .default)

		return session.responseProvider
	}()

	/// Add authentication for `request`, execute it, and return its result.
	public func response(for request: URLRequest) async throws -> (Data, URLResponse) {
		let userAuthenticator = config.userAuthenticator

		let login = try await loginTaskResult(manual: false, userAuthenticator: userAuthenticator)

		let result = try await authedResponse(for: request, login: login)

		let action = try config.tokenHandling.responseStatusProvider(result)

		switch action {
		case .authorize:
			let newLogin = try await loginFromTask(task: Task {
				return try await performUserAuthentication(manual: false, userAuthenticator: userAuthenticator)
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

				return try await performUserAuthentication(manual: false, userAuthenticator: userAuthenticator)
			})

			return try await authedResponse(for: request, login: newLogin)
		case .valid:
			return result
		}
	}

	private func authedResponse(for request: URLRequest, login: Login) async throws -> (Data, URLResponse) {
		var authedRequest = request
		let token = login.accessToken.value

		if config.tokenHandling.dpopJWTGenerator == nil {
			authedRequest.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
		}

		return try await dpopResponse(for: authedRequest, login: login)
	}

	/// Manually perform user authentication, if required.
	public func authenticate(with userAuthenticator: UserAuthenticator? = nil) async throws {
		let _ = try await loginTaskResult(manual: true, userAuthenticator: userAuthenticator ?? config.userAuthenticator)
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
	private func makeLoginTask(manual: Bool, userAuthenticator: @escaping UserAuthenticator) -> Task<Login, Error> {
		return Task {
			guard let login = try await retrieveLogin() else {
				return try await performUserAuthentication(manual: manual, userAuthenticator: userAuthenticator)
			}

			if login.accessToken.valid {
				return login
			}

			if let refreshedLogin = try await refresh(with: login) {
				return refreshedLogin
			}

			return try await performUserAuthentication(manual: manual, userAuthenticator: userAuthenticator)
		}
	}

	private func loginTaskResult(manual: Bool, userAuthenticator: @escaping UserAuthenticator) async throws -> Login {
		let task = activeTokenTask ?? makeLoginTask(manual: manual, userAuthenticator: userAuthenticator)

        var login: Login
        do {
            do {
                login = try await loginFromTask(task: task)
            } catch AuthenticatorError.tokenInvalid {
                let newTask = makeLoginTask(manual: manual, userAuthenticator: userAuthenticator)
                login = try await loginFromTask(task: newTask)
            }

            // Inform authenticationResult closure of new login information
            self.config.authenticationStatusHandler?(.success(login))
        }
        catch let authenticatorError as AuthenticatorError {
            self.config.authenticationStatusHandler?(.failure(authenticatorError))

            // Rethrow error
            throw authenticatorError
        }
        
		return login
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

	private func performUserAuthentication(manual: Bool, userAuthenticator: UserAuthenticator) async throws -> Login {
		if manual == false && config.mode == .manualOnly {
			throw AuthenticatorError.manualAuthenticationRequired
		}

		let parRequestURI = try await getPARRequestURI()

		let authConfig = TokenHandling.AuthorizationURLParameters(
			credentials: config.appCredentials,
			pcke: pkce,
			parRequestURI: parRequestURI,
			stateToken: stateToken,
			responseProvider: { try await self.dpopResponse(for: $0, login: nil) }
		)

		let tokenURL = try await config.tokenHandling.authorizationURLProvider(authConfig)

		let scheme = try config.appCredentials.callbackURLScheme

		let	callbackURL = try await userAuthenticator(tokenURL, scheme)

		let params = TokenHandling.LoginProviderParameters(
			authorizationURL: tokenURL,
			credentials: config.appCredentials,
			redirectURL: callbackURL,
			responseProvider: { try await self.dpopResponse(for: $0, login: nil) },
			stateToken: stateToken,
			pcke: pkce
		)

		let login = try await config.tokenHandling.loginProvider(params)

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

		let login = try await refreshProvider(login, config.appCredentials, { try await self.dpopResponse(for: $0, login: nil) })

		try await storeLogin(login)

		return login
	}

	private func parRequest(url: URL, params: [String: String]) async throws -> PARResponse {
		let challenge = pkce.challenge
		let scopes = config.appCredentials.scopes.joined(separator: " ")
		let callbackURI = config.appCredentials.callbackURL
		let clientId = config.appCredentials.clientId

		var request = URLRequest(url: url)
		request.httpMethod = "POST"
		request.setValue("application/json", forHTTPHeaderField: "Accept")
		request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")

		let base: [String: String] = [
			"client_id": clientId,
			"state": stateToken,
			"scope": scopes,
			"response_type": "code",
			"redirect_uri": callbackURI.absoluteString,
			"code_challenge": challenge.value,
			"code_challenge_method": challenge.method,
		]

		let body = params
			.merging(base, uniquingKeysWith: { a, b in a })
			.map({ [$0, $1].joined(separator: "=") })
			.joined(separator: "&")

		request.httpBody = Data(body.utf8)

		let (parData, _) = try await dpopResponse(for: request, login: nil)

		return try JSONDecoder().decode(PARResponse.self, from: parData)
	}

	private func getPARRequestURI() async throws -> String? {
		guard let parConfig = config.tokenHandling.parConfiguration else {
			return nil
		}

		let parResponse = try await parRequest(url: parConfig.url, params: parConfig.parameters)

		return parResponse.requestURI
	}
}

extension Authenticator {
	public nonisolated var responseProvider: URLResponseProvider {
		{ try await self.response(for: $0) }
	}

	private func dpopResponse(for request: URLRequest, login: Login?) async throws -> (Data, URLResponse) {
		guard let generator = config.tokenHandling.dpopJWTGenerator else {
			return try await urlLoader(request)
		}

		let token = login?.accessToken.value
		let tokenHash = token.map { PKCEVerifier.computeHash($0) }

		return try await self.dpop.response(
			for: request,
			using: generator,
			token: token,
			tokenHash: tokenHash,
			issuingServer: login?.issuingServer,
			provider: urlLoader
		)
	}
}
