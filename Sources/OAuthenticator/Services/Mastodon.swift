import Foundation

public struct Mastodon {

	public static let scheme: String = "https"
	static let authorizePath: String = "/oauth/authorize"
	static let tokenPath: String = "/oauth/token"
	static let appRegistrationPath: String = "/api/v1/apps"

	static let clientNameKey: String = "client_name"
	static let clientIDKey: String = "client_id"
	static let clientSecretKey: String = "client_secret"
	static let redirectURIKey: String = "redirect_uri"
	static let redirectURIsKey: String = "redirect_uris"
	static let responseTypeKey: String = "response_type"
	static let scopeKey: String = "scope"
	static let scopesKey: String = "scopes"
	static let codeKey: String = "code"
	static let grantTypeKey: String = "grant_type"
	static let grantTypeAuthorizationCode: String = "authorization_code"
	static let responseTypeCode: String = "code"

	struct AppAuthResponse: Codable, Hashable, Sendable {
		public let accessToken: String
		public let scope: String
		public let tokenType: String
		public let createdAt: Int

		enum CodingKeys: String, CodingKey {
			case accessToken = "access_token"
			case scope
			case tokenType = "token_type"
			case createdAt = "created_at"
		}

		var login: Login {
			Login(accessToken: .init(value: accessToken))
		}
	}

	public struct AppRegistrationResponse: Codable {
		let id: String
		public let client_id: String
		public let client_secret: String
		public let redirect_uri: String?

		let name: String?
		let website: String?
		let vapid_key: String?
	}

	public struct UserTokenParameters {
		public let host: String
		public let clientName: String
		public let redirectURI: String
		public let scopes: [String]

		public init(host: String, clientName: String, redirectURI: String, scopes: [String]) {
			self.host = host
			self.clientName = clientName
			self.redirectURI = redirectURI
			self.scopes = scopes
		}
	}

	public static func tokenHandling(with parameters: UserTokenParameters) -> TokenHandling {
		TokenHandling(authorizationURLProvider: authorizationURLProvider(with: parameters),
					  loginProvider: loginProvider(with: parameters),
					  refreshProvider: refreshProvider(with: parameters))
	}

	static func authorizationURLProvider(with parameters: UserTokenParameters) -> TokenHandling.AuthorizationURLProvider {
		return { credentials in
			var urlBuilder = URLComponents()

			urlBuilder.scheme = Mastodon.scheme
			urlBuilder.host = parameters.host
			urlBuilder.path = Mastodon.authorizePath
			urlBuilder.queryItems = [
				URLQueryItem(name: Mastodon.clientIDKey, value: credentials.clientId),
				URLQueryItem(name: Mastodon.redirectURIKey, value: credentials.callbackURL.absoluteString),
				URLQueryItem(name: Mastodon.responseTypeKey, value: Mastodon.responseTypeCode),
				URLQueryItem(name: Mastodon.scopeKey, value: credentials.scopeString)
			]

			guard let url = urlBuilder.url else {
				throw AuthenticatorError.missingAuthorizationURL
			}

			return url
		}
	}

	static func authenticationRequest(with parameters: UserTokenParameters, url: URL, appCredentials: AppCredentials) throws -> URLRequest {
		let code = try url.authorizationCode

		var urlBuilder = URLComponents()

		urlBuilder.scheme = Mastodon.scheme
		urlBuilder.host = parameters.host
		urlBuilder.path = Mastodon.tokenPath
		urlBuilder.queryItems = [
			URLQueryItem(name: Mastodon.grantTypeKey, value: Mastodon.grantTypeAuthorizationCode),
			URLQueryItem(name: Mastodon.clientIDKey, value: appCredentials.clientId),
			URLQueryItem(name: Mastodon.clientSecretKey, value: appCredentials.clientPassword),
			URLQueryItem(name: Mastodon.redirectURIKey, value: appCredentials.callbackURL.absoluteString),
			URLQueryItem(name: Mastodon.codeKey, value: code),
			URLQueryItem(name: Mastodon.scopeKey, value: appCredentials.scopeString)
		]

		guard let url = urlBuilder.url else {
			throw AuthenticatorError.missingTokenURL
		}

		var request = URLRequest(url: url)

		request.httpMethod = "POST"
		request.setValue("application/json", forHTTPHeaderField: "Accept")

		return request
	}

	static func loginProvider(with parameters: UserTokenParameters) -> TokenHandling.LoginProvider {
		return { url, appCredentials, tokenURL, urlLoader in
			let request = try authenticationRequest(with: parameters, url: url, appCredentials: appCredentials)

			let (data, _) = try await urlLoader(request)

			let response = try JSONDecoder().decode(Mastodon.AppAuthResponse.self, from: data)

			return response.login
		}
	}

	static func refreshProvider(with parameters: UserTokenParameters) -> TokenHandling.RefreshProvider {
		return { login, appCredentials, urlResponseProvider in
			throw AuthenticatorError.refreshUnsupported
		}
	}

	public static func register(with parameters: UserTokenParameters) async throws -> AppRegistrationResponse {
		var urlBuilder = URLComponents()

		urlBuilder.scheme = Mastodon.scheme
		urlBuilder.host = parameters.host
		urlBuilder.path = Mastodon.appRegistrationPath
		urlBuilder.queryItems = [
			URLQueryItem(name: Mastodon.clientNameKey, value: parameters.clientName),
			URLQueryItem(name: Mastodon.redirectURIsKey, value: parameters.redirectURI),
			URLQueryItem(name: Mastodon.scopesKey, value: parameters.scopes.joined(separator: " "))
		]

		guard let url = urlBuilder.url else {
			throw AuthenticatorError.missingTokenURL
		}

		var request = URLRequest(url: url)
		request.httpMethod = "POST"

		let (data, _) = try await URLSession.shared.data(for: request)
		let registrationResponse = try JSONDecoder().decode(AppRegistrationResponse.self, from: data)
		return registrationResponse
	}
}
