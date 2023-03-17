import Foundation

public enum GitHub {
	static let host = "github.com"

	struct AppAuthResponse: Codable, Hashable, Sendable {
		public let accessToken: String
		public let expiresIn: Int
		public let refreshToken: String
		public let refreshTokenExpiresIn: Int
		public let tokenType: String
		public let scope: String

		enum CodingKeys: String, CodingKey {
			case accessToken = "access_token"
			case expiresIn = "expires_in"
			case refreshToken = "refresh_token"
			case refreshTokenExpiresIn = "refresh_token_expires_in"
			case tokenType = "token_type"
			case scope
		}

		var login: Login {
			Login(accessToken: .init(value: accessToken, expiresIn: expiresIn),
				  refreshToken: .init(value: refreshToken, expiresIn: refreshTokenExpiresIn))
		}
	}

	public struct UserTokenParameters {
		public let state: String?
		public let login: String?
		public let allowSignup: Bool?

		public init(state: String? = nil, login: String? = nil, allowSignup: Bool? = nil) {
			self.state = state
			self.login = login
			self.allowSignup = allowSignup
		}
	}

	public static func tokenHandling(with parameters: UserTokenParameters = .init()) -> TokenHandling {
		TokenHandling(authorizationURLProvider: authorizationURLProvider(with: parameters),
					  loginProvider: loginProvider,
					  refreshProvider: refreshProvider)
	}

	static func authorizationURLProvider(with parameters: UserTokenParameters) -> TokenHandling.AuthorizationURLProvider {
		return { credentials in
			var urlBuilder = URLComponents()

			urlBuilder.scheme = "https"
			urlBuilder.host = host
			urlBuilder.path = "/login/oauth/authorize"
			urlBuilder.queryItems = [
				URLQueryItem(name: "client_id", value: credentials.clientId),
				URLQueryItem(name: "redirect_uri", value: credentials.callbackURL.absoluteString),
			]

			if let state = parameters.state {
				urlBuilder.queryItems?.append(URLQueryItem(name: "state", value: state))
			}

			guard let url = urlBuilder.url else {
				throw AuthenticatorError.missingAuthorizationURL
			}

			return url
		}
	}

	static func authenticationRequest(with url: URL, appCredentials: AppCredentials) throws -> URLRequest {
		let code = try url.accessCode

		var urlBuilder = URLComponents()

		urlBuilder.scheme = "https"
		urlBuilder.host = host
		urlBuilder.path = "/login/oauth/access_token"
		urlBuilder.queryItems = [
			URLQueryItem(name: "client_id", value: appCredentials.clientId),
			URLQueryItem(name: "client_secret", value: appCredentials.clientPassword),
			URLQueryItem(name: "redirect_uri", value: appCredentials.callbackURL.absoluteString),
			URLQueryItem(name: "code", value: code),
		]

		guard let url = urlBuilder.url else {
			throw AuthenticatorError.missingTokenURL
		}

		var request = URLRequest(url: url)

		request.httpMethod = "POST"
		request.setValue("application/json", forHTTPHeaderField: "Accept")

		return request
	}

	static func loginProvider(url: URL, credentials: AppCredentials, tokenURL: URL, urlLoader: URLResponseProvider) async throws -> Login {
		let request = try authenticationRequest(with: url, appCredentials: credentials)

		let (data, _) = try await urlLoader(request)

		let response = try JSONDecoder().decode(GitHub.AppAuthResponse.self, from: data)

		return response.login
	}

	static func refreshProvider(login: Login, credentials: AppCredentials, urlLoader: URLResponseProvider) async throws -> Login {
		throw AuthenticatorError.refreshUnsupported
	}
}
