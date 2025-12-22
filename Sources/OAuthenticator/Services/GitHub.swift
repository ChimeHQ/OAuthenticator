import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// OAuth details for github.com
///
/// GitHub supports two different kinds of integrations, called "OAuth Apps" and "GitHub Apps". Make sure to check which kind you need, as they differ in their authentication requirements.
///
/// Check out https://docs.github.com/en/apps/creating-github-apps/creating-github-apps/differences-between-github-apps-and-oauth-apps
public enum GitHub {
	static let host = "github.com"

	struct AppAuthResponse: Codable, Hashable, Sendable {
		let accessToken: String
		let expiresIn: Int
		let refreshToken: String
		let refreshTokenExpiresIn: Int
		let tokenType: String
		let scope: String

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

	struct OAuthResponse: Codable, Hashable, Sendable {
		let accessToken: String
		let tokenType: String
		let scope: String

		enum CodingKeys: String, CodingKey {
			case accessToken = "access_token"
			case tokenType = "token_type"
			case scope
		}

		var login: Login {
			Login(token: accessToken)
		}
	}

	public struct UserTokenParameters: Sendable {
		public let state: String?
		public let login: String?
		public let allowSignup: Bool?

		public init(state: String? = nil, login: String? = nil, allowSignup: Bool? = nil) {
			self.state = state
			self.login = login
			self.allowSignup = allowSignup
		}
	}

	/// TokenHandling for GitHub Apps
	public static func gitHubAppTokenHandling(with parameters: UserTokenParameters = .init()) -> TokenHandling {
		TokenHandling(
			authorizationURLProvider: authorizationURLProvider(with: parameters),
			loginProvider: gitHubAppLoginProvider,
			refreshProvider: refreshProvider
		)
	}

	/// TokenHandling for OAuth Apps
	public static func OAuthAppTokenHandling() -> TokenHandling {
		TokenHandling(
			authorizationURLProvider: authorizationURLProvider(with: .init()),
			loginProvider: OAuthAppLoginProvider
		)
	}

	static func authorizationURLProvider(with parameters: UserTokenParameters) -> TokenHandling.AuthorizationURLProvider {
		return { params in
			let credentials = params.credentials
			
			var urlBuilder = URLComponents()

			urlBuilder.scheme = "https"
			urlBuilder.host = host
			urlBuilder.path = "/login/oauth/authorize"
			urlBuilder.queryItems = [
				URLQueryItem(name: "client_id", value: credentials.clientId),
				URLQueryItem(name: "redirect_uri", value: credentials.callbackURL.absoluteString),
				URLQueryItem(name: "scope", value: credentials.scopeString),
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
		let code = try url.authorizationCode

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

	@Sendable
	static func gitHubAppLoginProvider(params: TokenHandling.LoginProviderParameters) async throws -> Login {
		let request = try authenticationRequest(with: params.authorizationURL, appCredentials: params.credentials)

		let (data, _) = try await params.responseProvider(request)

		let response = try JSONDecoder().decode(GitHub.AppAuthResponse.self, from: data)

		return response.login
	}

	@Sendable
	static func OAuthAppLoginProvider(params: TokenHandling.LoginProviderParameters) async throws -> Login {
		let request = try authenticationRequest(with: params.authorizationURL, appCredentials: params.credentials)

		let (data, _) = try await params.responseProvider(request)

		let response = try JSONDecoder().decode(GitHub.OAuthResponse.self, from: data)

		return response.login
	}

	@Sendable
	static func refreshProvider(login: Login, credentials: AppCredentials, urlLoader: URLResponseProvider) async throws -> Login {
		// TODO: GitHub Apps actually do support refresh
		throw AuthenticatorError.refreshUnsupported
	}
}
