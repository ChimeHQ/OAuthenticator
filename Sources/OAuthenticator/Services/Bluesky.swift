import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// Find the spec here: https://atproto.com/specs/oauth
public enum Bluesky {
	struct TokenRequest: Hashable, Sendable, Codable {
		public let code: String
		public let code_verifier: String
		public let redirect_uri: String
		public let grant_type: String
		public let client_id: String

		public init(code: String, code_verifier: String, redirect_uri: String, grant_type: String, client_id: String) {
			self.code = code
			self.code_verifier = code_verifier
			self.redirect_uri = redirect_uri
			self.grant_type = grant_type
			self.client_id = client_id
		}
	}

	struct RefreshTokenRequest: Hashable, Sendable, Codable {
		public let refresh_token: String
		public let redirect_uri: String
		public let grant_type: String
		public let client_id: String

		public init(refresh_token: String, redirect_uri: String, grant_type: String, client_id: String) {
			self.refresh_token = refresh_token
			self.redirect_uri = redirect_uri
			self.grant_type = grant_type
			self.client_id = client_id
		}
	}

	struct TokenResponse: Hashable, Sendable, Codable {
		public let access_token: String
		public let refresh_token: String?
		public let sub: String
		public let scope: String
		public let token_type: String
		public let expires_in: Int

		public func login(for issuingServer: String) -> Login {
			Login(
				accessToken: Token(value: access_token, expiresIn: expires_in),
				refreshToken: refresh_token.map { Token(value: $0) },
				scopes: scope,
				issuingServer: issuingServer
			)
		}
	}

	public static func tokenHandling(
		account: String?,
		server: ServerMetadata,
		jwtGenerator: @escaping DPoPSigner.JWTGenerator,
		pkce: PKCEVerifier
	) -> TokenHandling {
		TokenHandling(
			parConfiguration: PARConfiguration(
				url: URL(string: server.pushedAuthorizationRequestEndpoint)!,
				parameters: { if let account { ["login_hint": account] } else { [:] } }()
			),
			authorizationURLProvider: authorizionURLProvider(server: server),
			loginProvider: loginProvider(server: server),
			refreshProvider: refreshProvider(server: server),
			dpopJWTGenerator: jwtGenerator,
			pkce: pkce
		)
	}

#if canImport(CryptoKit)
	public static func tokenHandling(
		account: String?,
		server: ServerMetadata,
		jwtGenerator: @escaping DPoPSigner.JWTGenerator
	) -> TokenHandling {
		tokenHandling(
			account: account,
			server: server,
			jwtGenerator: jwtGenerator,
			pkce: PKCEVerifier()
		)
	}
#endif

	private static func authorizionURLProvider(server: ServerMetadata) -> TokenHandling.AuthorizationURLProvider {
		return { params in
			var components = URLComponents(string: server.authorizationEndpoint)

			guard let parRequestURI = params.parRequestURI else {
				throw AuthenticatorError.parRequestURIMissing
			}

			components?.queryItems = [
				URLQueryItem(name: "request_uri", value: parRequestURI),
				URLQueryItem(name: "client_id", value: params.credentials.clientId),
			]

			guard let url = components?.url else {
				throw AuthenticatorError.missingAuthorizationURL
			}

			return url
		}
	}

	private static func loginProvider(server: ServerMetadata) -> TokenHandling.LoginProvider {
		return { params in
			// decode the params in the redirectURL
			guard let redirectComponents = URLComponents(url: params.redirectURL, resolvingAgainstBaseURL: false) else {
				throw AuthenticatorError.missingTokenURL
			}

			guard
				let authCode = redirectComponents.queryItems?.first(where: { $0.name == "code" })?.value,
				let iss = redirectComponents.queryItems?.first(where: { $0.name == "iss" })?.value,
				let state = redirectComponents.queryItems?.first(where: { $0.name == "state" })?.value
			else {
				throw AuthenticatorError.missingAuthorizationCode
			}

			if state != params.stateToken {
				throw AuthenticatorError.stateTokenMismatch(state, params.stateToken)
			}

			// and use them (plus just a little more) to construct the token request
			guard let tokenURL = URL(string: server.tokenEndpoint) else {
				throw AuthenticatorError.missingTokenURL
			}
			
			guard let verifier = params.pcke?.verifier else {
				throw AuthenticatorError.pkceRequired
			}

			let tokenRequest = TokenRequest(
				code: authCode,
				code_verifier: verifier,
				redirect_uri: params.credentials.callbackURL.absoluteString,
				grant_type: "authorization_code",
				client_id: params.credentials.clientId // is this field truly necessary?
			)

			var request = URLRequest(url: tokenURL)

			request.httpMethod = "POST"
			request.setValue("application/json", forHTTPHeaderField: "Content-Type")
			request.httpBody = try JSONEncoder().encode(tokenRequest)

			let (data, response) = try await params.responseProvider(request)

			print("data:", String(decoding: data, as: UTF8.self))
			print("response:", response)

			let tokenResponse = try JSONDecoder().decode(TokenResponse.self, from: data)

			guard tokenResponse.token_type == "DPoP" else {
				throw AuthenticatorError.dpopTokenExpected(tokenResponse.token_type)
			}

			return tokenResponse.login(for: iss)
		}
	}

	private static func refreshProvider(server: ServerMetadata) -> TokenHandling.RefreshProvider {
		{ login, credentials, responseProvider -> Login in
			guard let refreshToken = login.refreshToken?.value else {
				throw AuthenticatorError.refreshNotPossible
			}

			guard let tokenURL = URL(string: server.tokenEndpoint) else {
				throw AuthenticatorError.missingTokenURL
			}

			let tokenRequest = RefreshTokenRequest(
				refresh_token: refreshToken,
				redirect_uri: credentials.callbackURL.absoluteString,
				grant_type: "refresh_token",
				client_id: credentials.clientId // is this field truly necessary?
			)

			var request = URLRequest(url: tokenURL)

			request.httpMethod = "POST"
			request.setValue("application/json", forHTTPHeaderField: "Content-Type")
			request.httpBody = try JSONEncoder().encode(tokenRequest)

			let (data, response) = try await responseProvider(request)

			// make sure that we got a successful HTTP response
			guard
				let httpResponse = response as? HTTPURLResponse,
				httpResponse.statusCode >= 200 && httpResponse.statusCode < 300
			else {
				print("data:", String(decoding: data, as: UTF8.self))
				print("response:", response)
				
				throw AuthenticatorError.refreshNotPossible
			}

			let tokenResponse = try JSONDecoder().decode(TokenResponse.self, from: data)

			guard tokenResponse.token_type == "DPoP" else {
				throw AuthenticatorError.dpopTokenExpected(tokenResponse.token_type)
			}

			return tokenResponse.login(for: server.issuer)
		}
	}
}
