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

	public struct TokenResponse: Hashable, Sendable, Codable {
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

		public var accessToken: String { access_token }
		public var refreshToken: String? { refresh_token }
		public var tokenType: String { token_type }
		public var expiresIn: Int { expires_in }
	}

	public typealias TokenSubscriberValidator = @Sendable (TokenResponse, _ issuer: String) async throws -> Bool

	public static func tokenHandling(
		account: String?,
		server: ServerMetadata,
		jwtGenerator: @escaping DPoPSigner.JWTGenerator,
		pkce: PKCEVerifier,
		validator: @escaping TokenSubscriberValidator
	) -> TokenHandling {
		TokenHandling(
			parConfiguration: PARConfiguration(
				url: URL(string: server.pushedAuthorizationRequestEndpoint)!,
				parameters: { if let account { ["login_hint": account] } else { [:] } }()
			),
			authorizationURLProvider: authorizionURLProvider(server: server),
			loginProvider: loginProvider(server: server, validator: validator),
			refreshProvider: refreshProvider(server: server, validator: validator),
			dpopJWTGenerator: jwtGenerator,
			pkce: pkce
		)
	}

#if canImport(CryptoKit)
	public static func tokenHandling(
		account: String?,
		server: ServerMetadata,
		jwtGenerator: @escaping DPoPSigner.JWTGenerator,
		validator: @escaping TokenSubscriberValidator
	) -> TokenHandling {
		tokenHandling(
			account: account,
			server: server,
			jwtGenerator: jwtGenerator,
			pkce: PKCEVerifier(),
			validator: validator
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

	private static func loginProvider(
		server: ServerMetadata, validator: @escaping TokenSubscriberValidator
	) -> TokenHandling.LoginProvider {
		return { params in
			// decode the params in the redirectURL
			guard
				let redirectComponents = URLComponents(
					url: params.redirectURL, resolvingAgainstBaseURL: false)
			else {
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

			if iss != server.issuer {
				throw AuthenticatorError.issuingServerMismatch(iss, server.issuer)
			}

			guard let verifier = params.pcke?.verifier else {
				throw AuthenticatorError.pkceRequired
			}

			let tokenRequest = TokenRequest(
				code: authCode,
				code_verifier: verifier,
				redirect_uri: params.credentials.callbackURL.absoluteString,
				grant_type: "authorization_code",
				client_id: params.credentials.clientId
			)

			return try await Bluesky.requestToken(
				tokenRequest,
				authorizationServer: server,
				validator: validator,
				responseProvider: params.responseProvider
			)
		}
	}

	private static func refreshProvider(
		server: ServerMetadata, validator: @escaping TokenSubscriberValidator
	) -> TokenHandling.RefreshProvider {
		{ login, credentials, responseProvider -> Login in
			guard let refreshToken = login.refreshToken?.value else {
				throw AuthenticatorError.refreshNotPossible
			}

			let tokenRequest = RefreshTokenRequest(
				refresh_token: refreshToken,
				redirect_uri: credentials.callbackURL.absoluteString,
				grant_type: "refresh_token",
				client_id: credentials.clientId
			)

			return try await Bluesky.requestToken(
				tokenRequest,
				authorizationServer: server,
				validator: validator,
				responseProvider: responseProvider
			)
		}
	}

	private static func requestToken(
		_ tokenRequest: Encodable,
		authorizationServer: ServerMetadata,
		validator: @escaping TokenSubscriberValidator,
		responseProvider: URLResponseProvider
	) async throws -> Login {
		guard let tokenURL = URL(string: authorizationServer.tokenEndpoint) else {
			throw AuthenticatorError.missingTokenURL
		}

		var request = URLRequest(url: tokenURL)

		request.httpMethod = "POST"
		request.setValue("application/json", forHTTPHeaderField: "Content-Type")
		request.setValue("application/json", forHTTPHeaderField: "Accept")
		request.httpBody = try JSONEncoder().encode(tokenRequest)

		let (data, response) = try await responseProvider(request)

		guard
			let httpResponse = response as? HTTPURLResponse,
			httpResponse.statusCode >= 200 && httpResponse.statusCode < 300
		else {
			if let error = try? JSONDecoder().decode(OAuthErrorResponse.self, from: data) {
				switch error.error {
				case "invalid_request":
					throw AuthenticatorError.invalidRequest(error.error, error.errorDescription ?? "")
				case "invalid_grant":
					throw AuthenticatorError.invalidGrant(error.error, error.errorDescription ?? "")
				default:
					throw AuthenticatorError.unrecognizedError(error.error, error.errorDescription ?? "")
				}
			}

			throw AuthenticatorError.unrecognizedError(
				"unknown_response", "Received an unexpected response from the authorization server")
		}

		guard let tokenResponse = try? JSONDecoder().decode(TokenResponse.self, from: data) else {
			throw AuthenticatorError.unrecognizedError("invalid_json", "Decoding response JSON")
		}

		guard tokenResponse.token_type == "DPoP" else {
			throw AuthenticatorError.dpopTokenExpected(tokenResponse.token_type)
		}

		if try await validator(tokenResponse, authorizationServer.issuer) == false {
			throw AuthenticatorError.tokenInvalid
		}

		return tokenResponse.login(for: authorizationServer.issuer)
	}
}
