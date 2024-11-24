import Foundation

import CryptoKit

struct PKCE: Hashable, Sendable {
	let verifier: String
	let challenge: String
	let method: String
	
	init() {
		self.method = "S256"
		self.verifier = UUID().uuidString
		self.challenge = Self.computeHash(verifier)
	}
	
	static func computeHash(_ value: String) -> String {
		let digest = SHA256.hash(data: Data(value.utf8))

		return digest.map { String(format: "%02X", $0) }.joined()
	}
	
	func validate(_ value: String) -> Bool {
		Self.computeHash(value) == verifier
	}
}

/// Find the spec here: https://atproto.com/specs/oauth
public enum Bluesky {
	public struct ServerMetadata: Codable, Hashable, Sendable {
		public let issuer: String
		public let authorizationEndpoint: String
		public let tokenEndpoint: String
		public let responseTypesSupported: [String]
		public let grantTypesSupported: [String]
		public let codeChallengeMethodsSupported: [String]
		public let tokenEndpointAuthMethodsSupported: [String]
		public let tokenEndpointAuthSigningAlgValuesSupported: [String]
		public let scopesSupported: [String]
		public let authorizationResponseIssParameterSupported: Bool
		public let requirePushedAuthorizationRequests: Bool
		public let pushedAuthorizationRequestEndpoint: String
		public let dpopSigningAlgValuesSupported: [String]
		public let requireRequestUriRegistration: Bool
		public let clientIdMetadataDocumentSupported: Bool
		
		enum CodingKeys: String, CodingKey {
			case issuer
			case authorizationEndpoint = "authorization_endpoint"
			case tokenEndpoint = "token_endpoint"
			case responseTypesSupported = "response_types_supported"
			case grantTypesSupported = "grant_types_supported"
			case codeChallengeMethodsSupported = "code_challenge_methods_supported"
			case tokenEndpointAuthMethodsSupported = "token_endpoint_auth_methods_supported"
			case tokenEndpointAuthSigningAlgValuesSupported = "token_endpoint_auth_signing_alg_values_supported"
			case scopesSupported = "scopes_supported"
			case authorizationResponseIssParameterSupported = "authorization_response_iss_parameter_supported"
			case requirePushedAuthorizationRequests = "require_pushed_authorization_requests"
			case pushedAuthorizationRequestEndpoint = "pushed_authorization_request_endpoint"
			case dpopSigningAlgValuesSupported = "dpop_signing_alg_values_supported"
			case requireRequestUriRegistration = "require_request_uri_registration"
			case clientIdMetadataDocumentSupported = "client_id_metadata_document_supported"
		}
	}
	
	public struct ClientConfiguration: Hashable, Sendable {
		public let clientId: String
		public let callbackURI: String
		
		public init(clientId: String, callbackURI: String) {
			self.clientId = clientId
			self.callbackURI = callbackURI
		}
	}
	
	public struct AuthorizationURLRequest: Codable, Hashable, Sendable {
		
	}

	struct PARResponse: Codable, Hashable, Sendable {
		let request_uri: String
		let expires_in: Int
	}
	
	public struct AuthorizationURLResponse: Hashable, Sendable {
		public let requestURI: String
		public let expiry: Date
		let nonce: String
		let pkce: PKCE
		
		public func validateState(_ state: String) -> Bool {
			pkce.validate(state)
		}
	}
	
	public static func serverConfiguration(for host: String, provider: URLResponseProvider) async throws -> ServerMetadata {
		var components = URLComponents()
		
		components.scheme = "https"
		components.host = host
		components.path = "/.well-known/oauth-authorization-server"
		components.queryItems = [
			URLQueryItem(name: "Accept", value: "application/json")
		]
		
		guard let url = components.url else {
			throw AuthenticatorError.missingAuthorizationURL
		}
		
		let (data, _) = try await provider(URLRequest(url: url))
		
		return try JSONDecoder().decode(ServerMetadata.self, from: data)
	}
	
	public static func pushAuthorizationRequest(clientConfig: ClientConfiguration, hint: String, metadata: ServerMetadata, provider: URLResponseProvider) async throws -> AuthorizationURLResponse {
		guard let url = URL(string: metadata.pushedAuthorizationRequestEndpoint) else {
			throw AuthenticatorError.missingAuthorizationURL
		}
		
		let state = UUID().uuidString
		let pkce = PKCE()
		
		var request = URLRequest(url: url)
		request.httpMethod = "POST"
		request.setValue("application/json", forHTTPHeaderField: "Accept")
		request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
		
		let body = [
			"client_id=\(clientConfig.clientId)",
			"state=\(state)",
			"scopes=atproto",
			"response_type=code",
			"redirect_uri=\(clientConfig.callbackURI)",
			"code_challenge=\(pkce.challenge)",
			"code_challenge_method=\(pkce.method)",
			"login_hint=\(hint)",
		].joined(separator: "&")
		
		request.httpBody = Data(body.utf8)
		
		let (data, response) = try await provider(request)
		
		guard let httpResponse = response as? HTTPURLResponse else {
			print("data:", String(decoding: data, as: UTF8.self))
			
			throw AuthenticatorError.httpResponseExpected
		}
		
		let nonce = httpResponse.value(forHTTPHeaderField: "dpop-nonce") ?? ""
		
		let parResponse = try JSONDecoder().decode(PARResponse.self, from: data)
		
		return AuthorizationURLResponse(
			requestURI: parResponse.request_uri,
			expiry: Date(timeIntervalSinceNow: Double(parResponse.expires_in)),
			nonce: nonce,
			pkce: pkce
		)
	}
	
//	public static func tokenHandling(with server: String) -> TokenHandling {
//		TokenHandling(
//			authorizationURLProvider: authorizationURLProvider(with: server),
//			loginProvider: loginProvider,
//			refreshProvider: refreshProvider
//		)
//	}
//	
//	static func authorizationURLProvider(with server: String) -> TokenHandling.AuthorizationURLProvider {
//		return { credentials, provider in
//			
//			var components = URLComponents()
//			
//			components.scheme = "https"
//			components.host = server
//			components.path = "/.well-known/oauth-authorization-server"
//			components.queryItems = [
//				URLQueryItem(name: "Accept", value: "application/json")
//			]
//			
//			guard let url = components.url else {
//				throw AuthenticatorError.missingAuthorizationURL
//			}
//			
//			let (data, _) = try await provider(URLRequest(url: url))
//			
//			let response = try JSONDecoder().decode(AuthorizationServerResponse.self, from: data)
//			
//			print(response)
//			
////			var urlBuilder = URLComponents()
////
////			urlBuilder.scheme = "https"
////			urlBuilder.host = host
////			urlBuilder.path = "/login/oauth/authorize"
////			urlBuilder.queryItems = [
////				URLQueryItem(name: "client_id", value: credentials.clientId),
////				URLQueryItem(name: "redirect_uri", value: credentials.callbackURL.absoluteString),
////				URLQueryItem(name: "scope", value: credentials.scopeString),
////			]
////
////			if let state = parameters.state {
////				urlBuilder.queryItems?.append(URLQueryItem(name: "state", value: state))
////			}
////
////			guard let url = urlBuilder.url else {
//				throw AuthenticatorError.missingAuthorizationURL
////			}
//
////			return url
//		}
//	}
//	
//	@Sendable
//	static func loginProvider(url: URL, credentials: AppCredentials, tokenURL: URL, urlLoader: URLResponseProvider) async throws -> Login {
//		throw AuthenticatorError.missingAuthorizationURL
////		let request = try authenticationRequest(with: url, appCredentials: credentials)
////
////		let (data, _) = try await urlLoader(request)
////
////		let response = try JSONDecoder().decode(GitHub.AppAuthResponse.self, from: data)
////
////		return response.login
//	}
//
//	@Sendable
//	static func refreshProvider(login: Login, credentials: AppCredentials, urlLoader: URLResponseProvider) async throws -> Login {
//		// TODO: will have to figure this out
//		throw AuthenticatorError.refreshUnsupported
//	}
}
