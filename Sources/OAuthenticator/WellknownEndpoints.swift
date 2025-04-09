import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

enum MetadataError: Error {
	case urlInvalid
}

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

	public static func load(for host: String, provider: URLResponseProvider) async throws -> ServerMetadata {
		var components = URLComponents()

		components.scheme = "https"
		components.host = host
		components.path = "/.well-known/oauth-authorization-server"
		components.queryItems = [
			URLQueryItem(name: "Accept", value: "application/json")
		]

		guard let url = components.url else {
			throw MetadataError.urlInvalid
		}

		let (data, _) = try await provider(URLRequest(url: url))

		return try JSONDecoder().decode(ServerMetadata.self, from: data)
	}
}

public struct ClientMetadata: Hashable, Codable, Sendable {
	public let clientId: String
	public let scope: String
	public let redirectURIs: [String]
	public let dpopBoundAccessTokens: Bool

	enum CodingKeys: String, CodingKey {
		case clientId = "client_id"
		case scope
		case redirectURIs = "redirect_uris"
		case dpopBoundAccessTokens = "dpop_bound_access_tokens"
	}

	public static func load(for endpoint: String, provider: URLResponseProvider) async throws -> ClientMetadata {
		guard let url = URL(string: endpoint) else {
			throw MetadataError.urlInvalid
		}

		let (data, _) = try await provider(URLRequest(url: url))

		return try JSONDecoder().decode(ClientMetadata.self, from: data)
	}
}

extension ClientMetadata {
	public var credentials: AppCredentials {
		let url = redirectURIs.first.map({ URL(string: $0)! })!

		return AppCredentials(
			clientId: clientId,
			clientPassword: "",
			scopes: scope.components(separatedBy: " "),
			callbackURL: url
		)
	}
}
