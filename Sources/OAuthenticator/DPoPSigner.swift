import Foundation

#if canImport(FoundationNetworking)
	import FoundationNetworking
#endif

public final class NonceValue {
	public let origin: String
	public let nonce: String

	init(origin: String, nonce: String) {
		self.origin = origin
		self.nonce = nonce
	}
}

extension NSCache where KeyType == NSString, ObjectType == NonceValue {
	subscript(_ url: URL) -> String? {
		get {
			let key = url.origin
			guard let key = key else {
				return nil
			}
			let value = object(forKey: key as NSString)
			return value?.nonce
		}
		set {
			let key = url.origin
			guard let key = key else {
				return
			}

			if let entry = newValue {
				let value = NonceValue(origin: key, nonce: entry)
				setObject(value, forKey: key as NSString)
			} else {
				removeObject(forKey: key as NSString)
			}
		}
	}
}

public struct DPoPRequestPayload: Codable, Hashable, Sendable {
	public let uniqueCode: String
	public let httpMethod: String
	public let httpRequestURL: String
	/// UNIX type, seconds since epoch
	public let createdAt: Int
	/// UNIX type, seconds since epoch
	public let expiresAt: Int
	public let nonce: String?
	public let accessTokenHash: String?

	public enum CodingKeys: String, CodingKey {
		case uniqueCode = "jti"
		case httpMethod = "htm"
		case httpRequestURL = "htu"
		case createdAt = "iat"
		case expiresAt = "exp"
		case nonce
		case accessTokenHash = "ath"
	}

	public init(
		httpMethod: String,
		httpRequestURL: String,
		createdAt: Int,
		expiresAt: Int,
		nonce: String,
		authorizationServerIssuer: String,
		accessTokenHash: String
	) {
		self.uniqueCode = UUID().uuidString
		self.httpMethod = httpMethod
		self.httpRequestURL = httpRequestURL
		self.createdAt = createdAt
		self.expiresAt = expiresAt
		self.nonce = nonce
		self.accessTokenHash = accessTokenHash
	}
}

public enum DPoPError: Error, Equatable {
	case requestInvalid(URLRequest)
}

/// Manages state and operations for OAuth Demonstrating Proof-of-Possession (DPoP).
///
/// Currently only uses ES256.
///
/// Details here: https://datatracker.ietf.org/doc/html/rfc9449
public final class DPoPSigner {
	public struct JWTParameters: Sendable, Hashable {
		public let keyType: String

		public let httpMethod: String
		public let requestEndpoint: String
		public let nonce: String?
		public let tokenHash: String?
	}

	public typealias JWTGenerator = @Sendable (JWTParameters) async throws -> String

	// Return value is (origin, nonce)
	public typealias NonceDecoder = (Data, HTTPURLResponse) throws -> NonceValue?
	private let nonceCache: NSCache<NSString, NonceValue> = NSCache()
	private let nonceDecoder: NonceDecoder

	public static func nonceHeaderDecoder(data: Data, response: HTTPURLResponse) throws -> NonceValue?
	{
		guard let value = response.value(forHTTPHeaderField: "DPoP-Nonce") else {
			return nil
		}

		// I'm not sure why response.url is optional, but maybe we need the request
		// passed into the decoder here, to fallback to request.url.origin
		guard let responseOrigin = response.url?.origin else {
			return nil
		}

		return NonceValue(origin: responseOrigin, nonce: value)
	}

	public init(nonceDecoder: @escaping NonceDecoder = nonceHeaderDecoder) {
		self.nonceDecoder = nonceDecoder
	}

	// Test helper:
	public func testRetrieveNonceForOrigin(url: URL) -> NonceValue? {
		guard let origin = url.origin else {
			return nil
		}

		return nonceCache.object(forKey: origin as NSString)
	}
}

extension DPoPSigner {
	public func buildProof(
		_ request: inout URLRequest,
		isolation: isolated (any Actor),
		using jwtGenerator: JWTGenerator,
		nonce: String?,
		token: String?,
		tokenHash: String?
	) async throws {
		guard
			let method = request.httpMethod,
			let url = request.url
		else {
			throw DPoPError.requestInvalid(request)
		}

		let params = JWTParameters(
			keyType: "dpop+jwt",
			httpMethod: method,
			requestEndpoint: url.absoluteString,
			nonce: nonce,
			tokenHash: tokenHash
		)

		let jwt = try await jwtGenerator(params)

		request.setValue(jwt, forHTTPHeaderField: "DPoP")

		if let token {
			request.setValue("DPoP \(token)", forHTTPHeaderField: "Authorization")
		}
	}

	public func response(
		isolation: isolated (any Actor),
		for request: URLRequest,
		using jwtGenerator: JWTGenerator,
		token: String?,
		// FIXME: Remove and use swift crypto internally to provide sha256, instead
		// of using pkce.hashFunction in the caller to calculate the tokenHash
		tokenHash: String?,
		issuingServer: String?,
		responseProvider: URLResponseProvider
	) async throws -> (Data, HTTPURLResponse) {
		var request = request
		var issuer: String? = nil
		if let iss = issuingServer {
			issuer = URL(string: iss)?.origin
		}

		// FIXME: calculate tokenHash using the value from the request Authorization
		// header:
		//
		// `Authorization: DPoP access-token`
		//
		// which is `access-token`. This requires swift crypto or for DPoP Signer to
		// have a sha256 hash function supplied.

		// Requests must have a URL with an origin:
		guard let requestOrigin = request.url?.origin else {
			throw DPoPError.requestInvalid(request)
		}

		let initNonce = nonceCache.object(forKey: requestOrigin as NSString)

		// build proof
		try await buildProof(
			&request,
			isolation: isolation,
			using: jwtGenerator,
			nonce: initNonce?.nonce,
			token: token,
			tokenHash: tokenHash
		)

		let (data, response) = try await responseProvider(request)

		// Extract the next nonce value if any; if we don't have a new nonce, return the response:
		guard let nextNonce = try nonceDecoder(data, response) else {
			return (data, response)
		}

		// If the response doesn't have a new nonce, or the new nonce is the same as
		// the current nonce for the same origin, return the response:
		if nextNonce.origin == initNonce?.origin && nextNonce.nonce == initNonce?.nonce {
			return (data, response)
		}

		// Store the fresh nonce for future requests
		nonceCache.setObject(nextNonce, forKey: nextNonce.origin as NSString)

		let isAuthServer = issuer == requestOrigin
		let shouldRetry = isUseDpopError(data: data, response: response, isAuthServer: isAuthServer)
		if !shouldRetry {
			return (data, response)
		}

		// repeat once, using newly-established nonce
		try await buildProof(
			&request,
			isolation: isolation,
			using: jwtGenerator,
			nonce: nextNonce.nonce,
			token: token,
			tokenHash: tokenHash
		)

		let (retryData, retryResponse) = try await responseProvider(request)
		if let retryNonce = try nonceDecoder(retryData, retryResponse) {
			nonceCache.setObject(retryNonce, forKey: retryNonce.origin as NSString)
		}

		return (retryData, retryResponse)
	}

	// The logic here is taken from:
	// https://github.com/bluesky-social/atproto/blob/4e96e2c7/packages/oauth/oauth-client/src/fetch-dpop.ts#L195
	private func isUseDpopError(data: Data, response: HTTPURLResponse, isAuthServer: Bool?) -> Bool {
		print(
			"isAuthServer: " + (isAuthServer == nil ? "nil" : (isAuthServer == true ? "true" : "false")))
		// https://datatracker.ietf.org/doc/html/rfc6750#section-3
		// https://datatracker.ietf.org/doc/html/rfc9449#name-resource-server-provided-no
		if isAuthServer == nil || isAuthServer == false {
			if response.statusCode == 401 {
				if let wwwAuthHeader = response.value(forHTTPHeaderField: "WWW-Authenticate") {
					if wwwAuthHeader.starts(with: "DPoP") {
						return wwwAuthHeader.contains("error=\"use_dpop_nonce\"")
					}
				}
			}
		}

		// https://datatracker.ietf.org/doc/html/rfc9449#name-authorization-server-provid
		if isAuthServer == nil || isAuthServer == true {
			if response.statusCode == 400 {
				do {
					let err = try JSONDecoder().decode(OAuthErrorResponse.self, from: data)
					return err.error == "use_dpop_nonce"
				} catch {
					return false
				}
			}
		}

		return false
	}
}
