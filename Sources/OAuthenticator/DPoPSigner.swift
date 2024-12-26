#if canImport(CryptoKit)
import Foundation

struct DPoPTokenPayload: Codable, Hashable, Sendable {
	public let uniqueCode: String
	public let httpMethod: String
	public let httpRequestURL: String
	/// UNIX type, seconds since epoch
	public let createdAt: Int
	/// UNIX type, seconds since epoch
	public let expiresAt: Int
	public let nonce: String?

	public enum CodingKeys: String, CodingKey {
		case uniqueCode = "jti"
		case httpMethod = "htm"
		case httpRequestURL = "htu"
		case createdAt = "iat"
		case expiresAt = "exp"
		case nonce
	}

	public init(
		httpMethod: String,
		httpRequestURL: String,
		createdAt: Int,
		expiresAt: Int,
		nonce: String? = nil
	) {
		self.uniqueCode = UUID().uuidString
		self.httpMethod = httpMethod
		self.httpRequestURL = httpRequestURL
		self.createdAt = createdAt
		self.expiresAt = expiresAt
		self.nonce = nonce
	}
}

struct DPoPRequestPayload: Codable, Hashable, Sendable {
	public let uniqueCode: String
	public let httpMethod: String
	public let httpRequestURL: String
	/// UNIX type, seconds since epoch
	public let createdAt: Int
	/// UNIX type, seconds since epoch
	public let expiresAt: Int
	public let nonce: String?
	public let authorizationServerIssuer: String
	public let accessTokenHash: String
	
	public enum CodingKeys: String, CodingKey {
		case uniqueCode = "jti"
		case httpMethod = "htm"
		case httpRequestURL = "htu"
		case createdAt = "iat"
		case expiresAt = "exp"
		case nonce
		case authorizationServerIssuer = "iss"
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
		self.authorizationServerIssuer = authorizationServerIssuer
		self.accessTokenHash = accessTokenHash
	}
}

public enum DPoPError: Error {
	case nonceExpected(URLResponse)
	case requestInvalid(URLRequest)
}

/// Manages state and operations for OAuth Demonstrating Proof-of-Possession (DPoP).
///
/// Currently only uses ES256.
///
/// Details here: https://datatracker.ietf.org/doc/html/rfc9449
public final actor DPoPSigner {
	public struct JWTParameters: Sendable, Hashable {
		public let keyType: String

		public let httpMethod: String
		public let requestEndpoint: String
		public let nonce: String?
		public let tokenHash: String?
		public let issuingServer: String?
	}
	
	public typealias NonceDecoder = (Data, URLResponse) throws -> String
	public typealias JWTGenerator = @Sendable (JWTParameters) async throws -> String
	private let nonceDecoder: NonceDecoder
	public var nonce: String?

	public static func nonceHeaderDecoder(data: Data, response: URLResponse) throws -> String {
		guard let value = (response as? HTTPURLResponse)?.value(forHTTPHeaderField: "DPoP-Nonce") else {
			print("data:", String(decoding: data, as: UTF8.self))
			throw DPoPError.nonceExpected(response)
		}

		return value
	}

	public init(nonceDecoder: @escaping NonceDecoder = nonceHeaderDecoder) {
		self.nonceDecoder = nonceDecoder
	}
}

extension DPoPSigner {
	public func authenticateRequest(
		_ request: inout URLRequest,
		using jwtGenerator: JWTGenerator,
		token: String?,
		tokenHash: String?,
		issuer: String?
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
			tokenHash: tokenHash,
			issuingServer: issuer
		)

		let jwt = try await jwtGenerator(params)

		request.setValue(jwt, forHTTPHeaderField: "DPoP")

		if let token {
			request.setValue("DPoP \(token)", forHTTPHeaderField: "Authorization")
		}
	}

	@discardableResult
	public func setNonce(from response: URLResponse) -> Bool {
		let newValue = (response as? HTTPURLResponse)?.value(forHTTPHeaderField: "dpop-nonce")

		nonce = newValue

		return newValue != nil
	}

	public func response(
		for request: URLRequest,
		using jwtGenerator: JWTGenerator,
		token: String?,
		tokenHash: String?,
		issuingServer: String?,
		provider: URLResponseProvider
	) async throws -> (Data, URLResponse) {
		var request = request

		try await authenticateRequest(&request, using: jwtGenerator, token: token, tokenHash: tokenHash, issuer: issuingServer)

		let (data, response) = try await provider(request)

		let existingNonce = nonce

		self.nonce = try nonceDecoder(data, response)

		if nonce == existingNonce {
			return (data, response)
		}

		print("DPoP nonce updated", existingNonce ?? "", nonce ?? "")

		// repeat once, using newly-established nonce
		try await authenticateRequest(&request, using: jwtGenerator, token: token, tokenHash: tokenHash, issuer: issuingServer)

		return try await provider(request)
	}
}

#endif
