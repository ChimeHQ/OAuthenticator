/// Model of a JSON Web Key.
///
/// Defined by: https://datatracker.ietf.org/doc/html/rfc7517
struct JSONWebKey: Hashable, Sendable {
	public struct EllipticCurveParameters: Hashable, Sendable {
		public let curve: String
		public let x: String
		public let y: String
		
		public init(curve: String, x: String, y: String) {
			self.curve = curve
			self.x = x
			self.y = y
		}
	}
	
	public enum KeyType: Hashable, Sendable {
		case rsa
		case ec(EllipticCurveParameters)
	}
	
	public enum KeyUse: RawRepresentable, Hashable, Sendable {
		case signature
		case encryption
		case custom(String)
		
		public init?(rawValue: String) {
			switch rawValue {
			case "sig":
				self = .signature
			case "enc":
				self = .encryption
			default:
				self = .custom(rawValue)
			}
		}
		
		public var rawValue: String {
			switch self {
			case .encryption:
				"enc"
			case .signature:
				"sig"
			case let .custom(value):
				value
			}
		}
	}
	
	public let keyType: KeyType
	public let use: KeyUse?
	public let id: String?
	
	public init(keyType: KeyType, use: KeyUse? = nil, id: String? = nil) {
		self.keyType = keyType
		self.use = use
		self.id = id
	}
	
	public init(params: EllipticCurveParameters, use: KeyUse? = nil, id: String? = nil) {
		self.init(keyType: .ec(params), use: use, id: id)
	}
}

extension JSONWebKey: Codable {
	enum CodingKeys: String, CodingKey {
		case keyType = "kty"
		case use
		case id = "kid"
		case curve = "crv"
		case ecX = "x"
		case ecY = "y"
	}

	public init(from decoder: any Decoder) throws {
		throw DecodingError.dataCorrupted(.init(codingPath: decoder.codingPath, debugDescription: "This just isn't implenented yet"))
	}

	public func encode(to encoder: any Encoder) throws {
		var container = encoder.container(keyedBy: CodingKeys.self)
		
		switch keyType {
		case .rsa:
			try container.encode("RSA", forKey: .keyType)
		case let .ec(params):
			try container.encode("EC", forKey: .keyType)
			
			try container.encode(params.curve, forKey: .curve)
			try container.encode(params.x, forKey: .ecX)
			try container.encode(params.y, forKey: .ecY)
		}
		
		if let use {
			try container.encode(use.rawValue, forKey: .use)
		}
		
		if let id {
			try container.encode(id, forKey: .id)
		}
	}
}

#if canImport(CryptoKit)
import CryptoKit

extension JSONWebKey.EllipticCurveParameters {
	public init(p256Key: P256.Signing.PublicKey) {
		self.init(curve: "P-256", x: "x", y: "y")
	}
}

extension JSONWebKey {
	public init(p256Key: P256.Signing.PublicKey, use: KeyUse? = nil, id: String? = nil) {
		let curve = EllipticCurveParameters(p256Key: p256Key)
		
		self.init(params: curve, use: use, id: id)
	}
}
#endif
