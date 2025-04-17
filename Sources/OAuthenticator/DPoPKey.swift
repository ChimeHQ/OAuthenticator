import Foundation

/// A private key and ID pair used for DPoP signing.
public struct DPoPKey: Codable, Hashable, Sendable {
	public let data: Data
	public let id: UUID

	public init(keyData: Data) {
		self.id = UUID()
		self.data = keyData
	}
}

#if canImport(CryptoKit)
import CryptoKit

extension DPoPKey {
	/// Generate a new instance with P-256 key data.
	public static func P256() -> DPoPKey {
		let data = CryptoKit.P256.Signing.PrivateKey().rawRepresentation
		
		return DPoPKey(keyData: data)
	}
	
	public var p256PrivateKey: CryptoKit.P256.Signing.PrivateKey {
		get throws {
			try CryptoKit.P256.Signing.PrivateKey(rawRepresentation: data)
		}
	}
}
#endif
