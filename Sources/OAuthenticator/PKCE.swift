import Foundation

public struct PKCEVerifier: Sendable {
	public struct Challenge: Hashable, Sendable {
		public let value: String
		public let method: String
	}
	public typealias HashFunction = @Sendable (String) -> String

	public let verifier: String
	public let challenge: Challenge
	public let hashFunction: HashFunction

	public static func randomString(length: Int) -> String {
		let characters = Array("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")

		var string = ""

		for _ in 0..<length {
			string.append(characters.randomElement()!)
		}

		return string
	}

	public init(hash: String, hasher: @escaping HashFunction) {
		self.verifier = PKCEVerifier.randomString(length: 64)
		self.hashFunction = hasher

		self.challenge = Challenge(
			value: hashFunction(verifier),
			method: hash
		)
	}
}

#if canImport(CryptoKit)
import CryptoKit

extension SHA256.Digest {
	var data: Data {
		self.withUnsafeBytes { buffer in
			Data(bytes: buffer.baseAddress!, count: buffer.count)
		}
	}
}

extension PKCEVerifier {
	public init() {
		self.init(
			hash: "S256",
			hasher: { value in
				let digest = SHA256.hash(data: Data(value.utf8))
				
				return digest.data.base64EncodedURLEncodedString()
			}
		)
	}
}
#endif
