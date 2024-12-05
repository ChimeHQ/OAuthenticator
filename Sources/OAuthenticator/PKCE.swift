#if canImport(CryptoKit)
import CryptoKit
import Foundation

extension SHA256.Digest {
	var data: Data {
		self.withUnsafeBytes { buffer in
			Data(bytes: buffer.baseAddress!, count: buffer.count)
		}
	}
}

public struct PKCEVerifier: Hashable, Sendable {
	public struct Challenge: Hashable, Sendable {
		public let value: String
		public let method: String
	}

	public let verifier: String
	public let challenge: Challenge

	public static func randomString(length: Int) -> String {
		let characters = Array("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")

		var string = ""

		for _ in 0..<length {
			string.append(characters.randomElement()!)
		}

		return string
	}

	public init() {
		self.verifier = PKCEVerifier.randomString(length: 64)

		self.challenge = Challenge(
			value: Self.computeHash(verifier),
			method: "S256"
		)
	}
	
	static func computeHash(_ value: String) -> String {
		let digest = SHA256.hash(data: Data(value.utf8))

		return digest.data.base64EncodedURLEncodedString()
	}
	
	public func validate(_ value: String) -> Bool {
		Self.computeHash(value) == verifier
	}
}
#endif
