import Foundation

extension Data {
	func base64EncodedURLEncodedString() -> String {
		base64EncodedString()
			.replacingOccurrences(of: "+", with: "-")
			.replacingOccurrences(of: "/", with: "_")
			.replacingOccurrences(of: "=", with: "")
	}

	init?(base64URLEncoded string: String) {
		self.init(base64Encoded: string)
	}
}
