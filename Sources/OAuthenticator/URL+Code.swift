import Foundation

public extension URL {
	func queryValues(named name: String) -> [String] {
		let components = URLComponents(url: self, resolvingAgainstBaseURL: false)
		let items = components?.queryItems?.filter({ $0.name == name })
		return items?.compactMap { $0.value } ?? []
	}

	var accessCode: String {
		get throws {
			guard let value = queryValues(named: "code").first else {
				throw AuthenticatorError.missingLoginCode
			}

			return value
		}
	}
}
