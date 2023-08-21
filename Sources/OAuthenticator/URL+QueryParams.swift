import Foundation

public extension URL {
	func queryValues(named name: String) -> [String] {
		let components = URLComponents(url: self, resolvingAgainstBaseURL: false)
		let items = components?.queryItems?.filter({ $0.name == name })
		return items?.compactMap { $0.value } ?? []
	}

	var authorizationCode: String {
		get throws {
			guard let value = queryValues(named: "code").first else {
				throw AuthenticatorError.missingAuthorizationCode
			}

			return value
		}
	}
    
    ///
    /// The scope query parameter contains the authorized scopes by the user
    /// Typically used for the GoogleAPI
    var grantedScope: String {
        get throws {
            guard let value = queryValues(named: "scope").first else {
                throw AuthenticatorError.missingScope
            }

            return value
        }
    }
}
