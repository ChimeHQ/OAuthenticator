import Foundation

#if canImport(FoundationNetworking)
	import FoundationNetworking
#endif

public enum URLError: Error, Hashable {
	case relative(String)
}

let insecureSchemes = ["http", "ws"]
let secureSchemes = ["https", "wss"]

extension URL {
	var origin: String? {
		guard
			let host = self.host,
			let scheme = self.scheme
		else {
			// throw URLError.relative("Cannot calculate an origin for a relative URL")
			return nil
		}

		var origin: String = scheme + "://" + host
		guard let port = self.port else {
			return origin
		}

		let isStandardPort =
			(insecureSchemes.contains(scheme) && port == 80)
			|| (secureSchemes.contains(scheme) && port == 443)

		let isHttp = insecureSchemes.contains(scheme) || secureSchemes.contains(scheme)

		if (isHttp && !isStandardPort) || !isHttp {
			origin.append(":" + String(port))
		}

		return origin
	}
}
