import Foundation

#if canImport(FoundationNetworking)
	import FoundationNetworking
#endif

extension URL {
	var targetURI: String? {
		guard
			let host = self.host,
			let scheme = self.scheme
		else {
			return nil
		}

		var originComponents = URLComponents()
		originComponents.scheme = scheme
		originComponents.host = host
		originComponents.path = self.relativePath

		omitWebDefaultPort(components: &originComponents, port: self.port, scheme: scheme)

		return originComponents.string
	}
}
