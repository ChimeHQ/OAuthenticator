import Foundation

#if canImport(FoundationNetworking)
	import FoundationNetworking
#endif

extension URL {
	var origin: String? {
		guard
			let host = self.host,
			let scheme = self.scheme
		else {
			return nil
		}

		var originComponents = URLComponents()
		originComponents.scheme = scheme
		originComponents.host = host

		omitWebDefaultPort(components: &originComponents, port: self.port, scheme: scheme)

		return originComponents.string
	}
}
