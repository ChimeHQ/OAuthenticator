import Foundation

#if canImport(FoundationNetworking)
	import FoundationNetworking
#endif

extension URLComponents {
	public func firstQueryValue(_ name: String) -> String? {
		return queryItems?.first(where: { $0.name == name })?.value
	}
}
