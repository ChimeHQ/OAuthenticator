import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

enum URLResponseProviderError: Error {
	case missingResponseComponents
}

extension URLSession {
	/// Convert a `URLSession` instance into a `URLResponseProvider`.
	public var responseProvider: URLResponseProvider {
		return { request in
			return try await withCheckedThrowingContinuation { continuation in
				let task = self.dataTask(with: request) { data, response, error in
					switch (data, response, error) {
					case (let data?, let response?, nil):
						continuation.resume(returning: (data, response))
					case (_, _, let error?):
						continuation.resume(throwing: error)
					case (_, _, nil):
						continuation.resume(throwing: URLResponseProviderError.missingResponseComponents)
					}
				}

				task.resume()
			}
		}
	}

	/// Convert a `URLSession` with a default configuration into a `URLResponseProvider`.
	public static var defaultProvider: URLResponseProvider {
		let session = URLSession(configuration: .default)

		return session.responseProvider
	}
}
