import Foundation

enum URLResponseProviderError: Error {
	case missingResponseComponents
	case missingScheme
}

extension URLSession {
	var responseProvider: URLResponseProvider {
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

	static var defaultProvider: URLResponseProvider {
		let session = URLSession(configuration: .default)

		return session.responseProvider
	}
}
