import Foundation
import AuthenticationServices

enum WebAuthenticationSessionError: Error {
	case resultInvalid
}

@available(tvOS 16.0, macCatalyst 13.0, *)
extension ASWebAuthenticationSession {
	convenience init(url: URL, callbackURLScheme: String, completionHandler: @escaping (Result<URL, Error>) -> Void) {
		self.init(url: url, callbackURLScheme: callbackURLScheme, completionHandler: { (resultURL, error) in
			switch (resultURL, error) {
			case (_, let error?):
				completionHandler(.failure(error))
			case (let callbackURL?, nil):
				completionHandler(.success(callbackURL))
			default:
				completionHandler(.failure(WebAuthenticationSessionError.resultInvalid))
			}
		})
	}
}


@available(tvOS 16.0, macCatalyst 13.0, *)
extension ASWebAuthenticationSession {
#if os(iOS) || os(macOS)
	@MainActor
	public static func begin(with url: URL, callbackURLScheme scheme: String, contextProvider: ASWebAuthenticationPresentationContextProviding = CredentialWindowProvider()) async throws -> URL {
		try await withCheckedThrowingContinuation { continuation in
			let session = ASWebAuthenticationSession(url: url, callbackURLScheme: scheme, completionHandler: { result in
				continuation.resume(with: result)
			})

			if #available(macCatalyst 13.1, *) {
				session.prefersEphemeralWebBrowserSession = true
			}
			
			session.presentationContextProvider = contextProvider

			session.start()
		}
	}
	
	@MainActor
	public static func userAuthenticator(url: URL, scheme: String) async throws -> URL {
		try await begin(with: url, callbackURLScheme: scheme)
	}
#else
	@MainActor
	public static func userAuthenticator(url: URL, scheme: String) async throws -> URL {
		try await withCheckedThrowingContinuation { continuation in
			let session = ASWebAuthenticationSession(url: url, callbackURLScheme: scheme, completionHandler: { result in
				continuation.resume(with: result)
			})

#if os(watchOS)
			session.prefersEphemeralWebBrowserSession = true
#endif

			session.start()
		}
	}
#endif
}
