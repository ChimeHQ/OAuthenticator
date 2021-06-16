import Foundation
import AuthenticationServices

enum WebAuthenticationSessionError: Error {
    case resultInvalid
}

extension ASWebAuthenticationSession {
    public convenience init(url: URL, callbackURLScheme: String? = nil, completionHandler: @escaping (Result<URL, Error>) -> Void) {
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
