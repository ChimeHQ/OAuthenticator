import Foundation
import HTTPTypes

extension URLRequest {
    init(_ request: HTTPRequest, baseURL: URL) throws {
        guard var baseURLComponents = URLComponents(string: baseURL.absoluteString),
              let requestURLComponents = URLComponents(string: request.path ?? "")
        else {
            throw AuthenticatorTransportError.invalidRequestURL(
                path: request.path ?? "<nil>",
                method: request.method,
                baseURL: baseURL
            )
        }

        let path = requestURLComponents.percentEncodedPath
        baseURLComponents.percentEncodedPath += path
        baseURLComponents.percentEncodedQuery = requestURLComponents.percentEncodedQuery
        guard let url = baseURLComponents.url else {
            throw AuthenticatorTransportError.invalidRequestURL(path: path, method: request.method, baseURL: baseURL)
        }
        self.init(url: url)
        self.httpMethod = request.method.rawValue
        for header in request.headerFields {
            self.setValue(header.value, forHTTPHeaderField: header.name.canonicalName)
        }
    }
}
