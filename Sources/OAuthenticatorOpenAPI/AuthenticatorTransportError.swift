import Foundation
import HTTPTypes

/// Specialized error thrown by the transport.
enum AuthenticatorTransportError: Error {
    /// Invalid URL composed from base URL and received request.
    case invalidRequestURL(path: String, method: HTTPRequest.Method, baseURL: URL)

    /// Returned `URLResponse` could not be converted to `HTTPURLResponse`.
    case notHTTPResponse(URLResponse)
}
