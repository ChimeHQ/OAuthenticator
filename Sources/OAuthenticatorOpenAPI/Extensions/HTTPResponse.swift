import Foundation
import HTTPTypes

extension HTTPResponse {
    init(_ urlResponse: URLResponse) throws {
        guard let httpResponse = urlResponse as? HTTPURLResponse else {
            throw AuthenticatorTransportError.notHTTPResponse(urlResponse)
        }
        var headerFields = HTTPFields()
        for (headerName, headerValue) in httpResponse.allHeaderFields {
            guard let rawName = headerName as? String, let name = HTTPField.Name(rawName),
                  let value = headerValue as? String
            else {
                continue
            }
            headerFields[name] = value
        }
        self.init(status: .init(code: httpResponse.statusCode), headerFields: headerFields)
    }
}
