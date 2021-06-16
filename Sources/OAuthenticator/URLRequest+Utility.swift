import Foundation

public extension URLRequest {
    enum HTTPHeader: String {
        case authorization = "Authorization"
        case contentType = "Content-Type"
        case accept = "Accept"
    }
}

public extension URLRequest {
    mutating func addValue(_ value: String, forHeader type: HTTPHeader) {
        addValue(value, forHTTPHeaderField: type.rawValue)
    }

    mutating func setValue(_ value: String, forHeader type: HTTPHeader) {
        setValue(value, forHTTPHeaderField: type.rawValue)
    }

    func value(forHeader type: HTTPHeader) -> String? {
        return value(forHTTPHeaderField: type.rawValue)
    }

    func authorizedRequest(with authorization: String) -> URLRequest {
        var request = self

        request.setValue(authorization, forHeader: .authorization)

        return request
    }

    mutating func setBasicAuthorization(user: String, password: String) {
        let string = "\(user):\(password)"
        let encodedString = string.data(using: .utf8)?.base64EncodedString() ?? ""

        let value = "Basic \(encodedString)"

        setValue(value, forHeader: .authorization)
    }
}
