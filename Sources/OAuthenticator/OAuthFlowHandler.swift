import Foundation

public struct OAuthFlowHandler {
    public var authorizationHost: String
    public var clientId: String
    public var clientPassword: String
    public var callbackURLScheme: String
    public var scopes: [String]

    public init(authorizationHost: String, clientId: String, clientPassword: String, callbackURLScheme: String, scopes: [String]) {
        self.authorizationHost = authorizationHost
        self.clientId = clientId
        self.clientPassword = clientPassword
        self.callbackURLScheme = callbackURLScheme
        self.scopes = scopes
    }

    public var scopeString: String {
        return scopes.joined(separator: " ")
    }
}

extension OAuthFlowHandler {
    private var loginURL: URL? {
        var url = URLComponents()

        url.scheme = "https"
        url.host = authorizationHost
        url.path = "/login"
        url.queryItems = [
            URLQueryItem(name: "client_id", value: clientId),
            URLQueryItem(name: "response_type", value: "code"),
            URLQueryItem(name: "scope", value: scopeString),
            URLQueryItem(name: "redirect_uri", value: "\(callbackURLScheme)://login")
        ]

        return url.url
    }

    private func codeFromCallback(_ url: URL) throws -> String {
        // scheme://login?code=edbcdc2f-4ba1-4eb6-938c-877324ea3d57
        let components = URLComponents(url: url, resolvingAgainstBaseURL: false)

        guard components?.scheme == callbackURLScheme else {
            throw OAuthenticatorError.callbackURLInvalid
        }

        guard components?.host == "login" else {
            throw OAuthenticatorError.callbackURLInvalid
        }

        let codeItem = components?.queryItems?.first(where: { $0.name == "code" })

        guard let value = codeItem?.value else {
            throw OAuthenticatorError.callbackURLInvalid
        }

        return value
    }

    private func tokenURL(with callbackURL: URL) throws -> URL {
        let code = try codeFromCallback(callbackURL)
        var urlBuilder = URLComponents()

        urlBuilder.scheme = "https"
        urlBuilder.host = authorizationHost
        urlBuilder.path = "/oauth2/token"
        urlBuilder.queryItems = [
            URLQueryItem(name: "client_id", value: clientId),
            URLQueryItem(name: "grant_type", value: "authorization_code"),
            URLQueryItem(name: "scope", value: scopeString),
            URLQueryItem(name: "redirect_uri", value: "\(callbackURLScheme)://login"),
            URLQueryItem(name: "code", value: code),
        ]

        guard let url = urlBuilder.url else {
            throw OAuthenticatorError.unableToConstructURL
        }

        return url
    }

    private func refreshURL(with code: String) throws -> URL {
        var urlBuilder = URLComponents()

        urlBuilder.scheme = "https"
        urlBuilder.host = authorizationHost
        urlBuilder.path = "/oauth2/token"
        urlBuilder.queryItems = [
            URLQueryItem(name: "grant_type", value: "refresh_token"),
            URLQueryItem(name: "refresh_token", value: code),
            URLQueryItem(name: "scope", value: scopeString),
        ]

        guard let url = urlBuilder.url else {
            throw OAuthenticatorError.unableToConstructURL
        }

        return url
    }
}

extension OAuthFlowHandler: LoginFlowHandling {
    public func accessRequestFromCallback(url callbackURL: URL) throws -> URLRequest {
        let url = try tokenURL(with: callbackURL)

        var request = URLRequest(url: url)

        request.httpMethod = "POST"

        request.setBasicAuthorization(user: clientId, password: clientPassword)
        request.setValue("application/x-www-form-urlencoded", forHeader: .contentType)
        request.setValue("application/json", forHeader: .accept)

        return request
    }

    public func refreshRequestFromLogin(_ login: OAuthLogin) throws -> URLRequest {
        guard let token = login.refreshToken else {
            throw OAuthenticatorError.refreshTokenUnavailable
        }

        let url = try refreshURL(with: token)

        var request = URLRequest(url: url)

        request.httpMethod = "POST"

        request.setBasicAuthorization(user: clientId, password: clientPassword)
        request.addValue("application/x-www-form-urlencoded", forHeader: .contentType)
        request.addValue("application/json", forHeader: .accept)

        return request
    }

    public func requiresRefresh(_ result: URLSession.DataTaskResult) -> Bool {
        guard let response = try? result.get() else {
            return true
        }

        guard let httpResponse = response.response as? HTTPURLResponse else {
            return true
        }

        return httpResponse.statusCode == 401
    }
}
