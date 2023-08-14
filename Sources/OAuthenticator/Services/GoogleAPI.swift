import Foundation
import OSLog

public struct GoogleAPI {
    // Define scheme, host and query item names
	public static let scheme: String = "https"
    static let authorizeHost: String = "accounts.google.com"
	static let authorizePath: String = "/o/oauth2/auth"
    static let tokenHost: String = "accounts.google.com"
	static let tokenPath: String = "/o/oauth2/token"

	static let clientIDKey: String = "client_id"
	static let clientSecretKey: String = "client_secret"
	static let redirectURIKey: String = "redirect_uri"

    static let responseTypeKey: String = "response_type"
    static let responseTypeCode: String = "code"

    static let scopeKey: String = "scope"
    static let includeGrantedScopeKey: String = "include_granted_scopes"
    
	static let codeKey: String = "code"
    static let refreshTokenKey: String = "refresh_token"

    static let grantTypeKey: String = "grant_type"
	static let grantTypeAuthorizationCode: String = "authorization_code"
    static let grantTypeRefreshToken: String = "refresh_token"

	struct OAuthResponse: Codable, Hashable, Sendable {
		let accessToken: String
        let refreshToken: String?       // When not using offline mode, no refreshToken is provided
		let scope: String
		let tokenType: String
		let expiresIn: Int              // Access Token validity in seconds

		enum CodingKeys: String, CodingKey {
			case accessToken = "access_token"
            case refreshToken = "refresh_token"
			case scope
			case tokenType = "token_type"
			case expiresIn = "expires_in"
		}

		var login: Login {
            var login = Login(accessToken: .init(value: accessToken, expiresIn: expiresIn))
            
            // Set the refresh token if we have one
            if let refreshToken = refreshToken {
                login.refreshToken = .init(value: refreshToken)
            }
            
            return login
		}
	}

	public static func googleAPITokenHandling(with parameters: AppCredentials) -> TokenHandling {
        TokenHandling(authorizationURLProvider: Self.authorizationURLProvider(with: parameters),
                      loginProvider: Self.loginProvider(with: parameters),
                      refreshProvider: Self.refreshProvider(with: parameters))
	}

    /// This is part 1 of the OAuth process
    ///
    /// Will request an authentication `code` based on the acceptance by the user
	public static func authorizationURLProvider(with parameters: AppCredentials) -> TokenHandling.AuthorizationURLProvider {
		return { credentials in
			var urlBuilder = URLComponents()

			urlBuilder.scheme = GoogleAPI.scheme
			urlBuilder.host = GoogleAPI.authorizeHost
			urlBuilder.path = GoogleAPI.authorizePath
			urlBuilder.queryItems = [
				URLQueryItem(name: GoogleAPI.clientIDKey, value: credentials.clientId),
				URLQueryItem(name: GoogleAPI.redirectURIKey, value: credentials.callbackURL.absoluteString),
				URLQueryItem(name: GoogleAPI.responseTypeKey, value: GoogleAPI.responseTypeCode),
				URLQueryItem(name: GoogleAPI.scopeKey, value: credentials.scopeString),
                URLQueryItem(name: GoogleAPI.includeGrantedScopeKey, value: "true")           // Will include previously granted scoped for this user
			]

			guard let url = urlBuilder.url else {
				throw AuthenticatorError.missingAuthorizationURL
			}

			return url
		}
	}

    /// This is part 2 of the OAuth process
    ///
    /// The `code` is exchanged for an access / refresh token pair using the granted scope in part 1
	static func authenticationRequest(url: URL, appCredentials: AppCredentials) throws -> URLRequest {
		let code = try url.authorizationCode
        let grantedScope = try url.grantedScope

        // It's possible the user will decide to grant less scopes than requested by the app.
        // We should have a mechanism to tell us which scopes were authorized and decide if we
        // can continue forward or not.
        let grantedScopeItems = grantedScope.components(separatedBy: " ")
        if appCredentials.scopes.count > grantedScopeItems.count {
            // For now, just display that less scope was authorized
            os_log(.info, "[Authentication] Granted scopes less than requested scopes")
            print("GrantedScope: \(grantedScope)")
            print("RequestedScope: \(appCredentials.scopeString)")
        }

        // Regardless if we want to move forward, we need to supply the granted scopes.
        // If we don't, the tokens will not be issued and an error will occur
        var urlBuilder = URLComponents()
		urlBuilder.scheme = GoogleAPI.scheme
        urlBuilder.host = GoogleAPI.tokenHost
		urlBuilder.path = GoogleAPI.tokenPath
		urlBuilder.queryItems = [
			URLQueryItem(name: GoogleAPI.grantTypeKey, value: GoogleAPI.grantTypeAuthorizationCode),
			URLQueryItem(name: GoogleAPI.clientIDKey, value: appCredentials.clientId),
			URLQueryItem(name: GoogleAPI.redirectURIKey, value: appCredentials.callbackURL.absoluteString),
			URLQueryItem(name: GoogleAPI.codeKey, value: code),
			URLQueryItem(name: GoogleAPI.scopeKey, value: grantedScope)  // See above for grantedScope explanation
		]
        
        // Add clientSecret if supplied (not empty)
        if !appCredentials.clientPassword.isEmpty {
            urlBuilder.queryItems?.append(URLQueryItem(name: GoogleAPI.clientSecretKey, value: appCredentials.clientPassword))
        }

		guard let url = urlBuilder.url else {
			throw AuthenticatorError.missingTokenURL
		}

		var request = URLRequest(url: url)
		request.httpMethod = "POST"
		request.setValue("application/json", forHTTPHeaderField: "Accept")

		return request
	}
    
	static func loginProvider(with parameters: AppCredentials) -> TokenHandling.LoginProvider {
		return { url, appCredentials, tokenURL, urlLoader in
			let request = try authenticationRequest(url: url, appCredentials: appCredentials)

			let (data, _) = try await urlLoader(request)

            do {
                
                let jsonString = String(data: data, encoding: .utf8) ?? ""
                os_log(.debug, "%s", jsonString)
                
                let response = try JSONDecoder().decode(GoogleAPI.OAuthResponse.self, from: data)
                return response.login
            }
            catch let decodingError as DecodingError {
                os_log(.fault, "Reponse from AuthenticationProvider is not conformed to provided response format. %s", decodingError.failureReason ?? decodingError.localizedDescription)
                throw decodingError
            }
		}
	}

    /// Token Refreshing
    /// - Create the request that will refresh the access token from the information in the Login
    ///
    /// - Parameters:
    ///   - login: The current Login object containing the refresh token
    ///   - appCredentials: The Application credentials
    /// - Returns: The URLRequest to refresh the access token
    static func authenticationRefreshRequest(login: Login, appCredentials: AppCredentials) throws -> URLRequest {
        guard let refreshToken = login.refreshToken,
              !refreshToken.value.isEmpty else { throw AuthenticatorError.missingRefreshToken }

        var urlBuilder = URLComponents()

        urlBuilder.scheme = GoogleAPI.scheme
        urlBuilder.host = GoogleAPI.tokenHost
        urlBuilder.path = GoogleAPI.tokenPath
        urlBuilder.queryItems = [
            URLQueryItem(name: GoogleAPI.clientIDKey, value: appCredentials.clientId),
            URLQueryItem(name: GoogleAPI.refreshTokenKey, value: refreshToken.value),
            URLQueryItem(name: GoogleAPI.grantTypeKey, value: GoogleAPI.grantTypeRefreshToken),
        ]
        
        guard let url = urlBuilder.url else {
            throw AuthenticatorError.missingTokenURL
        }

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Accept")

        return request
    }
    
	static func refreshProvider(with parameters: AppCredentials) -> TokenHandling.RefreshProvider {
		return { login, appCredentials, urlLoader in
            let request = try authenticationRefreshRequest(login: login, appCredentials: appCredentials)
            let (data, _) = try await urlLoader(request)

            let jsonString = String(data: data, encoding: .utf8) ?? ""
            os_log(.debug, "[Authentication Refresh JSON Result] %s", jsonString)
            
            do {
                let response = try JSONDecoder().decode(GoogleAPI.OAuthResponse.self, from: data)
                return response.login
            }
            catch let decodingError as DecodingError {
                os_log(.fault, "Non-conformant response from AuthenticationProvider: %s", decodingError.failureReason ?? decodingError.localizedDescription)
                throw decodingError
            }
        }
	}
}

public extension URL {
    /// Add the ability to retrieve the scope query item from the URL
    var grantedScope: String {
        get throws {
            guard let value = queryValues(named: "scope").first else {
                throw AuthenticatorError.missingScope
            }

            return value
        }
    }
}
