import Foundation
import OperationPlus
import Combine

public protocol LoginStorage {
    func storeLogin(_ login: OAuthLogin, completionHandler: @escaping (Error?) -> Void)
    func retrieveLogin(completionHandler: @escaping (Result<OAuthLogin, Error>) -> Void)
}

public protocol LoginFlowHandling {
    func accessRequestFromCallback(url: URL) throws -> URLRequest
    func refreshRequestFromLogin(_ login: OAuthLogin) throws -> URLRequest
    func requiresRefresh(_ result: URLLoader.LoadResult) -> Bool
}

public struct AuthConfiguration {
    public var tokenURL: URL
    public var callbackURLScheme: String
    public var loader: URLLoader
    public var loginStorage: LoginStorage
    public var flowHandler: LoginFlowHandling

    public init(tokenURL: URL, callbackURLScheme: String, loader: URLLoader, loginStorage: LoginStorage, flowHandler: LoginFlowHandling) {
        self.tokenURL = tokenURL
        self.callbackURLScheme = callbackURLScheme
        self.loader = loader
        self.loginStorage = loginStorage
        self.flowHandler = flowHandler
    }
}

public struct OAuthLogin: Codable {
    public typealias Token = String

    public var accessToken: Token
    public var refreshToken: Token?
    public var validUntilDate: Date

    public init(accessToken: OAuthLogin.Token, refreshToken: OAuthLogin.Token? = nil, validUntilDate: Date) {
        self.accessToken = accessToken
        self.refreshToken = refreshToken
        self.validUntilDate = validUntilDate
    }
}

struct LoginResponse: Decodable {
    var idToken: String
    var accessToken: String
    var refreshToken: String?
    var expiresIn: Int
    var tokenType: String
    private let createdDate = Date()

    enum CodingKeys: String, CodingKey {
        case idToken = "id_token"
        case accessToken = "access_token"
        case refreshToken = "refresh_token"
        case expiresIn = "expires_in"
        case tokenType = "token_type"
    }

    var expiryDate: Date {
        return createdDate.addingTimeInterval(TimeInterval(expiresIn))
    }

    var oauthLogin: OAuthLogin {
        return OAuthLogin(accessToken: accessToken, refreshToken: refreshToken, validUntilDate: expiryDate)
    }
}

public enum OAuthenticatorError: Error {
    case missingResponseComponents
    case callbackURLInvalid
    case unableToStoreLoginData
    case unableToRetrieveLoginData
    case refreshTokenUnavailable
    case unableToConstructURL
    case loginAfterRefreshNeededNotSupported
}

public class OAuthenticator {
    private let queue: OperationQueue
    public let config: AuthConfiguration

    public init(config: AuthConfiguration) {
        self.config = config
        self.queue = OperationQueue.serialQueue(named: "io.stacksift.OAuthenticator")
    }
}

extension OAuthenticator: URLLoader {
    public func response(for request: URLRequest, completionHandler: @escaping (LoadResult) -> Void) {
        let applyAuthOp = ApplyAuthentationOperation(request: request,
                                                     config: config)

        queue.addOperation(applyAuthOp)

        applyAuthOp.resultCompletionBlock = { result in
            switch result {
            case .failure(let error):
                completionHandler(.failure(error))
            case .success(let authedRequest):
                self.performAuthedRequest(authedRequest, completionHandler: completionHandler)
            }
        }
    }

}

extension OAuthenticator {
    public func responseResult(with request: URLRequest, completionHandler: @escaping (URLSession.DataTaskResult) -> Void ) {
        response(for: request, completionHandler: completionHandler)
    }

    public func response(with request: URLRequest, completionHandler: @escaping (Data?, URLResponse?, Error?) -> Void) {
        responseResult(with: request) { result in
            switch result {
            case .failure(let error):
                completionHandler(nil, nil, error)
            case .success(let response):
                completionHandler(response.data, response.response, nil)
            }
        }
    }

    public func responsePublisher(for request: URLRequest) -> AnyPublisher<URLSession.DataTaskPublisher.Output, Error> {
        return Deferred {
            Future<URLSession.DataTaskPublisher.Output, Error> { promise in
                self.responseResult(with: request) { result in
                    switch result {
                    case .failure(let error):
                        promise(.failure(error))
                    case .success(let response):
                        promise(.success((response.data, response.response)))
                    }
                }

            }.eraseToAnyPublisher()
        }.eraseToAnyPublisher()
    }
}

extension OAuthenticator {
    private func performAuthedRequest(_ request: URLRequest, completionHandler: @escaping (LoadResult) -> Void) {
        config.loader.response(for: request) { result in
            let handleResultOp = HandleAuthenticatedResultOperation(request: request,
                                                                    response: result,
                                                                    config: self.config)

            self.queue.addOperation(handleResultOp)

            handleResultOp.resultCompletionBlock = completionHandler
        }
    }
}
