import Foundation
import AuthenticationServices

class AuthenticationApplier {
    let request: URLRequest
    let config: AuthConfiguration

    private var session: ASWebAuthenticationSession?

    private lazy var contextProvider: CredentialWindowProvider = {
        CredentialWindowProvider()
    }()

    init(request: URLRequest, config: AuthConfiguration) {
        self.request = request
        self.config = config
    }

    func cancel() {
        OperationQueue.main.addOperation {
            self.session?.cancel()
            self.session = nil
        }
    }

    func applyAuthentication(using login: OAuthLogin, completionHandler: @escaping (Result<URLRequest, Error>) -> Void) {
        let authedRequest = self.buildRequest(with: login)

        completionHandler(.success(authedRequest))
    }

    private func buildRequest(with login: OAuthLogin) -> URLRequest {
        return request.authorizedRequest(with: login.accessToken)
    }

    func beginLogin(completionHandler: @escaping (Result<URLRequest, Error>) -> Void) {
        precondition(self.session == nil)

        // ok, we have no token
        let url = config.tokenURL
        let scheme = config.callbackURLScheme

        OperationQueue.main.addOperation {
            let session = ASWebAuthenticationSession(url: url, callbackURLScheme: scheme, completionHandler: { result in
                switch result {
                case .failure(let error):
                    completionHandler(.failure(error))
                case .success(let callbackURL):
                    self.handleSessionResult(url: callbackURL, completionHandler: completionHandler)
                }
            })

            session.prefersEphemeralWebBrowserSession = true
            session.presentationContextProvider = self.contextProvider

            session.start()

            self.session = session
        }
    }

    private func handleSessionResult(url: URL, completionHandler: @escaping (Result<URLRequest, Error>) -> Void) {
        do {
            let tokenRequest = try self.config.flowHandler.accessRequestFromCallback(url: url)

            performAccessRequest(tokenRequest, completionHandler: completionHandler)
        } catch {
            completionHandler(.failure(error))
        }
    }

    private func performAccessRequest(_ request: URLRequest, completionHandler: @escaping (Result<URLRequest, Error>) -> Void) {
        config.loader.response(for: request) { result in
            switch result {
            case .failure(let error):
                completionHandler(.failure(error))
            case .success(let response):
                self.handleLoginResponse(response, completionHandler: completionHandler)
            }
        }
    }

    private func handleLoginResponse(_ response: URLSession.DataTaskResponse, completionHandler: @escaping (Result<URLRequest, Error>) -> Void) {
        do {
            let login = try JSONDecoder().decode(LoginResponse.self, from: response.data).oauthLogin

            self.config.loginStorage.storeLogin(login) { error in
                if let error = error {
                    completionHandler(.failure(error))
                    return
                }

                let authedRequest = self.buildRequest(with: login)

                completionHandler(.success(authedRequest))
            }
        } catch {
            completionHandler(.failure(error))
        }
    }
}
