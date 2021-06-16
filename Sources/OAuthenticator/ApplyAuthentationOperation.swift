import Foundation
import AuthenticationServices
import OperationPlus

class ApplyAuthentationOperation: AsyncProducerOperation<Result<URLRequest, Error>> {
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

    override func cancel() {
        OperationQueue.main.addOperation {
            self.session?.cancel()
            self.session = nil
        }

        super.cancel()
    }

    override func main() {
        OperationQueue.preconditionNotMain()
        
        config.loginStorage.retrieveLogin { result in
            switch result {
            case .success(let login):
                self.buildRequest(with: login)
            case .failure:
                self.beginLogin()
            }
        }
    }

    private func buildRequest(with login: OAuthLogin) {
        let authedRequest = self.request.authorizedRequest(with: login.accessToken)

        self.finish(with: .success(authedRequest))
    }

    private func beginLogin() {
        precondition(self.session == nil)

        // ok, we have no token
        let url = config.tokenURL
        let scheme = config.callbackURLScheme

        OperationQueue.main.addOperation {
            let session = ASWebAuthenticationSession(url: url, callbackURLScheme: scheme, completionHandler: { result in
                switch result {
                case .failure(let error):
                    self.finish(with: .failure(error))
                case .success(let callbackURL):
                    self.handleSessionResult(url: callbackURL)
                }
            })

            session.prefersEphemeralWebBrowserSession = true
            session.presentationContextProvider = self.contextProvider

            session.start()

            self.session = session
        }
    }

    private func handleSessionResult(url: URL) {
        do {
            let tokenRequest = try self.config.flowHandler.accessRequestFromCallback(url: url)

            performAccessRequest(tokenRequest)
        } catch {
            self.finish(with: .failure(error))
        }
    }

    private func performAccessRequest(_ request: URLRequest) {
        config.loader.response(for: request) { result in
            switch result {
            case .failure(let error):
                self.finish(with: .failure(error))
            case .success(let response):
                self.handleLoginResponse(response)
            }
        }
    }

    private func handleLoginResponse(_ response: URLSession.DataTaskResponse) {
        do {
            let login = try JSONDecoder().decode(LoginResponse.self, from: response.data).oauthLogin

            self.config.loginStorage.storeLogin(login) { error in
                if let error = error {
                    self.finish(with: .failure(error))
                    return
                }

                self.buildRequest(with: login)
            }
        } catch {
            self.finish(with: .failure(error))
        }
    }
}
