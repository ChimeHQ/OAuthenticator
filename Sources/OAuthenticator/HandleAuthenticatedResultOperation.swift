import Foundation
import OperationPlus

class HandleAuthenticatedResultOperation: AsyncProducerOperation<URLSession.DataTaskResult> {
    let loadResult: URLSession.DataTaskResult
    private let applier: AuthenticationApplier

    init(request: URLRequest, response: URLLoader.LoadResult, config: AuthConfiguration) {
        self.loadResult = response
        self.applier = AuthenticationApplier(request: request, config: config)
    }

    var config: AuthConfiguration {
        return applier.config
    }

    var request: URLRequest {
        return applier.request
    }

    override func main() {
        if config.flowHandler.requiresRefresh(self.loadResult) == false {
            finish(with: self.loadResult)
            return
        }

        config.loginStorage.retrieveLogin { result in
            switch result {
            case .success(let login):
                self.checkForRefresh(with: login)
            case .failure:
                self.beginNewLogin()
            }
        }
    }

    private func checkForRefresh(with login: OAuthLogin) {
        // if the login has changed since we first started, some parallel requests
        // could have piled up and one has refreshed succesfully. Try again.
        if request.value(forHeader: .authorization) != login.accessToken {
            retryOriginalRequest(with: login)
            return
        }

        beginRefresh(with: login)
    }

    private func beginRefresh(with login: OAuthLogin) {
        do {
            let refreshRequest = try config.flowHandler.refreshRequestFromLogin(login)

            self.config.loader.response(for: refreshRequest) { result in
                switch result {
                case .failure:
                    self.beginNewLogin()
                case .success(let response):
                    self.handleRefreshResponse(response, from: login)
                }
            }
        } catch {
            self.beginNewLogin()
        }
    }

    private func handleRefreshResponse(_ response: URLSession.DataTaskResponse, from originalLogin: OAuthLogin) {
        do {
            var login = try JSONDecoder().decode(LoginResponse.self, from: response.data).oauthLogin

            if login.refreshToken == nil {
                login.refreshToken = originalLogin.refreshToken
            }

            self.config.loginStorage.storeLogin(login) { error in
                if let error = error {
                    self.finish(with: .failure(error))
                    return
                }

                self.retryOriginalRequest(with: login)
            }
        } catch {
            self.beginNewLogin()
        }
    }

    private func retryOriginalRequest(with login: OAuthLogin) {
        let authedRequest = self.request.authorizedRequest(with: login.accessToken)

        config.loader.response(for: authedRequest) { result in
            self.finish(with: result)
        }
    }

    private func beginNewLogin() {
        // we want to attempt to re-request credentials from the user
        // and use the resulting value to try the request again. We make the
        // assumption that any successful login here will result in a token
        // that will not immediately then require a refresh
        applier.beginLogin() { result in
            switch result {
            case .failure(let error):
                self.finish(with: .failure(error))
            case .success(let request):
                self.config.loader.response(for: request) { result in
                    self.finish(with: result)
                }
            }
        }
    }
}
