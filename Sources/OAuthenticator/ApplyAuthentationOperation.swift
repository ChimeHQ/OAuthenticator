import Foundation
import OperationPlus

class ApplyAuthentationOperation: AsyncProducerOperation<Result<URLRequest, Error>> {
    private let applier: AuthenticationApplier

    init(request: URLRequest, config: AuthConfiguration) {
        self.applier = AuthenticationApplier(request: request, config: config)
    }

    override func cancel() {
        applier.cancel()

        super.cancel()
    }

    var config: AuthConfiguration {
        return applier.config
    }

    override func main() {
        OperationQueue.preconditionNotMain()
        
        config.loginStorage.retrieveLogin { loginResult in
            switch loginResult {
            case .failure(let error):
                self.finish(with: .failure(error))
            case .success(let login):
                self.applier.applyAuthentication(using: login) { result in
                    self.finish(with: result)
                }
            }
        }
    }
}
