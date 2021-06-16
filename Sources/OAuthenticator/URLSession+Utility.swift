import Foundation

public extension URLSession {
    typealias DataTaskResponse = (data: Data, response: URLResponse)
    typealias DataTaskResult = Result<DataTaskResponse, Error>

    func dataTaskResult(with request: URLRequest, completionHandler: @escaping (DataTaskResult) -> Void) {
        let task = dataTask(with: request) { data, response, error in
            switch (data, response, error) {
            case (let data?, let response?, nil):
                completionHandler(.success((data: data, response: response)))
            case (_, _, let error?):
                completionHandler(.failure(error))
            case (_, _, nil):
                completionHandler(.failure(OAuthenticatorError.missingResponseComponents))
            }
        }

        task.resume()
    }
}
