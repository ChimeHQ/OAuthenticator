import Foundation

public protocol URLLoader {
    typealias LoadResult = URLSession.DataTaskResult

    func response(for request: URLRequest, completionHandler: @escaping (LoadResult) -> Void)
}

extension URLSession: URLLoader {
    public func response(for request: URLRequest, completionHandler: @escaping (LoadResult) -> Void) {
        dataTaskResult(with: request, completionHandler: completionHandler)
    }
}
