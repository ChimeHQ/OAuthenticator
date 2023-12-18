import Foundation
import HTTPTypes
import OAuthenticator
import OpenAPIRuntime

extension Authenticator: ClientTransport {
    public func send(_ request: HTTPTypes.HTTPRequest, body: OpenAPIRuntime.HTTPBody?, baseURL: URL, operationID: String) async throws -> (HTTPTypes.HTTPResponse, OpenAPIRuntime.HTTPBody?) {
        let urlRequest = try URLRequest(request, baseURL: baseURL)
        let (data, response) = try await self.response(for: urlRequest)

        return try (
            HTTPTypes.HTTPResponse(response),
            OpenAPIRuntime.HTTPBody(data, length: .known(Int64(data.count)), iterationBehavior: .single)
        )
    }
}
